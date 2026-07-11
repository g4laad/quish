//! `quishd` — the quish server.
//!
//! Runs in one of four process modes:
//!   * **monitor** (default): root parent; owns the host key + auth registry,
//!     re-execs and serves the worker (see `monitor.rs`).
//!   * **worker** (`--internal-worker`): unprivileged chrooted child running all
//!     QUIC/H3/TLS (see `worker.rs`).
//!   * **session helper** (`--internal-run-session`): setuids to the target user
//!     and execs their shell (see `privdrop.rs`).
//!   * **dev** (`--dev-insecure-user`): single process, in-process auth, no
//!     privilege drop — for root-free local e2e.

mod config;
mod ipc;
mod monitor;
mod privdrop;
mod ratelimit;
mod session;
mod signproxy;
mod transport;
mod worker;

use std::net::SocketAddr;
use std::{path::PathBuf, sync::Arc, time::Duration};

use clap::Parser;
use quish_auth::{AuthBackend, DevInsecureBackend, Registry, pubkey::PubkeyBackend};

/// Constant-time floor every auth failure is padded to (anti-enumeration).
pub(crate) const FAIL_DELAY: Duration = Duration::from_secs(1);

/// quish server (HTTP/3 remote shell).
#[derive(Parser, Debug)]
#[command(name = "quishd", version)]
struct Args {
    /// TOML config file (see dist/server.toml). CLI flags override its values.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// UDP address to listen on. [default: [::]:4433]
    #[arg(long)]
    listen: Option<SocketAddr>,

    /// Secret request path; any other path gets a generic 404. [default: /quish]
    #[arg(long)]
    path: Option<String>,

    /// Dev mode: accept any password for this user, single process, no privilege
    /// drop — root-free local e2e.
    #[arg(long, value_name = "USER")]
    dev_insecure_user: Option<String>,

    /// Chroot directory for the worker (privsep mode). [default: /run/quishd]
    #[arg(long)]
    privsep_dir: Option<String>,

    /// Unprivileged user the worker drops to (privsep mode). [default: quish]
    #[arg(long)]
    privsep_user: Option<String>,

    /// Persist the host key (DER) here; generated on first use. Without it the
    /// key is ephemeral and the fingerprint changes on every restart.
    #[arg(long, value_name = "PATH")]
    host_key: Option<PathBuf>,

    /// Failed auth attempts tolerated per connection before further attempts get
    /// cheap 401s (connection stays up). [default: 6]
    #[arg(long)]
    max_auth_fails: Option<u32>,

    /// Enable local (`-L`) TCP port forwarding (loopback-only). OFF by default;
    /// this flag or `allow_forward = true` in the config file turns it on.
    #[arg(long)]
    allow_forward: bool,

    /// Internal: run as the privilege-dropped worker (spawned by the monitor).
    #[arg(long, hide = true)]
    internal_worker: bool,

    /// Internal: setuid to the target user and exec their shell.
    #[arg(long, hide = true)]
    internal_run_session: bool,
}

fn main() -> anyhow::Result<()> {
    // The session helper must exec before touching tokio/tracing/rustls.
    let raw: Vec<String> = std::env::args().collect();
    if raw.iter().any(|a| a == "--internal-run-session") {
        return privdrop::run_session_helper();
    }

    tracing_subscriber::fmt()
        // tracing-subscriber never tty-detects; without this, ANSI escapes land
        // in piped logs (journald, the e2e harness) and break `field=` parsing.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "quishd=info".into()),
        )
        .init();

    // rustls needs a process-wide crypto provider (ring backend).
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;

    let args = Args::parse();

    if args.internal_worker {
        return worker::run();
    }

    // Merge: CLI flag → config file → built-in default.
    let file = match &args.config {
        Some(p) => config::FileConfig::load(p)?,
        None => config::FileConfig::default(),
    };
    let listen = args
        .listen
        .or(file.listen)
        .unwrap_or_else(|| "[::]:4433".parse().unwrap());
    let path = args
        .path
        .or(file.path)
        .unwrap_or_else(|| quish_proto::DEFAULT_PATH.to_string());
    let host_key = args.host_key.or(file.host_key);
    let max_auth_fails = args
        .max_auth_fails
        .or(file.max_auth_fails)
        .unwrap_or(transport::DEFAULT_MAX_AUTH_FAILS);
    let allow_forward = args.allow_forward || file.allow_forward.unwrap_or(false);

    if let Some(dev_user) = args.dev_insecure_user {
        return run_dev(listen, path, dev_user, max_auth_fails, allow_forward);
    }
    monitor::run(monitor::Config {
        listen,
        path,
        chroot_dir: args
            .privsep_dir
            .or(file.privsep_dir)
            .unwrap_or_else(|| "/run/quishd".to_string()),
        worker_user: args
            .privsep_user
            .or(file.privsep_user)
            .unwrap_or_else(|| "quish".to_string()),
        host_key,
        max_auth_fails,
        allow_forward,
    })
}

/// Single-process dev server: in-process registry + local session spawning.
fn run_dev(
    listen: SocketAddr,
    path: String,
    dev_user: String,
    max_auth_fails: u32,
    allow_forward: bool,
) -> anyhow::Result<()> {
    let backends: Vec<Box<dyn AuthBackend>> = vec![
        Box::new(DevInsecureBackend::new(dev_user)),
        Box::new(PubkeyBackend::new(authorized_keys_path()?)),
    ];
    let registry = Arc::new(Registry::new(backends, FAIL_DELAY));
    let backend = Arc::new(transport::Backend::Dev { registry });

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let endpoint = transport::dev_endpoint(listen)?;
            transport::run(endpoint, path, backend, max_auth_fails, allow_forward).await
        })
}

fn authorized_keys_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME not set"))?;
    Ok(PathBuf::from(home).join(".config/quish/authorized_keys"))
}
