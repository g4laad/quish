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

mod ipc;
mod monitor;
mod privdrop;
mod ratelimit;
mod session;
mod signproxy;
mod transport;
mod worker;

use std::{path::PathBuf, sync::Arc, time::Duration};

use clap::Parser;
use quish_auth::{AuthBackend, DevInsecureBackend, Registry, pubkey::PubkeyBackend};

/// Constant-time floor every auth failure is padded to (anti-enumeration).
const FAIL_DELAY: Duration = Duration::from_secs(1);

/// quish server (HTTP/3 remote shell).
#[derive(Parser, Debug)]
#[command(name = "quishd", version)]
struct Args {
    /// UDP address to listen on.
    #[arg(long, default_value = "[::]:4433")]
    listen: std::net::SocketAddr,

    /// Secret request path; any other path gets a generic 404.
    #[arg(long, default_value = quish_proto::DEFAULT_PATH)]
    path: String,

    /// Dev mode: accept any password for this user, single process, no privilege
    /// drop — root-free local e2e.
    #[arg(long, value_name = "USER")]
    dev_insecure_user: Option<String>,

    /// Chroot directory for the worker (privsep mode).
    #[arg(long, default_value = "/run/quishd")]
    privsep_dir: String,

    /// Unprivileged user the worker drops to (privsep mode).
    #[arg(long, default_value = "quish")]
    privsep_user: String,

    /// Persist the host key (DER) here; generated on first use. Without it the
    /// key is ephemeral and the fingerprint changes on every restart.
    #[arg(long, value_name = "PATH")]
    host_key: Option<PathBuf>,

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
    if let Some(dev_user) = args.dev_insecure_user {
        return run_dev(args.listen, args.path, dev_user);
    }
    monitor::run(monitor::Config {
        listen: args.listen,
        path: args.path,
        chroot_dir: args.privsep_dir,
        worker_user: args.privsep_user,
        host_key: args.host_key,
    })
}

/// Single-process dev server: in-process registry + local session spawning.
fn run_dev(listen: std::net::SocketAddr, path: String, dev_user: String) -> anyhow::Result<()> {
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
            transport::run(endpoint, path, backend).await
        })
}

fn authorized_keys_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME not set"))?;
    Ok(PathBuf::from(home).join(".config/quish/authorized_keys"))
}
