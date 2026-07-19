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

use anyhow::Context;
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

    /// Dev mode only: also require a TOTP second factor after the dev password.
    /// The value is the shared secret (base32, RFC 4648). Turns on the
    /// challenge/2FA path for root-free local e2e.
    #[arg(long, value_name = "BASE32")]
    dev_insecure_totp_secret: Option<String>,

    /// Require a per-user TOTP second factor (privsep mode). Each user's base32
    /// secret is read from `~/.config/quish/totp`. Needs the `pam` feature for
    /// the password first factor. Or set `totp = true` in the config file.
    #[arg(long)]
    totp: bool,

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

    /// Enable remote (`-R`) TCP port forwarding (loopback-only). OFF by default;
    /// this flag or `allow_remote_forward = true` in the config file turns it on.
    #[arg(long)]
    allow_remote_forward: bool,

    /// Disable the worker's seccomp-bpf syscall filter (privsep mode only).
    /// Enforcing by default; use only to work around a kernel/glibc/tokio
    /// regression where the allowlist SIGSYS-kills the worker.
    #[arg(long)]
    no_seccomp: bool,

    /// Only these users may log in (repeatable). Empty = all authenticated
    /// users. `--deny-user` always wins. Or `allow_users = [...]` in the config.
    #[arg(long = "allow-user", value_name = "USER")]
    allow_users: Vec<String>,

    /// Refuse these users even if they authenticate (repeatable).
    #[arg(long = "deny-user", value_name = "USER")]
    deny_users: Vec<String>,

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
    let allow_remote_forward =
        args.allow_remote_forward || file.allow_remote_forward.unwrap_or(false);
    let no_seccomp = args.no_seccomp || file.no_seccomp.unwrap_or(false);
    let totp = args.totp || file.totp.unwrap_or(false);
    let policy = quish_auth::UserPolicy {
        allow_users: if args.allow_users.is_empty() {
            file.allow_users.unwrap_or_default()
        } else {
            args.allow_users
        },
        deny_users: if args.deny_users.is_empty() {
            file.deny_users.unwrap_or_default()
        } else {
            args.deny_users
        },
    };
    // OIDC is config-file only this slice (no CLI flags); resolve its defaults now.
    let oidc = file.oidc.map(config::OidcConfig::into_backend);

    if let Some(dev_user) = args.dev_insecure_user {
        return run_dev(
            listen,
            path,
            dev_user,
            args.dev_insecure_totp_secret,
            max_auth_fails,
            allow_forward,
            allow_remote_forward,
            policy,
            oidc,
        );
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
        allow_remote_forward,
        no_seccomp,
        totp,
        policy,
        oidc,
    })
}

/// Single-process dev server: in-process registry + local session spawning.
#[allow(clippy::too_many_arguments)]
fn run_dev(
    listen: SocketAddr,
    path: String,
    dev_user: String,
    dev_totp_secret: Option<String>,
    max_auth_fails: u32,
    allow_forward: bool,
    allow_remote_forward: bool,
    policy: quish_auth::UserPolicy,
    oidc: Option<quish_auth::oidc::OidcConfig>,
) -> anyhow::Result<()> {
    // With a dev TOTP secret, wrap the dev password backend so every password
    // login must clear a second factor (always-challenge). One vec entry either
    // way, exactly like the privsep registry.
    let password: Box<dyn AuthBackend> = match dev_totp_secret {
        Some(b32) => {
            let secret = quish_auth::totp::decode_base32_secret(&b32)
                .context("--dev-insecure-totp-secret is not valid base32")?;
            Box::new(quish_auth::totp::TotpBackend::new(
                Box::new(DevInsecureBackend::new(dev_user)),
                Box::new(move |_user| Some(secret.clone())),
            ))
        }
        None => Box::new(DevInsecureBackend::new(dev_user)),
    };
    let mut backends: Vec<Box<dyn AuthBackend>> = vec![
        password,
        Box::new(PubkeyBackend::new(authorized_keys_path()?)),
    ];
    if let Some(oidc) = oidc {
        backends.push(Box::new(quish_auth::oidc::OidcBackend::new(oidc)));
    }
    let registry = Arc::new(Registry::new(backends, FAIL_DELAY, policy));
    let backend = Arc::new(transport::Backend::Dev {
        registry,
        challenges: transport::ChallengeStore::default(),
    });
    session::set_allow_remote_forward(allow_remote_forward);

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
