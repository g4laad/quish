//! `quishd` — the quish server.
//!
//! Milestone 3: single-process dev server that terminates QUIC + HTTP/3, accepts
//! the quish Extended CONNECT on the secret path (404 otherwise), authenticates
//! it through the `quish-auth` registry (dev-password + pubkey backends, with the
//! centralized anti-enumeration floor), then echoes frames to prove the pipe.
//! Real sessions (M4) and privilege separation + PAM (M5) come later.

mod session;
mod transport;

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
    /// drop. The only supported mode until M5 wires up the monitor/worker split.
    #[arg(long, value_name = "USER")]
    dev_insecure_user: Option<String>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "quishd=info".into()),
        )
        .init();

    let args = Args::parse();
    let Some(dev_user) = args.dev_insecure_user else {
        anyhow::bail!(
            "only dev mode is supported until M5 privsep; pass --dev-insecure-user <name>"
        );
    };

    // Dev-mode registry: accept any password for the dev user (no PAM/root), plus
    // real pubkey auth against ~/.config/quish/authorized_keys. PAM lands in M5.
    let backends: Vec<Box<dyn AuthBackend>> = vec![
        Box::new(DevInsecureBackend::new(dev_user)),
        Box::new(PubkeyBackend::new(authorized_keys_path()?)),
    ];
    let registry = Arc::new(Registry::new(backends, FAIL_DELAY));

    // rustls needs a process-wide crypto provider; we build with the ring backend.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(transport::run(args.listen, args.path, registry))
}

fn authorized_keys_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME not set"))?;
    Ok(PathBuf::from(home).join(".config/quish/authorized_keys"))
}
