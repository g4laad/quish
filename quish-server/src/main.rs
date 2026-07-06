//! `quishd` — the quish server.
//!
//! Milestone 2 is transport only: a single-process dev server that terminates
//! QUIC + HTTP/3, accepts the quish Extended CONNECT on the secret path (404
//! otherwise), and echoes frames back over the tunnel to prove the pipe. Auth
//! (M3), real sessions (M4), and privilege separation (M5) come later.

mod transport;

use clap::Parser;

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
    if args.dev_insecure_user.is_none() {
        anyhow::bail!("M2 only supports dev mode; pass --dev-insecure-user <name>");
    }

    // rustls needs a process-wide crypto provider; we build with the ring backend.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(transport::run(args.listen, args.path))
}
