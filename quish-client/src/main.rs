//! `quish` — the client CLI.
//!
//! Milestone 4: parse an ssh-style target, open a QUIC+H3 connection with
//! web-PKI→TOFU server verification, authenticate the Extended CONNECT (password
//! Basic or channel-bound pubkey Bearer), then open a shell (interactive PTY) or
//! exec channel and pump it to completion, exiting with the remote status.

mod connect;
mod terminal;

use std::future;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::Parser;
use h3::ext::Protocol;
use quish_proto::ChannelOpen;
use tracing::info;

/// quish client (HTTP/3 remote shell).
#[derive(Parser, Debug)]
#[command(name = "quish", version)]
struct Args {
    /// Target as `[user@]host[:port][/path]`.
    target: String,

    /// OpenSSH ed25519 private key for pubkey auth. Without it, password auth is
    /// used (prompted, or read from `QUISH_PASSWORD`).
    #[arg(short, long)]
    identity: Option<std::path::PathBuf>,

    /// Command to run (unused until M4; parsed now for the final CLI shape).
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

/// Parsed connection target.
#[derive(Debug, PartialEq, Eq)]
struct Target {
    user: String,
    host: String,
    port: u16,
    path: String,
}

fn parse_target(s: &str) -> Result<Target> {
    let (user, rest) = match s.split_once('@') {
        Some((u, r)) => (u.to_string(), r),
        None => (whoami(), s),
    };
    // Path is everything from the first '/'; the rest is host[:port].
    let (hostport, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, quish_proto::DEFAULT_PATH.to_string()),
    };
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        // Bracketed IPv6: [addr] or [addr]:port
        let (addr, after) = rest
            .split_once(']')
            .context("missing closing ']' in IPv6 target")?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().context("invalid port")?,
            None if after.is_empty() => 4433,
            None => bail!("unexpected text after ']' in target `{s}`"),
        };
        (addr.to_string(), port)
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        if h.contains(':') {
            // Bare IPv6 literal (multiple colons, no brackets): no port present.
            (hostport.to_string(), 4433)
        } else {
            (h.to_string(), p.parse().context("invalid port")?)
        }
    } else {
        (hostport.to_string(), 4433)
    };
    if host.is_empty() {
        bail!("missing host in target `{s}`");
    }
    Ok(Target {
        user,
        host,
        port,
        path,
    })
}

/// `host:port` for the resolver, the TOFU pin key, and the CONNECT URI
/// authority, bracketing IPv6 literals so `tokio::net::lookup_host` and
/// `http::Uri` accept them (`[::1]:4433`). All three uses must stay identical.
fn socket_target(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn whoami() -> String {
    std::env::var("USER").unwrap_or_else(|_| "root".into())
}

/// Build the `Authorization` header value. With `--identity`, mint a channel-bound
/// pubkey token (Bearer); otherwise use a password (Basic), read from
/// `QUISH_PASSWORD` for scripted runs or prompted interactively.
fn build_authorization(
    user: &str,
    identity: Option<&std::path::Path>,
    binding: &[u8; 32],
) -> Result<String> {
    match identity {
        Some(path) => {
            let key = std::fs::read(path)
                .with_context(|| format!("reading identity {}", path.display()))?;
            let token = quish_auth::pubkey::build_token(&key, user, binding)?;
            Ok(quish_auth::bearer_header(&token))
        }
        None => {
            let password = match std::env::var("QUISH_PASSWORD") {
                Ok(p) => p,
                Err(_) => rpassword::prompt_password(format!("{user}'s password: "))
                    .context("reading password")?,
            };
            Ok(quish_auth::basic_header(user, &password))
        }
    }
}

fn main() -> Result<()> {
    // Logs go to stderr and stay quiet by default: stdout is the remote channel's
    // stdout (piping `quish host cmd > file` must yield clean output).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "quish=warn".into()),
        )
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;

    let args = Args::parse();
    let target = parse_target(&args.target)?;

    let code = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(target, args.identity, args.command))?;
    std::process::exit(code);
}

async fn run(
    target: Target,
    identity: Option<std::path::PathBuf>,
    command: Vec<String>,
) -> Result<i32> {
    let host_key = socket_target(&target.host, target.port);
    let addr = tokio::net::lookup_host(&host_key)
        .await
        .context("resolving host")?
        .next()
        .with_context(|| format!("no address for {host_key}"))?;

    let endpoint = connect::endpoint(host_key.clone())?;
    let conn = endpoint
        .connect(addr, &target.host)
        .context("starting connection")?
        .await
        .context("connecting")?;
    info!(%addr, "connected");

    // Channel binding for pubkey tokens: export before `conn` moves into h3. Must
    // match the server's label byte-for-byte.
    let mut binding = [0u8; quish_proto::CHANNEL_BINDING_LEN];
    conn.export_keying_material(&mut binding, quish_proto::CHANNEL_BINDING_LABEL, &[])
        .map_err(|e| anyhow::anyhow!("exporting channel binding: {e:?}"))?;
    let authorization = build_authorization(&target.user, identity.as_deref(), &binding)?;

    let (mut driver, mut send_request) = h3::client::builder()
        .enable_extended_connect(true)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
        .await
        .context("h3 handshake")?;
    let drive = tokio::spawn(async move {
        let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // Extended CONNECT to the secret path. :protocol must be a value h3 accepts
    // (its Protocol enum is closed), so we use WEB_TRANSPORT and let the secret
    // path + version header mark this as quish.
    let req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!(
            "https://{}{}",
            socket_target(&target.host, target.port),
            target.path
        ))
        .header(
            quish_proto::HEADER_VERSION,
            quish_proto::PROTOCOL_VERSION.to_string(),
        )
        .header(quish_proto::HEADER_AUTHORIZATION, &authorization)
        .extension(Protocol::WEB_TRANSPORT)
        .body(())
        .expect("valid request");

    let mut stream = send_request
        .send_request(req)
        .await
        .context("sending CONNECT")?;
    let resp = stream.recv_response().await.context("awaiting response")?;
    match resp.status() {
        http::StatusCode::OK => {}
        http::StatusCode::UNAUTHORIZED => bail!("authentication failed"),
        s => bail!("server rejected session: HTTP {s}"),
    }
    info!(user = %target.user, "session authenticated");

    // Open a channel on the authed stream: shell if no command, else exec.
    let (send, recv) = stream.split();
    let interactive = command.is_empty();
    let (cols, rows) = terminal::winsize();
    let open = if interactive {
        ChannelOpen::Shell {
            term: std::env::var("TERM").unwrap_or_else(|_| "xterm".into()),
            cols,
            rows,
        }
    } else {
        ChannelOpen::Exec {
            command: command.join(" "),
        }
    };
    let code = terminal::run_channel(send, recv, open, interactive).await?;

    drop(send_request);
    let _ = drive.await;
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_target() {
        let t = parse_target("alice@example.com:8443/secret").unwrap();
        assert_eq!(
            t,
            Target {
                user: "alice".into(),
                host: "example.com".into(),
                port: 8443,
                path: "/secret".into(),
            }
        );
    }

    #[test]
    fn defaults_port_and_path() {
        let t = parse_target("host").unwrap();
        assert_eq!(t.host, "host");
        assert_eq!(t.port, 4433);
        assert_eq!(t.path, quish_proto::DEFAULT_PATH);
    }

    #[test]
    fn rejects_bad_port() {
        assert!(parse_target("host:notaport").is_err());
    }

    #[test]
    fn parses_bracketed_ipv6() {
        let t = parse_target("alice@[2001:db8::1]:22/x").unwrap();
        assert_eq!(t.user, "alice");
        assert_eq!(t.host, "2001:db8::1");
        assert_eq!(t.port, 22);
        assert_eq!(t.path, "/x");
    }

    #[test]
    fn bracketed_ipv6_default_port() {
        let t = parse_target("[::1]").unwrap();
        assert_eq!(t.host, "::1");
        assert_eq!(t.port, 4433);
    }

    #[test]
    fn bare_ipv6_defaults_port() {
        let t = parse_target("::1").unwrap();
        assert_eq!(t.host, "::1");
        assert_eq!(t.port, 4433);
    }

    #[test]
    fn socket_target_brackets_ipv6_only() {
        assert_eq!(socket_target("::1", 4433), "[::1]:4433");
        assert_eq!(socket_target("example.com", 22), "example.com:22");
        assert_eq!(socket_target("10.0.0.1", 22), "10.0.0.1:22");
    }

    #[test]
    fn connect_uri_authority_is_bracketed_for_ipv6() {
        let uri: http::Uri = format!("https://{}{}", socket_target("::1", 4433), "/quish")
            .parse()
            .unwrap();
        assert_eq!(uri.host(), Some("[::1]"));
        assert_eq!(uri.port_u16(), Some(4433));
        assert_eq!(uri.path(), "/quish");
    }
}
