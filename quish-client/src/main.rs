//! `quish` — the client CLI.
//!
//! Milestone 2: parse an ssh-style target, open a QUIC+H3 connection with
//! web-PKI→TOFU server verification, do the Extended CONNECT to the secret path,
//! and round-trip one frame through the server's echo tunnel to prove the pipe.

mod connect;

use std::future;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::Parser;
use h3::ext::Protocol;
use quish_proto::{ChannelMessage, LEN_PREFIX, parse_len};
use tracing::info;

/// quish client (HTTP/3 remote shell).
#[derive(Parser, Debug)]
#[command(name = "quish", version)]
struct Args {
    /// Target as `[user@]host[:port][/path]`.
    target: String,

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
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().context("invalid port")?),
        None => (hostport.to_string(), 4433),
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

fn whoami() -> String {
    std::env::var("USER").unwrap_or_else(|_| "root".into())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "quish=info".into()),
        )
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;

    let args = Args::parse();
    let target = parse_target(&args.target)?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(target))
}

async fn run(target: Target) -> Result<()> {
    let host_key = format!("{}:{}", target.host, target.port);
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
            "https://{}:{}{}",
            target.host, target.port, target.path
        ))
        .header(quish_proto::HEADER_USERNAME, &target.user)
        .header(
            quish_proto::HEADER_VERSION,
            quish_proto::PROTOCOL_VERSION.to_string(),
        )
        .extension(Protocol::WEB_TRANSPORT)
        .body(())
        .expect("valid request");

    let mut stream = send_request
        .send_request(req)
        .await
        .context("sending CONNECT")?;
    let resp = stream.recv_response().await.context("awaiting response")?;
    if resp.status() != http::StatusCode::OK {
        bail!("server rejected session: HTTP {}", resp.status());
    }
    info!(user = %target.user, "session established");

    // M2 echo check: send one frame, expect the same bytes back.
    let msg = ChannelMessage::Data(b"quish M2 echo".to_vec());
    stream
        .send_data(Bytes::from(quish_proto::encode(&msg)?))
        .await
        .context("sending frame")?;
    let body = read_frame(&mut stream).await?;
    let got: ChannelMessage = quish_proto::decode(&body).context("decoding echo")?;
    if got != msg {
        bail!("echo mismatch: sent {msg:?}, got {got:?}");
    }
    stream.finish().await.context("finishing stream")?;
    println!("quish: transport OK — CONNECT accepted and frame round-tripped");

    drop(send_request);
    let _ = drive.await;
    Ok(())
}

/// Read exactly one length-prefixed frame body off the tunnel, buffering across
/// H3 DATA chunks. Enforces the frame cap via [`parse_len`].
async fn read_frame(
    stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<Vec<u8>> {
    use bytes::Buf;
    let mut buf: Vec<u8> = Vec::new();
    let mut need = LEN_PREFIX;
    let mut body_len: Option<usize> = None;
    loop {
        while buf.len() >= need {
            match body_len {
                None => {
                    let len = parse_len(buf[..LEN_PREFIX].try_into().unwrap())?;
                    body_len = Some(len);
                    need = LEN_PREFIX + len;
                }
                Some(len) => return Ok(buf[LEN_PREFIX..LEN_PREFIX + len].to_vec()),
            }
        }
        let mut chunk = stream
            .recv_data()
            .await
            .context("tunnel recv")?
            .context("stream closed before frame completed")?;
        buf.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
    }
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
}
