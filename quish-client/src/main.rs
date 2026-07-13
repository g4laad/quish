//! `quish` — the client CLI.
//!
//! Milestone 4: parse an ssh-style target, open a QUIC+H3 connection with
//! web-PKI→TOFU server verification, authenticate the Extended CONNECT (password
//! Basic or channel-bound pubkey Bearer), then open a shell (interactive PTY) or
//! exec channel and pump it to completion, exiting with the remote status.

mod connect;
mod cp;
mod terminal;

use std::future;
use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, Result, bail};
use bytes::{BufMut, Bytes, BytesMut};
use clap::Parser;
use h3::ext::Protocol;
use quish_proto::{ChannelMessage, ChannelOpen};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

/// Halves of an open H3 channel stream (client side).
pub(crate) type SendHalf = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
pub(crate) type RecvHalf = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;
/// The multiplexing handle used to open new channels on the authed connection.
pub(crate) type SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// quish client (HTTP/3 remote shell).
#[derive(Parser, Debug)]
#[command(name = "quish", version, args_conflicts_with_subcommands = true)]
struct Args {
    #[command(subcommand)]
    action: Option<Command>,
    #[command(flatten)]
    connect: ConnectArgs,
}

#[derive(clap::Args, Debug)]
struct ConnectArgs {
    /// Target as `[user@]host[:port][/path]`.
    target: Option<String>,

    /// OpenSSH ed25519 private key for pubkey auth. Without it, password auth is
    /// used (prompted, or read from `QUISH_PASSWORD`).
    #[arg(short, long)]
    identity: Option<std::path::PathBuf>,

    /// Local forward: `-L [bind:]lport:rhost:rport` (repeatable). `rhost:rport`
    /// is opened on the server; connections to the local port are tunneled to it.
    #[arg(short = 'L', long = "local-forward")]
    local_forward: Vec<String>,

    /// Command to run (empty = interactive shell).
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Manage pinned server host keys (TOFU known_hosts).
    KnownHosts {
        #[command(subcommand)]
        action: KnownHostsAction,
    },
    /// Copy a file or folder to/from a server (scp-like). Exactly one of
    /// SRC/DST is remote (`[user@]host:path`); a local folder SRC uploads
    /// recursively (symlinks are skipped, never followed).
    Cp(cp::CpArgs),
}

#[derive(clap::Subcommand, Debug)]
enum KnownHostsAction {
    /// List pinned hosts and their fingerprints.
    List,
    /// Remove a pinned host (like `ssh-keygen -R`). HOST is the `host:port` shown by `list`.
    Remove { host: String },
}

/// Parsed connection target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub(crate) user: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path: String,
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

/// A parsed `-L` local-forward spec: bind a local `bind:lport` and tunnel every
/// accepted connection to `rhost:rport` on the server side.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardSpec {
    bind: IpAddr,
    lport: u16,
    rhost: String,
    rport: u16,
}

/// Parse `-L [bind:]lport:rhost:rport` (modeled on [`parse_target`]). Bracket
/// IPv6 literals (`[::1]`) so their colons don't split; a bare `bind` defaults to
/// `127.0.0.1`. The local bind MUST be loopback (loopback-only PoC policy).
fn parse_forward(s: &str) -> Result<ForwardSpec> {
    let tokens = split_forward_tokens(s)?;
    let (bind_tok, lport_tok, rhost_tok, rport_tok) = match tokens.as_slice() {
        [l, rh, rp] => (None, l.as_str(), rh.as_str(), rp.as_str()),
        [b, l, rh, rp] => (Some(b.as_str()), l.as_str(), rh.as_str(), rp.as_str()),
        _ => bail!("forward spec `{s}` must be [bind:]lport:rhost:rport"),
    };
    let lport: u16 = lport_tok
        .parse()
        .with_context(|| format!("invalid local port in forward spec `{s}`"))?;
    let rport: u16 = rport_tok
        .parse()
        .with_context(|| format!("invalid remote port in forward spec `{s}`"))?;
    if rhost_tok.is_empty() {
        bail!("missing remote host in forward spec `{s}`");
    }
    let bind: IpAddr = match bind_tok {
        Some(b) => b
            .parse()
            .with_context(|| format!("invalid bind address in forward spec `{s}`"))?,
        None => IpAddr::V4(Ipv4Addr::LOCALHOST),
    };
    if !bind.is_loopback() {
        bail!("refusing non-loopback bind address {bind} in forward spec `{s}` (loopback-only)");
    }
    Ok(ForwardSpec {
        bind,
        lport,
        rhost: rhost_tok.to_string(),
        rport,
    })
}

/// Split a forward spec on `:`, keeping a bracketed IPv6 literal (`[::1]`) as one
/// token (brackets stripped). A bare IPv6 literal (unbracketed) yields too many
/// tokens and is rejected upstream — bracket it.
fn split_forward_tokens(s: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut rest = s;
    loop {
        if let Some(inner) = rest.strip_prefix('[') {
            let (addr, after) = inner
                .split_once(']')
                .context("missing closing ']' in forward spec")?;
            tokens.push(addr.to_string());
            match after.strip_prefix(':') {
                Some(r) => rest = r,
                None if after.is_empty() => return Ok(tokens),
                None => bail!("unexpected text after ']' in forward spec `{s}`"),
            }
        } else {
            match rest.split_once(':') {
                Some((tok, r)) => {
                    tokens.push(tok.to_string());
                    rest = r;
                }
                None => {
                    tokens.push(rest.to_string());
                    return Ok(tokens);
                }
            }
        }
    }
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

pub(crate) fn whoami() -> String {
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
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "quish=warn".into()),
        )
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;

    let args = Args::parse();

    match args.action {
        Some(Command::KnownHosts { action }) => {
            return match action {
                KnownHostsAction::List => connect::list_known_hosts(),
                KnownHostsAction::Remove { host } => connect::remove_known_host(&host),
            };
        }
        Some(Command::Cp(a)) => {
            let code = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(cp::run_cp(a))?;
            std::process::exit(code);
        }
        None => {}
    }

    let target_str = args
        .connect
        .target
        .context("a target ([user@]host[:port]) is required")?;
    let target = parse_target(&target_str)?;

    let code = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(
            target,
            args.connect.identity,
            args.connect.command,
            args.connect.local_forward,
        ))?;
    std::process::exit(code);
}

async fn run(
    target: Target,
    identity: Option<std::path::PathBuf>,
    command: Vec<String>,
    local_forwards: Vec<String>,
) -> Result<i32> {
    // Parse `-L` specs up front so a malformed spec fails before any network I/O.
    let forwards = local_forwards
        .iter()
        .map(|s| parse_forward(s))
        .collect::<Result<Vec<_>>>()?;

    let (mut send_request, drive, authorization) = establish(&target, identity.as_deref()).await?;

    // Forward mode: bind the local ports and tunnel each accepted connection over
    // its own Extended CONNECT channel. Runs until the listeners stop (Ctrl-C).
    if !forwards.is_empty() {
        run_forwards(send_request, forwards, target, authorization).await?;
        let _ = drive.await;
        return Ok(0);
    }

    // Open the shell/exec channel on the authed connection.
    let (send, recv) = open_channel(&mut send_request, &target, &authorization).await?;
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

/// Resolve, connect, and authenticate the QUIC/H3 connection, then spawn its
/// driver task. Returns the multiplexing handle, the driver `JoinHandle`, and
/// the channel-bound `Authorization` reused on every channel opened on this
/// connection (it is bound to the connection, not the stream).
pub(crate) async fn establish(
    target: &Target,
    identity: Option<&std::path::Path>,
) -> Result<(SendRequest, tokio::task::JoinHandle<()>, String)> {
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
    let authorization = build_authorization(&target.user, identity, &binding)?;

    let (mut driver, send_request) = h3::client::builder()
        .enable_extended_connect(true)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
        .await
        .context("h3 handshake")?;
    let drive = tokio::spawn(async move {
        let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    Ok((send_request, drive, authorization))
}

/// Open one Extended CONNECT channel on the authed connection and split it into
/// send/recv halves. :protocol must be a value h3 accepts (its Protocol enum is
/// closed), so we use WEB_TRANSPORT and let the secret path + version header mark
/// this as quish. The status match maps auth/version failures to errors.
pub(crate) async fn open_channel(
    send_request: &mut SendRequest,
    target: &Target,
    authorization: &str,
) -> Result<(SendHalf, RecvHalf)> {
    let req = build_connect_request(target, authorization);
    let mut stream = send_request
        .send_request(req)
        .await
        .context("sending CONNECT")?;
    let resp = stream.recv_response().await.context("awaiting response")?;
    match resp.status() {
        http::StatusCode::OK => {}
        http::StatusCode::UNAUTHORIZED => bail!("authentication failed"),
        http::StatusCode::UPGRADE_REQUIRED => {
            bail!(
                "server rejected our protocol version (quish-version {}); client/server mismatch",
                quish_proto::PROTOCOL_VERSION
            )
        }
        s => bail!("server rejected session: HTTP {s}"),
    }
    info!(user = %target.user, "session authenticated");
    Ok(stream.split())
}

/// Build the Extended CONNECT request every channel opens with. `:protocol` must
/// be a value h3 accepts (its `Protocol` enum is closed), so we use WEB_TRANSPORT
/// and let the secret path + version header mark this as quish. The channel-bound
/// `authorization` is reused on every channel (it is bound to the connection, not
/// the stream).
fn build_connect_request(target: &Target, authorization: &str) -> http::Request<()> {
    http::Request::builder()
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
        .header(quish_proto::HEADER_AUTHORIZATION, authorization)
        .extension(Protocol::WEB_TRANSPORT)
        .body(())
        .expect("valid request")
}

/// Bind every `-L` listener, then serve accepted connections until a listener
/// errors. Each listener runs on its own task; each accepted connection opens a
/// fresh forward channel.
async fn run_forwards(
    send_request: SendRequest,
    forwards: Vec<ForwardSpec>,
    target: Target,
    authorization: String,
) -> Result<()> {
    let mut tasks = Vec::new();
    for spec in forwards {
        let listener = TcpListener::bind((spec.bind, spec.lport))
            .await
            .with_context(|| format!("binding local forward {}:{}", spec.bind, spec.lport))?;
        info!(
            bind = %spec.bind, lport = spec.lport, rhost = %spec.rhost, rport = spec.rport,
            "local forward listening"
        );
        let send_request = send_request.clone();
        let target = target.clone();
        let authorization = authorization.clone();
        tasks.push(tokio::spawn(accept_loop(
            listener,
            send_request,
            spec,
            target,
            authorization,
        )));
    }
    // Listeners run until they error; join so a bind/accept failure surfaces.
    for task in tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(e) => return Err(anyhow::anyhow!("forward listener task panicked: {e}")),
        }
    }
    Ok(())
}

/// Accept connections on one local listener; tunnel each over its own channel.
async fn accept_loop(
    listener: TcpListener,
    send_request: SendRequest,
    spec: ForwardSpec,
    target: Target,
    authorization: String,
) -> Result<()> {
    loop {
        let (tcp, peer) = listener.accept().await.context("accepting local forward")?;
        info!(%peer, rhost = %spec.rhost, rport = spec.rport, "forward connection accepted");
        let send_request = send_request.clone();
        let target = target.clone();
        let authorization = authorization.clone();
        let rhost = spec.rhost.clone();
        let rport = spec.rport;
        tokio::spawn(async move {
            if let Err(e) =
                forward_one(send_request, tcp, target, authorization, rhost, rport).await
            {
                warn!(error = %e, "forward connection ended");
            }
        });
    }
}

/// Open one forward channel and bridge it to the accepted local `TcpStream`.
async fn forward_one(
    mut send_request: SendRequest,
    tcp: TcpStream,
    target: Target,
    authorization: String,
    rhost: String,
    rport: u16,
) -> Result<()> {
    let req = build_connect_request(&target, &authorization);
    let mut stream = send_request
        .send_request(req)
        .await
        .context("opening forward channel")?;
    let resp = stream
        .recv_response()
        .await
        .context("awaiting forward channel response")?;
    if resp.status() != http::StatusCode::OK {
        bail!("server rejected forward channel: HTTP {}", resp.status());
    }
    let (mut send, recv) = stream.split();
    send.send_data(Bytes::from(quish_proto::encode(&ChannelOpen::Forward {
        host: rhost,
        port: rport,
    })?))
    .await
    .context("sending Forward open")?;
    bridge(tcp, send, recv).await
}

/// Bidirectional byte bridge: local `TcpStream` ⇄ H3 channel, both directions
/// framed as `ChannelMessage::Data` (per the Decision record). Either EOF closes
/// the other direction.
async fn bridge(tcp: TcpStream, mut send: SendHalf, recv: RecvHalf) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    // remote → local: decode Data frames off the channel, write to the socket.
    let down = tokio::spawn(async move {
        let mut reader = ChannelFrameReader::new(recv);
        while let Ok(Some(msg)) = reader.next().await {
            if let ChannelMessage::Data(d) = msg
                && tcp_write.write_all(&d).await.is_err()
            {
                break;
            }
        }
        let _ = tcp_write.shutdown().await;
    });

    // local → remote: read socket bytes, frame each chunk as Data.
    let mut buf = vec![0u8; 8192];
    loop {
        match tcp_read.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let frame = quish_proto::encode(&ChannelMessage::Data(buf[..n].to_vec()))?;
                if send.send_data(Bytes::from(frame)).await.is_err() {
                    break; // channel closed by server (policy refusal / peer EOF)
                }
            }
        }
    }
    let _ = send.finish().await;
    let _ = down.await;
    Ok(())
}

/// Reassembles length-prefixed [`ChannelMessage`] frames off an H3 recv half.
pub(crate) struct ChannelFrameReader {
    recv: RecvHalf,
    buf: BytesMut,
}

impl ChannelFrameReader {
    pub(crate) fn new(recv: RecvHalf) -> Self {
        Self {
            recv,
            buf: BytesMut::new(),
        }
    }

    /// Next decoded message, or `None` at clean end of stream.
    pub(crate) async fn next(&mut self) -> Result<Option<ChannelMessage>> {
        loop {
            if let Some(body) = quish_proto::take_frame(&mut self.buf)? {
                return Ok(Some(quish_proto::decode::<ChannelMessage>(&body)?));
            }
            match self.recv.recv_data().await {
                Ok(Some(chunk)) => self.buf.put(chunk),
                Ok(None) => return Ok(None),
                Err(e) if e.is_h3_no_error() => return Ok(None),
                Err(e) => return Err(anyhow::anyhow!("recv forward frame: {e}")),
            }
        }
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

    #[test]
    fn parse_forward_lport_rhost_rport() {
        let f = parse_forward("8080:127.0.0.1:5432").unwrap();
        assert_eq!(
            f,
            ForwardSpec {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                lport: 8080,
                rhost: "127.0.0.1".into(),
                rport: 5432,
            }
        );
    }

    #[test]
    fn parse_forward_bind_lport_rhost_rport() {
        let f = parse_forward("127.0.0.1:8080:127.0.0.1:5432").unwrap();
        assert_eq!(
            f,
            ForwardSpec {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                lport: 8080,
                rhost: "127.0.0.1".into(),
                rport: 5432,
            }
        );
    }

    #[test]
    fn parse_forward_rejects_non_loopback_bind() {
        assert!(parse_forward("0.0.0.0:8080:127.0.0.1:5432").is_err());
        assert!(parse_forward("192.168.1.10:8080:127.0.0.1:5432").is_err());
    }

    #[test]
    fn parse_forward_rejects_malformed() {
        assert!(parse_forward("nonsense").is_err()); // too few fields
        assert!(parse_forward("8080:127.0.0.1").is_err()); // missing rport
        assert!(parse_forward("notaport:127.0.0.1:5432").is_err()); // bad lport
        assert!(parse_forward("8080:127.0.0.1:notaport").is_err()); // bad rport
        assert!(parse_forward("a:8080:127.0.0.1:5432").is_err()); // bad bind
    }
}
