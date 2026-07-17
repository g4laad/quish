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

    /// Remote forward: `-R [bind:]rport:lhost:lport` (repeatable). Asks the
    /// server to bind `rport` (loopback-only); each inbound connection is
    /// tunneled back and dialed to `lhost:lport` on this client. Requires the
    /// server's `--allow-remote-forward`.
    #[arg(short = 'R', long = "remote-forward")]
    remote_forward: Vec<String>,

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
    /// Generate an OpenSSH ed25519 identity for pubkey auth and print the
    /// authorized_keys line to install server-side.
    Keygen {
        /// Output path. [default: ~/.config/quish/id_ed25519]
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
        /// Key comment. [default: user@host]
        #[arg(short, long)]
        comment: Option<String>,
    },
    /// Generate a TOTP second-factor secret: prints the base32 secret, an
    /// otpauth:// URI, a QR code, and where to install it server-side.
    Totp {
        #[command(subcommand)]
        action: TotpAction,
    },
}

#[derive(clap::Subcommand, Debug)]
enum KnownHostsAction {
    /// List pinned hosts and their fingerprints.
    List,
    /// Remove a pinned host (like `ssh-keygen -R`). HOST is the `host:port` shown by `list`.
    Remove { host: String },
}

#[derive(clap::Subcommand, Debug)]
enum TotpAction {
    /// Generate a fresh secret for USER on HOST (labels the authenticator entry).
    Generate { user: String, host: String },
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

/// A parsed `-R` remote-forward spec: ask the server to bind `bind:rport` and
/// tunnel every inbound connection back to `lhost:lport` on the client side.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteForwardSpec {
    bind: IpAddr,
    rport: u16,
    lhost: String,
    lport: u16,
}

/// Parse `-R [bind:]rport:lhost:lport` (mirrors [`parse_forward`]). Bracket IPv6
/// literals (`[::1]`) so their colons don't split; a bare `bind` defaults to
/// `127.0.0.1`. The server-side bind MUST be loopback (loopback-only policy; the
/// server enforces this and the `<1024` refusal independently).
fn parse_remote_forward(s: &str) -> Result<RemoteForwardSpec> {
    let tokens = split_forward_tokens(s)?;
    let (bind_tok, rport_tok, lhost_tok, lport_tok) = match tokens.as_slice() {
        [r, lh, lp] => (None, r.as_str(), lh.as_str(), lp.as_str()),
        [b, r, lh, lp] => (Some(b.as_str()), r.as_str(), lh.as_str(), lp.as_str()),
        _ => bail!("remote forward spec `{s}` must be [bind:]rport:lhost:lport"),
    };
    let rport: u16 = rport_tok
        .parse()
        .with_context(|| format!("invalid remote port in remote forward spec `{s}`"))?;
    let lport: u16 = lport_tok
        .parse()
        .with_context(|| format!("invalid local port in remote forward spec `{s}`"))?;
    if lhost_tok.is_empty() {
        bail!("missing local host in remote forward spec `{s}`");
    }
    let bind: IpAddr = match bind_tok {
        Some(b) => b
            .parse()
            .with_context(|| format!("invalid bind address in remote forward spec `{s}`"))?,
        None => IpAddr::V4(Ipv4Addr::LOCALHOST),
    };
    if !bind.is_loopback() {
        bail!(
            "refusing non-loopback bind address {bind} in remote forward spec `{s}` (loopback-only)"
        );
    }
    Ok(RemoteForwardSpec {
        bind,
        rport,
        lhost: lhost_tok.to_string(),
        lport,
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

/// `quish keygen`: generate an OpenSSH ed25519 identity, write the private key
/// (mode 0600, refusing to overwrite) and its `.pub` (mode 0644), then print the
/// authorized_keys line and install instructions. Synchronous — no runtime.
fn run_keygen(output: Option<std::path::PathBuf>, comment: Option<String>) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let output = match output {
        Some(p) => p,
        None => {
            let home = std::env::var("HOME").context("HOME not set")?;
            std::path::PathBuf::from(home).join(".config/quish/id_ed25519")
        }
    };
    let comment = comment.unwrap_or_else(|| {
        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "quish".into());
        format!("{}@{}", whoami(), host)
    });

    let (pem, pub_line) = quish_auth::pubkey::generate_keypair(&comment)?;

    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    // Refuse to overwrite an existing identity; the private key is mode 0600.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&output)
        .with_context(|| format!("creating {} (refusing to overwrite)", output.display()))?;
    f.write_all(pem.as_bytes())
        .with_context(|| format!("writing {}", output.display()))?;

    let mut pub_os = output.clone().into_os_string();
    pub_os.push(".pub");
    let pub_path = std::path::PathBuf::from(pub_os);
    let mut pf = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&pub_path)
        .with_context(|| format!("creating {}", pub_path.display()))?;
    writeln!(pf, "{pub_line}").with_context(|| format!("writing {}", pub_path.display()))?;

    println!("{pub_line}");
    println!();
    println!("Wrote private key to {} (mode 0600)", output.display());
    println!("Wrote public key to  {} (mode 0644)", pub_path.display());
    println!();
    println!("To authorize this key, append the public line above to the target");
    println!("user's server-side ~<user>/.config/quish/authorized_keys, then connect:");
    println!("  quish -i {} user@host", output.display());
    Ok(())
}

/// Build the `otpauth://` enrollment URI an authenticator app scans. The
/// `algorithm`/`digits`/`period` values MUST match the server's TOTP constants
/// in `quish-auth/src/totp.rs:26-28` (`STEP_SECS = 30`, `DIGITS = 6`,
/// HMAC-SHA1) or generated codes will not verify. The label is emitted as
/// `quish:<user>@<host>` verbatim (no percent-encoding); callers pass plain
/// user/host tokens.
fn otpauth_uri(user: &str, host: &str, b32: &str) -> String {
    format!(
        "otpauth://totp/quish:{user}@{host}?secret={b32}&issuer=quish&algorithm=SHA1&digits=6&period=30"
    )
}

/// `quish totp generate`: mint a fresh second-factor secret and print it (base32),
/// its `otpauth://` URI, a terminal QR code, the current code, and server-side
/// install instructions. The secret goes to stdout only — never logged, never
/// written to a client-side file. Synchronous — no runtime.
fn run_totp(action: TotpAction) -> Result<()> {
    match action {
        TotpAction::Generate { user, host } => {
            let secret = quish_auth::totp::generate_totp_secret();
            let b32 = quish_auth::totp::encode_base32_secret(&secret);
            let uri = otpauth_uri(&user, &host, &b32);

            println!("secret: {b32}");
            println!("{uri}");
            let qr = qrcode::QrCode::new(&uri)
                .map_err(|e| anyhow::anyhow!("building QR code: {e}"))?
                .render::<qrcode::render::unicode::Dense1x2>()
                .build();
            println!("{qr}");
            // Zero-padded to DIGITS (6) so it matches the authenticator display.
            println!("current code: {:06}", quish_auth::totp::current_code(&secret));
            println!();
            println!("Install server-side: write the base32 secret above to");
            println!("  ~{user}/.config/quish/totp   (mode 0600)");
            println!(
                "then enable TOTP on the server (--totp, or `totp = true` in its config)."
            );
            Ok(())
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
        Some(Command::Keygen { output, comment }) => {
            return run_keygen(output, comment);
        }
        Some(Command::Totp { action }) => {
            return run_totp(action);
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
            args.connect.remote_forward,
        ))?;
    std::process::exit(code);
}

async fn run(
    target: Target,
    identity: Option<std::path::PathBuf>,
    command: Vec<String>,
    local_forwards: Vec<String>,
    remote_forwards: Vec<String>,
) -> Result<i32> {
    // Parse `-L` specs up front so a malformed spec fails before any network I/O.
    let forwards = local_forwards
        .iter()
        .map(|s| parse_forward(s))
        .collect::<Result<Vec<_>>>()?;
    let remote_forwards = remote_forwards
        .iter()
        .map(|s| parse_remote_forward(s))
        .collect::<Result<Vec<_>>>()?;

    let (mut send_request, drive, authorization) = establish(&target, identity.as_deref()).await?;

    // Forward mode: bind the local ports and tunnel each accepted connection over
    // its own Extended CONNECT channel. Runs until the listeners stop (Ctrl-C).
    if !forwards.is_empty() || !remote_forwards.is_empty() {
        run_forwarding(
            send_request,
            forwards,
            remote_forwards,
            target,
            authorization,
        )
        .await?;
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
    // One first attempt (no answer) plus up to MAX_CHALLENGE_ROUNDS follow-up
    // rounds. Each CONNECT carries the same channel-bound `authorization`; a
    // challenge round additionally echoes the server's opaque token + our
    // responses. The per-connection challenge state lives server-side.
    let mut answer: Option<String> = None;
    for round in 0..=MAX_CHALLENGE_ROUNDS {
        let req = build_connect_request_with(target, authorization, answer.as_deref());
        let mut stream = send_request
            .send_request(req)
            .await
            .context("sending CONNECT")?;
        let resp = stream.recv_response().await.context("awaiting response")?;
        match resp.status() {
            http::StatusCode::OK => {
                info!(user = %target.user, "session authenticated");
                return Ok(stream.split());
            }
            http::StatusCode::UNAUTHORIZED => {
                // A challenge header means "answer a further factor", not a
                // terminal failure. Without it (or once rounds run out), the 401
                // is final and indistinguishable from any other auth rejection.
                let challenge = resp
                    .headers()
                    .get(quish_proto::HEADER_CHALLENGE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(quish_proto::decode_challenge);
                match challenge {
                    Some(challenge) if round < MAX_CHALLENGE_ROUNDS => {
                        let a = build_challenge_answer(&challenge, read_prompt)?;
                        answer = Some(quish_proto::encode_challenge_answer(&a));
                    }
                    _ => bail!("authentication failed"),
                }
            }
            http::StatusCode::UPGRADE_REQUIRED => {
                bail!(
                    "server rejected our protocol version (quish-version {}); client/server mismatch",
                    quish_proto::PROTOCOL_VERSION
                )
            }
            s => bail!("server rejected session: HTTP {s}"),
        }
    }
    bail!("authentication failed")
}

/// Cap on challenge follow-up rounds, so a misbehaving/hostile server can never
/// loop the client forever prompting for codes.
const MAX_CHALLENGE_ROUNDS: usize = 3;

/// Assemble a [`ChallengeAnswer`] for `challenge`: echo its token and collect one
/// response per prompt (in order) via `read`. Pure over `read` so it is unit-
/// testable without a live terminal.
fn build_challenge_answer(
    challenge: &quish_proto::Challenge,
    read: impl FnMut(&quish_proto::Prompt) -> Result<String>,
) -> Result<quish_proto::ChallengeAnswer> {
    let responses = challenge
        .prompts
        .iter()
        .map(read)
        .collect::<Result<Vec<_>>>()?;
    Ok(quish_proto::ChallengeAnswer {
        token: challenge.token.clone(),
        responses,
    })
}

/// Read one prompt's response. Scripted runs set `QUISH_TOTP` (used for every
/// prompt, matching how `QUISH_PASSWORD` drives the first factor). Interactively,
/// echo-off prompts read with `rpassword`; visible prompts read a plain line.
fn read_prompt(prompt: &quish_proto::Prompt) -> Result<String> {
    if let Ok(v) = std::env::var("QUISH_TOTP") {
        return Ok(v);
    }
    if prompt.echo {
        use std::io::Write;
        eprint!("{}", prompt.message);
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("reading challenge response")?;
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    } else {
        rpassword::prompt_password(&prompt.message).context("reading challenge response")
    }
}

/// Build the Extended CONNECT request every channel opens with. `:protocol` must
/// be a value h3 accepts (its `Protocol` enum is closed), so we use WEB_TRANSPORT
/// and let the secret path + version header mark this as quish. The channel-bound
/// `authorization` is reused on every channel (it is bound to the connection, not
/// the stream).
fn build_connect_request(target: &Target, authorization: &str) -> http::Request<()> {
    build_connect_request_with(target, authorization, None)
}

/// Like [`build_connect_request`], but also attaches the challenge-response
/// header when `answer` is `Some` (a follow-up round of a multi-round login).
fn build_connect_request_with(
    target: &Target,
    authorization: &str,
    answer: Option<&str>,
) -> http::Request<()> {
    let mut builder = http::Request::builder()
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
        .extension(Protocol::WEB_TRANSPORT);
    if let Some(a) = answer {
        builder = builder.header(quish_proto::HEADER_CHALLENGE_RESPONSE, a);
    }
    builder.body(()).expect("valid request")
}

/// Bind every `-L` listener and open every `-R` control channel, then serve
/// until a forward task ends (a listener/accept error, or the connection drops).
/// Each `-L` listener and each `-R` control channel runs on its own task.
async fn run_forwarding(
    send_request: SendRequest,
    forwards: Vec<ForwardSpec>,
    remote_forwards: Vec<RemoteForwardSpec>,
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
        tasks.push(tokio::spawn(accept_loop(
            listener,
            send_request.clone(),
            spec,
            target.clone(),
            authorization.clone(),
        )));
    }
    for spec in remote_forwards {
        tasks.push(tokio::spawn(remote_forward_listen(
            send_request.clone(),
            spec,
            target.clone(),
            authorization.clone(),
        )));
    }
    // Tasks run until they end; join so a bind/accept/channel failure surfaces.
    for task in tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(e) => return Err(anyhow::anyhow!("forward task panicked: {e}")),
        }
    }
    Ok(())
}

/// Open one `-R` control channel: request the server bind `bind:rport`, then for
/// every `Accepted { conn_ref }` signal open a data channel and dial the local
/// `lhost:lport`. The control channel (and thus the server-side listener) stays
/// up until the connection drops or the server closes it.
async fn remote_forward_listen(
    mut send_request: SendRequest,
    spec: RemoteForwardSpec,
    target: Target,
    authorization: String,
) -> Result<()> {
    let req = build_connect_request(&target, &authorization);
    let mut stream = send_request
        .send_request(req)
        .await
        .context("opening remote-forward control channel")?;
    let resp = stream
        .recv_response()
        .await
        .context("awaiting remote-forward control response")?;
    if resp.status() != http::StatusCode::OK {
        bail!(
            "server rejected remote-forward control channel: HTTP {}",
            resp.status()
        );
    }
    let (mut send, recv) = stream.split();
    // The send half is held (never finished) for the listener's lifetime so the
    // server sees the control channel stay open.
    send.send_data(Bytes::from(quish_proto::encode(
        &ChannelOpen::RemoteForwardListen {
            bind: spec.bind.to_string(),
            port: spec.rport,
        },
    )?))
    .await
    .context("sending RemoteForwardListen open")?;
    info!(
        bind = %spec.bind, rport = spec.rport, lhost = %spec.lhost, lport = spec.lport,
        "remote forward requested"
    );

    let mut reader = ChannelFrameReader::new(recv);
    // The control channel carries only `AcceptedSignal` frames (server→client).
    while let Some(body) = reader.next_frame().await? {
        let quish_proto::AcceptedSignal { conn_ref } =
            quish_proto::decode::<quish_proto::AcceptedSignal>(&body)
                .context("decoding remote-forward accept signal")?;
        let send_request = send_request.clone();
        let target = target.clone();
        let authorization = authorization.clone();
        let lhost = spec.lhost.clone();
        let lport = spec.lport;
        tokio::spawn(async move {
            if let Err(e) =
                remote_forward_data(send_request, target, authorization, conn_ref, lhost, lport)
                    .await
            {
                warn!(error = %e, "remote-forward connection ended");
            }
        });
    }
    Ok(())
}

/// Handle one inbound connection the server accepted for a `-R` forward: dial the
/// local `lhost:lport`, open a `RemoteForwardData` channel for `conn_ref`, and
/// bridge the two. If the local dial fails the inbound is dropped (the server's
/// parked socket then times out).
async fn remote_forward_data(
    mut send_request: SendRequest,
    target: Target,
    authorization: String,
    conn_ref: u64,
    lhost: String,
    lport: u16,
) -> Result<()> {
    let tcp = match TcpStream::connect((lhost.as_str(), lport)).await {
        Ok(s) => s,
        Err(e) => {
            warn!(%lhost, %lport, error = %e, "remote-forward: local dial failed; dropping inbound");
            return Ok(());
        }
    };
    let req = build_connect_request(&target, &authorization);
    let mut stream = send_request
        .send_request(req)
        .await
        .context("opening remote-forward data channel")?;
    let resp = stream
        .recv_response()
        .await
        .context("awaiting remote-forward data response")?;
    if resp.status() != http::StatusCode::OK {
        bail!(
            "server rejected remote-forward data channel: HTTP {}",
            resp.status()
        );
    }
    let (mut send, recv) = stream.split();
    send.send_data(Bytes::from(quish_proto::encode(
        &ChannelOpen::RemoteForwardData { conn_ref },
    )?))
    .await
    .context("sending RemoteForwardData open")?;
    bridge(tcp, send, recv).await
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

    /// Next decoded [`ChannelMessage`], or `None` at clean end of stream.
    pub(crate) async fn next(&mut self) -> Result<Option<ChannelMessage>> {
        match self.next_frame().await? {
            Some(body) => Ok(Some(quish_proto::decode::<ChannelMessage>(&body)?)),
            None => Ok(None),
        }
    }

    /// Next raw frame body, or `None` at clean end of stream. Callers decode it
    /// into the type their channel carries (data channels: [`ChannelMessage`];
    /// a remote-forward control channel: [`quish_proto::AcceptedSignal`]).
    pub(crate) async fn next_frame(&mut self) -> Result<Option<Bytes>> {
        loop {
            if let Some(body) = quish_proto::take_frame(&mut self.buf)? {
                return Ok(Some(body));
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
    fn challenge_answer_echoes_token_and_orders_responses() {
        let challenge = quish_proto::Challenge {
            token: "srv-token-xyz".into(),
            prompts: vec![
                quish_proto::Prompt {
                    message: "TOTP code: ".into(),
                    echo: false,
                },
                quish_proto::Prompt {
                    message: "PIN: ".into(),
                    echo: true,
                },
            ],
        };
        // Stub reader: response is derived from the prompt so we can assert order.
        let answer = build_challenge_answer(&challenge, |p| {
            Ok(if p.echo {
                "pin-2".into()
            } else {
                "code-1".into()
            })
        })
        .unwrap();
        assert_eq!(answer.token, "srv-token-xyz");
        assert_eq!(answer.responses, vec!["code-1".to_string(), "pin-2".into()]);
        // Round-trips through the header codec the server decodes.
        let encoded = quish_proto::encode_challenge_answer(&answer);
        assert_eq!(quish_proto::decode_challenge_answer(&encoded), Some(answer));
    }

    #[test]
    fn challenge_answer_propagates_a_read_error() {
        let challenge = quish_proto::Challenge {
            token: "t".into(),
            prompts: vec![quish_proto::Prompt {
                message: "x".into(),
                echo: false,
            }],
        };
        let err = build_challenge_answer(&challenge, |_p| bail!("no tty")).is_err();
        assert!(err, "a failing prompt read must abort answer assembly");
    }

    #[test]
    fn otpauth_uri_formats_exactly() {
        // The URI must carry the server's fixed TOTP parameters verbatim
        // (SHA1/6/30) and label the entry `quish:<user>@<host>`.
        let uri = otpauth_uri("alice", "example.com", "JBSWY3DPEHPK3PXP");
        assert_eq!(
            uri,
            "otpauth://totp/quish:alice@example.com?secret=JBSWY3DPEHPK3PXP\
             &issuer=quish&algorithm=SHA1&digits=6&period=30"
        );
    }

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

    #[test]
    fn parse_remote_forward_rport_lhost_lport() {
        let f = parse_remote_forward("8080:127.0.0.1:5432").unwrap();
        assert_eq!(
            f,
            RemoteForwardSpec {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                rport: 8080,
                lhost: "127.0.0.1".into(),
                lport: 5432,
            }
        );
    }

    #[test]
    fn parse_remote_forward_bind_rport_lhost_lport() {
        let f = parse_remote_forward("127.0.0.1:8080:127.0.0.1:5432").unwrap();
        assert_eq!(
            f,
            RemoteForwardSpec {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                rport: 8080,
                lhost: "127.0.0.1".into(),
                lport: 5432,
            }
        );
    }

    #[test]
    fn parse_remote_forward_rejects_non_loopback_bind() {
        assert!(parse_remote_forward("0.0.0.0:8080:127.0.0.1:5432").is_err());
        assert!(parse_remote_forward("192.168.1.10:8080:127.0.0.1:5432").is_err());
    }

    #[test]
    fn parse_remote_forward_rejects_malformed() {
        assert!(parse_remote_forward("nonsense").is_err()); // too few fields
        assert!(parse_remote_forward("8080:127.0.0.1").is_err()); // missing lport
        assert!(parse_remote_forward("notaport:127.0.0.1:5432").is_err()); // bad rport
        assert!(parse_remote_forward("8080:127.0.0.1:notaport").is_err()); // bad lport
        assert!(parse_remote_forward("a:8080:127.0.0.1:5432").is_err()); // bad bind
    }
}
