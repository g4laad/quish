//! The worker: unprivileged, chrooted child. Terminates QUIC/H3/TLS and does all
//! untrusted parsing. It never holds the host key (signs via the monitor proxy)
//! and never spawns sessions itself — it RPCs the monitor and pumps the returned
//! fds. Auth verdicts are the monitor's; the worker only sees allow/deny.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::prelude::{BASE64_STANDARD, Engine};
use quish_auth::ConnInfo;
use quish_proto::{ChannelMessage, ChannelOpen};
use rustls::SignatureScheme;
use rustls::pki_types::CertificateDer;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use tokio::sync::{Mutex, mpsc};
use tokio_seqpacket::UnixSeqpacket;
use tracing::info;

use crate::ipc::{self, Request, Response};
use crate::session::{FrameReader, FullStream, SendHalf, send_msg, spawn_frame_reader};
use crate::signproxy::ProxySigningKey;

/// `--internal-worker` entry. Connects to the monitor, drops privileges, then
/// serves QUIC/H3.
pub fn run() -> Result<()> {
    let ctrl_path = env(ipc::ENV_CTRL_PATH)?;
    let sign_path = env(ipc::ENV_SIGN_PATH)?;
    let listen: std::net::SocketAddr = env(ipc::ENV_LISTEN)?.parse().context("listen addr")?;
    let path = env(ipc::ENV_PATH)?;
    let chroot_dir = env(ipc::ENV_CHROOT)?;
    let worker_user = env(ipc::ENV_USER)?;
    let scheme = SignatureScheme::from(env(ipc::ENV_SIGN_SCHEME)?.parse::<u16>()?);
    let cert_der = CertificateDer::from(
        BASE64_STANDARD
            .decode(env(ipc::ENV_CERT)?)
            .context("decode cert")?,
    );

    // Single-threaded runtime: privilege drop then affects the whole process, and
    // session I/O uses dedicated blocking threads (spawned post-drop) anyway.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        // Connect to the monitor *before* chroot (socket paths live outside it).
        let ctrl = UnixSeqpacket::connect(&ctrl_path)
            .await
            .context("connect ctrl socket")?;
        let sign_stream = UnixStream::connect(&sign_path).context("connect sign socket")?;

        // Irrevocably drop privileges.
        crate::privdrop::drop_to_worker(&chroot_dir, &worker_user)?;
        info!(user = %worker_user, "worker privilege-dropped");

        // TLS with the signing proxy (host key stays in the monitor).
        let proxy = ProxySigningKey::new(sign_stream, scheme);
        let certified = Arc::new(CertifiedKey::new(vec![cert_der], Arc::new(proxy)));
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCert(certified)));
        tls.alpn_protocols = vec![quish_proto::ALPN.to_vec()];

        let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .context("quinn rustls config")?;
        let mut sc = quinn::ServerConfig::with_crypto(Arc::new(quic));
        sc.transport_config(crate::transport::transport_config());
        let endpoint = quinn::Endpoint::server(sc, listen).context("binding endpoint")?;

        let client = Arc::new(MonitorClient::new(ctrl));
        let backend = Arc::new(crate::transport::Backend::Privsep { client });
        crate::transport::run(endpoint, path, backend).await
    })
}

/// Static single-cert resolver returning the monitor-provided chain + proxy key.
#[derive(Debug)]
struct SingleCert(Arc<CertifiedKey>);

impl ResolvesServerCert for SingleCert {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// The worker's serialized RPC client to the monitor.
pub struct MonitorClient {
    // ponytail: one lock serializes all RPCs (auth/spawn/reap). Fine at v1 scale;
    // per-connection monitors would be the throughput upgrade.
    sock: Mutex<UnixSeqpacket>,
    pub fail_delay: Duration,
}

impl MonitorClient {
    fn new(sock: UnixSeqpacket) -> Self {
        Self {
            sock: Mutex::new(sock),
            fail_delay: Duration::from_secs(1),
        }
    }

    async fn call(&self, req: &Request) -> Result<(Response, Vec<OwnedFd>)> {
        let sock = self.sock.lock().await;
        ipc::ctrl_send(&sock, req, &[]).await?;
        ipc::ctrl_recv::<Response>(&sock)
            .await?
            .context("monitor closed control channel")
    }

    pub async fn authenticate(
        &self,
        conn_id: u64,
        authorization: Option<&str>,
        conn: &ConnInfo,
    ) -> Result<bool> {
        let req = Request::Authenticate {
            conn_id,
            authorization: authorization.map(str::to_string),
            peer: conn.peer_addr.to_string(),
            channel_binding: conn.channel_binding,
        };
        match self.call(&req).await?.0 {
            Response::Verdict(allow) => Ok(allow),
            _ => Ok(false),
        }
    }

    async fn spawn_shell(
        &self,
        conn_id: u64,
        term: &str,
        cols: u16,
        rows: u16,
    ) -> Result<(u64, OwnedFd)> {
        let (resp, mut fds) = self
            .call(&Request::SpawnShell {
                conn_id,
                term: term.to_string(),
                cols,
                rows,
            })
            .await?;
        match resp {
            Response::Spawned { session_id } if fds.len() == 1 => Ok((session_id, fds.remove(0))),
            _ => bail!("monitor refused shell"),
        }
    }

    async fn spawn_exec(&self, conn_id: u64, command: &str) -> Result<(u64, [OwnedFd; 3])> {
        let (resp, fds) = self
            .call(&Request::SpawnExec {
                conn_id,
                command: command.to_string(),
            })
            .await?;
        match resp {
            Response::Spawned { session_id } if fds.len() == 3 => {
                let mut it = fds.into_iter();
                Ok((
                    session_id,
                    [it.next().unwrap(), it.next().unwrap(), it.next().unwrap()],
                ))
            }
            _ => bail!("monitor refused exec"),
        }
    }

    async fn reap(&self, session_id: u64) -> i32 {
        match self.call(&Request::Reap { session_id }).await {
            Ok((Response::Exited(code), _)) => code,
            _ => -1,
        }
    }

    pub async fn close(&self, conn_id: u64) {
        let _ = self.call(&Request::Close { conn_id }).await;
    }
}

/// Serve one channel: read `ChannelOpen`, ask the monitor to spawn, pump fds.
pub async fn serve_channel(client: &MonitorClient, conn_id: u64, stream: FullStream) -> Result<()> {
    let (send, recv) = stream.split();
    let mut reader = FrameReader::new(recv);
    let Some(body) = reader.next_frame().await? else {
        return Ok(());
    };
    match quish_proto::decode::<ChannelOpen>(&body).context("decoding ChannelOpen")? {
        ChannelOpen::Shell { term, cols, rows } => {
            info!(%conn_id, %cols, %rows, "shell channel");
            let (session_id, master) = client.spawn_shell(conn_id, &term, cols, rows).await?;
            run_shell(client, session_id, master, cols, rows, send, reader).await
        }
        ChannelOpen::Exec { command } => {
            info!(%conn_id, %command, "exec channel");
            let (session_id, io) = client.spawn_exec(conn_id, &command).await?;
            run_exec(client, session_id, io, send, reader).await
        }
    }
}

fn set_winsize(file: &File, cols: u16, rows: u16) {
    let ws = rustix::termios::Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let _ = rustix::termios::tcsetwinsize(file, ws);
}

async fn run_shell(
    client: &MonitorClient,
    session_id: u64,
    master: OwnedFd,
    cols: u16,
    rows: u16,
    mut send: SendHalf,
    reader: FrameReader,
) -> Result<()> {
    let master = File::from(master);
    set_winsize(&master, cols, rows);

    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
    let out_file = master.try_clone()?;
    std::thread::spawn(move || read_loop(out_file, out_tx));

    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    let in_file = master.try_clone()?;
    std::thread::spawn(move || write_loop(in_file, in_rx));

    let mut frames = spawn_frame_reader(reader);
    let mut in_tx = Some(in_tx);
    let mut frames_done = false;

    loop {
        tokio::select! {
            msg = frames.recv(), if !frames_done => match msg {
                Some(ChannelMessage::Data(d)) => {
                    if let Some(tx) = in_tx.as_ref() {
                        let _ = tx.send(d).await;
                    }
                }
                Some(ChannelMessage::Resize { cols, rows }) => set_winsize(&master, cols, rows),
                Some(_) => {}
                None => {
                    frames_done = true;
                    in_tx = None; // EOF the shell's stdin
                }
            },
            out = out_rx.recv() => match out {
                Some(bytes) => {
                    if !send_msg(&mut send, &ChannelMessage::Data(bytes)).await? {
                        break;
                    }
                }
                None => break, // PTY drained: shell exited
            },
        }
    }

    let code = client.reap(session_id).await;
    send_msg(&mut send, &ChannelMessage::ExitStatus(code)).await?;
    send.finish().await.map_err(Into::into)
}

async fn run_exec(
    client: &MonitorClient,
    session_id: u64,
    [stdin, stdout, stderr]: [OwnedFd; 3],
    mut send: SendHalf,
    reader: FrameReader,
) -> Result<()> {
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || read_loop(File::from(stdout), out_tx));
    let (err_tx, mut err_rx) = mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || read_loop(File::from(stderr), err_tx));
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || write_loop(File::from(stdin), in_rx));

    let mut frames = spawn_frame_reader(reader);
    let mut in_tx = Some(in_tx);
    let (mut out_done, mut err_done, mut frames_done) = (false, false, false);

    loop {
        tokio::select! {
            out = out_rx.recv(), if !out_done => match out {
                Some(bytes) => { if !send_msg(&mut send, &ChannelMessage::Data(bytes)).await? { break; } }
                None => out_done = true,
            },
            err = err_rx.recv(), if !err_done => match err {
                Some(bytes) => { if !send_msg(&mut send, &ChannelMessage::DataErr(bytes)).await? { break; } }
                None => err_done = true,
            },
            msg = frames.recv(), if !frames_done => match msg {
                Some(ChannelMessage::Data(d)) => {
                    if let Some(tx) = in_tx.as_ref() { let _ = tx.send(d).await; }
                }
                Some(_) => {}
                None => { frames_done = true; in_tx = None; } // EOF child stdin
            },
        }
        if out_done && err_done {
            break;
        }
    }

    let code = client.reap(session_id).await;
    send_msg(&mut send, &ChannelMessage::ExitStatus(code)).await?;
    send.finish().await.map_err(Into::into)
}

/// Blocking fd → mpsc (session output). Ends on EOF/error.
fn read_loop(mut file: File, tx: mpsc::Sender<Vec<u8>>) {
    let mut buf = [0u8; 8192];
    loop {
        match file.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if tx.blocking_send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        }
    }
}

/// Blocking mpsc → fd (session input). Ends when the sender drops (stdin EOF).
fn write_loop(mut file: File, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(bytes) = rx.blocking_recv() {
        if file.write_all(&bytes).is_err() || file.flush().is_err() {
            break;
        }
    }
}

fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing env {key}"))
}
