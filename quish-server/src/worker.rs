//! The worker: unprivileged, chrooted child. Terminates QUIC/H3/TLS and does all
//! untrusted parsing. It never holds the host key (signs via the monitor proxy)
//! and never spawns sessions itself — it RPCs the monitor and pumps the returned
//! fds. Auth verdicts are the monitor's; the worker only sees allow/deny.

use std::fs::File;
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
use tracing::{info, warn};

use crate::ipc::{self, Request, Response};
use crate::session::{
    FrameReader, FullStream, PumpEnd, SendHalf, pump_exec, pump_shell, read_loop, send_msg,
    serve_forward, spawn_frame_reader, write_loop,
};
use crate::signproxy::ProxySigningKey;

/// Max byte length of a client-supplied command/term forwarded to the monitor.
/// Kept well below ipc::IPC_CAP so the wrapped Request (enum tag + conn_id +
/// length varints) can never overflow the monitor's recv buffer — an overflow
/// would truncate the SEQPACKET message and fail decode.
const MAX_SPAWN_ARG_LEN: usize = 60 * 1024;

/// Whether a client-supplied spawn arg (command/term) length is within cap.
fn spawn_arg_ok(len: usize) -> bool {
    len <= MAX_SPAWN_ARG_LEN
}

/// `--internal-worker` entry. Connects to the monitor, drops privileges, then
/// serves QUIC/H3.
pub fn run() -> Result<()> {
    let ctrl_path = ipc::env(ipc::ENV_CTRL_PATH)?;
    let sign_path = ipc::env(ipc::ENV_SIGN_PATH)?;
    let listen: std::net::SocketAddr = ipc::env(ipc::ENV_LISTEN)?.parse().context("listen addr")?;
    let path = ipc::env(ipc::ENV_PATH)?;
    let chroot_dir = ipc::env(ipc::ENV_CHROOT)?;
    let worker_user = ipc::env(ipc::ENV_USER)?;
    let scheme = SignatureScheme::from(ipc::env(ipc::ENV_SIGN_SCHEME)?.parse::<u16>()?);
    let max_auth_fails = ipc::env(ipc::ENV_MAX_AUTH_FAILS)?
        .parse::<u32>()
        .context("max_auth_fails")?;
    let allow_forward = ipc::env_bool(ipc::ENV_ALLOW_FORWARD);
    let cert_der = CertificateDer::from(
        BASE64_STANDARD
            .decode(ipc::env(ipc::ENV_CERT)?)
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

        // Bind the UDP socket while still root so privileged ports (<1024) work;
        // quinn then adopts this already-bound socket after we drop privileges.
        let socket = std::net::UdpSocket::bind(listen).context("binding UDP socket")?;

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
        let runtime = quinn::default_runtime().context("no async runtime for quinn")?;
        let endpoint =
            quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(sc), socket, runtime)
                .context("building endpoint from bound socket")?;

        let client = Arc::new(MonitorClient::new(ctrl));
        let backend = Arc::new(crate::transport::Backend::Privsep { client });
        crate::transport::run(endpoint, path, backend, max_auth_fails, allow_forward).await
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
            fail_delay: crate::FAIL_DELAY,
        }
    }

    async fn call(&self, req: &Request) -> Result<(Response, Vec<OwnedFd>)> {
        let sock = self.sock.lock().await;
        ipc::ctrl_send(&sock, req, &[]).await?;
        match ipc::ctrl_recv::<Response>(&sock).await? {
            ipc::Recv::Msg(resp, fds) => Ok((resp, fds)),
            ipc::Recv::Bad | ipc::Recv::Closed => bail!("monitor closed control channel"),
        }
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

    async fn spawn_shell(&self, conn_id: u64, term: &str) -> Result<(u64, OwnedFd)> {
        let (resp, mut fds) = self
            .call(&Request::SpawnShell {
                conn_id,
                term: term.to_string(),
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

    async fn signal(&self, session_id: u64, signal: quish_proto::Signal) {
        let _ = self.call(&Request::Signal { session_id, signal }).await;
    }

    pub async fn close(&self, conn_id: u64) {
        let _ = self.call(&Request::Close { conn_id }).await;
    }
}

/// Serve one channel: read `ChannelOpen`, ask the monitor to spawn, pump fds.
pub async fn serve_channel(
    client: &MonitorClient,
    conn_id: u64,
    stream: FullStream,
    allow_forward: bool,
) -> Result<()> {
    let (send, recv) = stream.split();
    let mut reader = FrameReader::new(recv);
    let Some(body) = reader.next_frame().await? else {
        return Ok(());
    };
    match quish_proto::decode::<ChannelOpen>(&body).context("decoding ChannelOpen")? {
        ChannelOpen::Shell { term, cols, rows } => {
            if !spawn_arg_ok(term.len()) {
                warn!(%conn_id, len = term.len(), "rejecting over-length term");
                return Ok(());
            }
            info!(%conn_id, %cols, %rows, "shell channel");
            let (session_id, master) = client.spawn_shell(conn_id, &term).await?;
            run_shell(client, session_id, master, cols, rows, send, reader).await
        }
        ChannelOpen::Exec { command } => {
            if !spawn_arg_ok(command.len()) {
                warn!(%conn_id, len = command.len(), "rejecting over-length command");
                return Ok(());
            }
            // do not log the command body — it may contain secrets
            info!(%conn_id, "exec channel");
            let (session_id, io) = client.spawn_exec(conn_id, &command).await?;
            run_exec(client, session_id, io, send, reader).await
        }
        ChannelOpen::Forward { host, port } => {
            if !spawn_arg_ok(host.len()) {
                warn!(%conn_id, len = host.len(), "rejecting over-length forward host");
                return Ok(());
            }
            info!(%conn_id, %port, "forward channel");
            // Loopback-only egress policy + Data pump live in the shared helper;
            // no monitor RPC (the worker opens the socket unprivileged).
            serve_forward(send, reader, host, port, allow_forward).await
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

    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);
    let out_file = master.try_clone()?;
    std::thread::spawn(move || read_loop(out_file, out_tx));

    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    let in_file = master.try_clone()?;
    std::thread::spawn(move || write_loop(in_file, in_rx));

    let frames = spawn_frame_reader(reader);
    let end = pump_shell(&mut send, frames, out_rx, in_tx, |cols, rows| {
        set_winsize(&master, cols, rows)
    })
    .await?;

    drop(master); // release the winsize handle; reap kills/collects the child
    let code = client.reap(session_id).await; // ALWAYS reap — no session leak
    if let PumpEnd::Drained = end {
        send_msg(&mut send, &ChannelMessage::ExitStatus(code)).await?;
    }
    send.finish().await.map_err(Into::into)
}

async fn run_exec(
    client: &MonitorClient,
    session_id: u64,
    [stdin, stdout, stderr]: [OwnedFd; 3],
    mut send: SendHalf,
    reader: FrameReader,
) -> Result<()> {
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || read_loop(File::from(stdout), out_tx));
    let (err_tx, err_rx) = mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || read_loop(File::from(stderr), err_tx));
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || write_loop(File::from(stdin), in_rx));

    let frames = spawn_frame_reader(reader);
    let (sig_tx, mut sig_rx) = mpsc::channel::<quish_proto::Signal>(8);
    let pump = pump_exec(&mut send, frames, out_rx, err_rx, in_tx, sig_tx);
    let drain = async {
        while let Some(s) = sig_rx.recv().await {
            client.signal(session_id, s).await;
        }
    };
    let (end, ()) = tokio::join!(pump, drain);
    let end = end?;

    let code = client.reap(session_id).await; // ALWAYS reap — no session leak
    if let PumpEnd::Drained = end {
        send_msg(&mut send, &ChannelMessage::ExitStatus(code)).await?;
    }
    send.finish().await.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_arg_boundary() {
        assert!(spawn_arg_ok(MAX_SPAWN_ARG_LEN));
        assert!(!spawn_arg_ok(MAX_SPAWN_ARG_LEN + 1));
        const { assert!(MAX_SPAWN_ARG_LEN < super::ipc::IPC_CAP) };
    }
}
