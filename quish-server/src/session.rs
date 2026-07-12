//! Channel sessions: interactive PTY shell + one-shot exec.
//!
//! After the authed Extended CONNECT gets its 200, the client sends one
//! [`ChannelOpen`] frame; this module reads it and runs the requested channel,
//! tunnelling [`ChannelMessage`] frames over H3 DATA both directions until the
//! process exits (final `ExitStatus` frame) or a side hangs up.
//!
//! Cancel-safety: H3 `recv_data` is not cancel-safe, so it is never `select!`ed
//! directly. A dedicated task ([`spawn_frame_reader`]) owns the recv half and
//! feeds decoded frames into an mpsc the main loop selects over.

use std::process::Stdio;

use anyhow::{Context, Result};
use bytes::{Buf, Bytes};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use quish_proto::{ChannelMessage, ChannelOpen, LEN_PREFIX, parse_len};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub(crate) type FullStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
pub(crate) type SendHalf = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
pub(crate) type RecvHalf = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;

/// Read the opening frame and dispatch to the requested channel type (dev mode:
/// spawns the process locally via portable-pty).
pub async fn serve(stream: FullStream, allow_forward: bool) -> Result<()> {
    let (send, recv) = stream.split();
    let mut reader = FrameReader::new(recv);

    let Some(body) = reader.next_frame().await? else {
        // Client opened the channel then said nothing; nothing to do.
        return Ok(());
    };
    match quish_proto::decode::<ChannelOpen>(&body).context("decoding ChannelOpen")? {
        ChannelOpen::Shell { term, cols, rows } => {
            info!(%cols, %rows, "shell channel");
            shell(send, reader, term, cols, rows).await
        }
        ChannelOpen::Exec { command } => {
            // do not log the command body — it may contain secrets
            info!("exec channel");
            exec(send, reader, command).await
        }
        ChannelOpen::Forward { host, port } => {
            info!(%port, "forward channel");
            serve_forward(send, reader, host, port, allow_forward).await
        }
        ChannelOpen::ReadFile { path } => {
            info!("readfile channel");
            transfer(send, path).await
        }
    }
}

/// Dev-mode download: open `path`, refuse non-regular files, and stream the
/// bytes as `Data` frames + a terminal `ExitStatus` (nonzero on failure). Dev
/// mode is a single process with no privilege drop, so the file is read as
/// whoever runs `quishd` — the privsep worker (worker.rs) is the path that
/// enforces the real per-user identity boundary.
async fn transfer(mut send: SendHalf, path: String) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    let reader = std::thread::spawn(move || -> std::io::Result<()> {
        let file = std::fs::File::open(&path)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(std::io::Error::other("not a regular file"));
        }
        read_loop(file, tx);
        Ok(())
    });

    let mut client_gone = false;
    while let Some(chunk) = rx.recv().await {
        if !send_msg(&mut send, &ChannelMessage::Data(chunk)).await? {
            client_gone = true;
            break;
        }
    }

    let code = match reader.join() {
        Ok(Ok(())) => 0,
        _ => 1,
    };
    if !client_gone {
        send_msg(&mut send, &ChannelMessage::ExitStatus(code)).await?;
    }
    send.finish().await.map_err(Into::into)
}

/// Interactive shell on a PTY. stdout+stderr merge on the tty (correct terminal
/// behaviour); resize is honoured; the shell's exit code is the final frame.
async fn shell(
    mut send: SendHalf,
    reader: FrameReader,
    term: String,
    cols: u16,
    rows: u16,
) -> Result<()> {
    let size = PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    };
    let pair = native_pty_system().openpty(size).context("openpty")?;

    let mut cmd = CommandBuilder::new_default_prog();
    cmd.env("TERM", if term.is_empty() { "xterm" } else { &term });
    let mut child = pair.slave.spawn_command(cmd).context("spawning shell")?;
    drop(pair.slave); // parent doesn't hold the slave side

    // PTY output → mpsc (blocking read thread; portable-pty is std::io).
    let pty_out = pair.master.try_clone_reader().context("pty reader")?;
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || read_loop(pty_out, out_tx));

    // stdin mpsc → PTY writer (blocking write thread). Dropping in_tx closes the
    // shell's stdin (EOF) — that's how a client hangup ends e.g. `cat`.
    let pty_in = pair.master.take_writer().context("pty writer")?;
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || write_loop(pty_in, in_rx));

    // Child reaper → oneshot exit code.
    let (exit_tx, mut exit_rx) = tokio::sync::oneshot::channel::<i32>();
    std::thread::spawn(move || {
        let code = child.wait().map(|s| s.exit_code() as i32).unwrap_or(-1);
        let _ = exit_tx.send(code);
    });

    let master = pair.master; // kept alive; borrowed by the resize closure below
    let frames = spawn_frame_reader(reader);

    let end = pump_shell(&mut send, frames, out_rx, in_tx, move |cols, rows| {
        let _ = master.resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        });
    })
    .await?;

    if let PumpEnd::Drained = end {
        let code = match exit_rx.try_recv() {
            Ok(c) => c,
            Err(_) => (&mut exit_rx).await.unwrap_or(-1),
        };
        send_msg(&mut send, &ChannelMessage::ExitStatus(code)).await?;
    }
    send.finish().await.map_err(Into::into)
}

/// One-shot command under the login shell. stdout→`Data`, stderr→`DataErr`,
/// exit code as the final `ExitStatus` frame.
async fn exec(mut send: SendHalf, reader: FrameReader, command: String) -> Result<()> {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let mut child = tokio::process::Command::new(shell)
        .arg("-c")
        .arg(&command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning exec")?;

    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let mut stdin = child.stdin.take().expect("piped stdin");

    // stdout/stderr → mpsc (async read tasks); mpsc → stdin (async write task).
    // Mirrors the blocking read_loop/write_loop the privsep worker uses over fds,
    // but with tokio's async child pipes.
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    let (err_tx, err_rx) = mpsc::channel::<Vec<u8>>(64);
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if err_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(64);
    tokio::spawn(async move {
        while let Some(bytes) = in_rx.recv().await {
            if stdin.write_all(&bytes).await.is_err() || stdin.flush().await.is_err() {
                break;
            }
        }
        // dropping `stdin` here closes the child's stdin (EOF) when the pump
        // drops `in_tx` on client frame-EOF or when the loop ends.
    });

    let frames = spawn_frame_reader(reader);
    let (sig_tx, mut sig_rx) = mpsc::channel::<quish_proto::Signal>(8);
    let child_id = child.id(); // Option<u32>
    let pump = pump_exec(&mut send, frames, out_rx, err_rx, in_tx, sig_tx);
    let drain = async {
        while let Some(s) = sig_rx.recv().await {
            if let Some(pid) = child_id {
                let sig = match s {
                    quish_proto::Signal::Int => nix::sys::signal::Signal::SIGINT,
                    quish_proto::Signal::Quit => nix::sys::signal::Signal::SIGQUIT,
                    quish_proto::Signal::Term => nix::sys::signal::Signal::SIGTERM,
                };
                let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), sig);
            }
        }
    };
    let (end, ()) = tokio::join!(pump, drain);
    let end = end?;

    if let PumpEnd::Drained = end {
        let code = child
            .wait()
            .await
            .map(|s| s.code().unwrap_or(-1))
            .unwrap_or(-1);
        send_msg(&mut send, &ChannelMessage::ExitStatus(code)).await?;
    }
    send.finish().await.map_err(Into::into)
}

/// Encode + send one frame. `Ok(false)` means the client hung up gracefully
/// (H3_NO_ERROR) — the caller should stop, not treat it as an error.
pub(crate) async fn send_msg(send: &mut SendHalf, msg: &ChannelMessage) -> Result<bool> {
    match send.send_data(Bytes::from(quish_proto::encode(msg)?)).await {
        Ok(()) => Ok(true),
        Err(e) if e.is_h3_no_error() => Ok(false),
        Err(e) => Err(anyhow::anyhow!("sending frame: {e}")),
    }
}

/// Why a channel pump loop ended.
pub(crate) enum PumpEnd {
    /// Local process output fully drained (child exited). The caller should
    /// obtain the exit code and send a final `ExitStatus` frame.
    Drained,
    /// The client hung up mid-send (H3_NO_ERROR). The send half is done; the
    /// caller should NOT send `ExitStatus`, only `finish()`.
    ClientGone,
}

/// Shared PTY-shell pump. Selects client frames against merged PTY output until
/// the PTY drains (child exited) or the client hangs up. On client frame-EOF it
/// EOFs the shell's stdin (drops `in_tx`) and keeps draining output — a client
/// that stops sending input can still read the rest of the shell's output. The
/// caller supplies the resize action (portable-pty vs. rustix on an fd differ)
/// and, after this returns `Drained`, the exit code.
pub(crate) async fn pump_shell(
    send: &mut SendHalf,
    mut frames: mpsc::Receiver<ChannelMessage>,
    mut out_rx: mpsc::Receiver<Vec<u8>>,
    in_tx: mpsc::Sender<Vec<u8>>,
    mut resize: impl FnMut(u16, u16),
) -> Result<PumpEnd> {
    let mut in_tx = Some(in_tx);
    let mut frames_done = false;
    loop {
        tokio::select! {
            msg = frames.recv(), if !frames_done => match msg {
                Some(ChannelMessage::Data(d)) => {
                    if let Some(tx) = in_tx.as_ref() { let _ = tx.send(d).await; }
                }
                Some(ChannelMessage::Resize { cols, rows }) => resize(cols, rows),
                Some(_) => {} // DataErr/ExitStatus from client: ignore
                None => { frames_done = true; in_tx = None; } // EOF the shell's stdin
            },
            out = out_rx.recv() => match out {
                Some(bytes) => {
                    if !send_msg(send, &ChannelMessage::Data(bytes)).await? {
                        return Ok(PumpEnd::ClientGone);
                    }
                }
                None => return Ok(PumpEnd::Drained), // PTY drained: shell exited
            },
        }
    }
}

/// Shared one-shot-exec pump. Selects stdout / stderr / client frames until both
/// output streams drain, or the client hangs up. Client frame-EOF EOFs the
/// child's stdin (drops `in_tx`) and keeps draining. After this returns
/// `Drained`, the caller obtains the exit code (`child.wait()` in dev, a monitor
/// reap RPC in privsep).
pub(crate) async fn pump_exec(
    send: &mut SendHalf,
    mut frames: mpsc::Receiver<ChannelMessage>,
    mut out_rx: mpsc::Receiver<Vec<u8>>,
    mut err_rx: mpsc::Receiver<Vec<u8>>,
    in_tx: mpsc::Sender<Vec<u8>>,
    sig_tx: mpsc::Sender<quish_proto::Signal>,
) -> Result<PumpEnd> {
    let mut in_tx = Some(in_tx);
    let (mut out_done, mut err_done, mut frames_done) = (false, false, false);
    loop {
        tokio::select! {
            out = out_rx.recv(), if !out_done => match out {
                Some(bytes) => {
                    if !send_msg(send, &ChannelMessage::Data(bytes)).await? {
                        return Ok(PumpEnd::ClientGone);
                    }
                }
                None => out_done = true,
            },
            err = err_rx.recv(), if !err_done => match err {
                Some(bytes) => {
                    if !send_msg(send, &ChannelMessage::DataErr(bytes)).await? {
                        return Ok(PumpEnd::ClientGone);
                    }
                }
                None => err_done = true,
            },
            msg = frames.recv(), if !frames_done => match msg {
                Some(ChannelMessage::Data(d)) => {
                    if let Some(tx) = in_tx.as_ref() { let _ = tx.send(d).await; }
                }
                Some(ChannelMessage::Signal(s)) => {
                    let _ = sig_tx.send(s).await;
                }
                Some(_) => {}
                None => { frames_done = true; in_tx = None; } // EOF child stdin
            },
        }
        if out_done && err_done {
            return Ok(PumpEnd::Drained);
        }
    }
}

/// Serve a `Forward` channel: enforce the loopback-only egress policy, then
/// bridge the H3 channel to a server-side TCP connection. The channel is closed
/// WITHOUT connecting when forwarding is disabled or the destination resolves to
/// any non-loopback address — the security check runs strictly before
/// `TcpStream::connect`, and we connect only to an address already verified
/// loopback (so a DNS rebind cannot slip a non-loopback address through).
pub(crate) async fn serve_forward(
    mut send: SendHalf,
    reader: FrameReader,
    host: String,
    port: u16,
    allow_forward: bool,
) -> Result<()> {
    if !allow_forward {
        warn!(%port, "forward channel refused: forwarding disabled");
        return send.finish().await.map_err(Into::into);
    }
    // Resolve, then require EVERY returned address to be loopback.
    let addrs: Vec<std::net::SocketAddr> =
        match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(it) => it.collect(),
            Err(e) => {
                warn!(%host, %port, error = %e, "forward channel refused: resolve failed");
                return send.finish().await.map_err(Into::into);
            }
        };
    if addrs.is_empty() || !addrs.iter().all(|a| a.ip().is_loopback()) {
        warn!(%host, %port, "forward channel refused: destination not loopback-only");
        return send.finish().await.map_err(Into::into);
    }
    // Connect only to an address we have already checked is loopback.
    let target = addrs[0];
    let tcp = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            warn!(%target, error = %e, "forward channel: connect failed");
            return send.finish().await.map_err(Into::into);
        }
    };
    info!(%target, "forward channel connected");
    pump_forward(&mut send, reader, tcp).await
}

/// Symmetric byte pump for a forward channel: client channel frames ⇄ the
/// server-side TCP stream, both directions carried as `ChannelMessage::Data`
/// (per the Decision record — no stderr/resize/exit). Ends when either side EOFs.
async fn pump_forward(send: &mut SendHalf, reader: FrameReader, tcp: TcpStream) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let mut frames = spawn_frame_reader(reader);

    // Service output → mpsc (dedicated reader task, matching the pump shape used
    // by the shell/exec channels).
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let (mut frames_done, mut out_done) = (false, false);
    loop {
        tokio::select! {
            msg = frames.recv(), if !frames_done => match msg {
                // client → server bytes: write to the forwarded service.
                Some(ChannelMessage::Data(d)) => {
                    if tcp_write.write_all(&d).await.is_err() {
                        frames_done = true;
                    }
                }
                Some(_) => {} // forward channels carry only Data
                None => {
                    frames_done = true;
                    let _ = tcp_write.shutdown().await; // EOF the service's input
                }
            },
            out = out_rx.recv(), if !out_done => match out {
                // service → client bytes: frame as Data.
                Some(bytes) => {
                    if !send_msg(send, &ChannelMessage::Data(bytes)).await? {
                        break; // client hung up
                    }
                }
                None => out_done = true, // service closed its output
            },
        }
        if frames_done && out_done {
            break;
        }
    }
    up.abort();
    send.finish().await.map_err(Into::into)
}

/// Owns the recv half, spooling H3 DATA into complete frame bodies.
pub(crate) struct FrameReader {
    recv: RecvHalf,
    buf: Vec<u8>,
}

impl FrameReader {
    pub(crate) fn new(recv: RecvHalf) -> Self {
        Self {
            recv,
            buf: Vec::new(),
        }
    }

    /// Next complete frame body, or `None` at clean end of stream.
    pub(crate) async fn next_frame(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            if self.buf.len() >= LEN_PREFIX {
                let len = parse_len(self.buf[..LEN_PREFIX].try_into().unwrap())?;
                if self.buf.len() >= LEN_PREFIX + len {
                    let body = self.buf[LEN_PREFIX..LEN_PREFIX + len].to_vec();
                    self.buf.drain(..LEN_PREFIX + len);
                    return Ok(Some(body));
                }
            }
            match self.recv.recv_data().await {
                Ok(Some(mut chunk)) => {
                    self.buf
                        .extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
                }
                // Clean EOF (possibly with a trailing partial frame we ignore).
                Ok(None) => return Ok(None),
                Err(e) if e.is_h3_no_error() => return Ok(None),
                Err(e) => return Err(anyhow::anyhow!("recv frame: {e}")),
            }
        }
    }
}

/// Dedicated reader task: decode frames off the recv half into an mpsc so the
/// session loop never `select!`s a non-cancel-safe `recv_data` directly.
pub(crate) fn spawn_frame_reader(mut reader: FrameReader) -> mpsc::Receiver<ChannelMessage> {
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(async move {
        loop {
            match reader.next_frame().await {
                Ok(Some(body)) => match quish_proto::decode::<ChannelMessage>(&body) {
                    Ok(msg) => {
                        if tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "dropping malformed channel frame");
                        break;
                    }
                },
                Ok(None) => break,
                Err(e) => {
                    warn!(error = %e, "channel frame reader stopped");
                    break;
                }
            }
        }
    });
    rx
}

/// Blocking reader → mpsc: forwards 8 KiB chunks until EOF/error, stopping early
/// if the receiver is dropped. Runs on a dedicated `std::thread` (blocking I/O).
/// Shared by dev-mode PTY output and the privsep worker's session fds.
pub(crate) fn read_loop<R: std::io::Read>(mut reader: R, tx: mpsc::Sender<Vec<u8>>) {
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if tx.blocking_send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        }
    }
}

/// Blocking mpsc → writer: drains the channel until the sender is dropped (EOF)
/// or a write fails. Runs on a dedicated `std::thread`.
pub(crate) fn write_loop<W: std::io::Write>(mut writer: W, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(bytes) = rx.blocking_recv() {
        if writer.write_all(&bytes).is_err() || writer.flush().is_err() {
            break;
        }
    }
}
