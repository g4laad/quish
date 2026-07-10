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
use tokio::sync::mpsc;
use tracing::{info, warn};

pub(crate) type FullStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
pub(crate) type SendHalf = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
pub(crate) type RecvHalf = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;

/// Read the opening frame and dispatch to the requested channel type (dev mode:
/// spawns the process locally via portable-pty).
pub async fn serve(stream: FullStream) -> Result<()> {
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
    }
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
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
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

    let master = pair.master; // kept alive for resize
    let mut frames = spawn_frame_reader(reader);
    let mut in_tx = Some(in_tx);
    let mut frames_done = false;

    loop {
        tokio::select! {
            // client → shell stdin / resize
            msg = frames.recv(), if !frames_done => match msg {
                Some(ChannelMessage::Data(d)) => {
                    if let Some(tx) = in_tx.as_ref() {
                        let _ = tx.send(d).await;
                    }
                }
                Some(ChannelMessage::Resize { cols, rows }) => {
                    let _ = master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
                }
                Some(_) => {} // DataErr/ExitStatus from client: ignore
                None => {
                    frames_done = true;
                    in_tx = None; // EOF the shell's stdin
                }
            },
            // shell output → client. None = PTY fully drained (child gone): finish.
            out = out_rx.recv() => match out {
                Some(bytes) => {
                    if !send_msg(&mut send, &ChannelMessage::Data(bytes)).await? {
                        return send.finish().await.map_err(Into::into);
                    }
                }
                None => break,
            },
        }
    }

    let code = match exit_rx.try_recv() {
        Ok(c) => c,
        Err(_) => (&mut exit_rx).await.unwrap_or(-1),
    };
    send_msg(&mut send, &ChannelMessage::ExitStatus(code)).await?;
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
    let mut stdin = Some(child.stdin.take().expect("piped stdin"));
    let mut frames = spawn_frame_reader(reader);

    let mut out_buf = [0u8; 8192];
    let mut err_buf = [0u8; 8192];
    let (mut out_done, mut err_done, mut frames_done) = (false, false, false);
    let mut exit_code: Option<i32> = None;

    loop {
        tokio::select! {
            r = stdout.read(&mut out_buf), if !out_done => {
                match r.context("reading stdout")? {
                    0 => out_done = true,
                    n => if !send_msg(&mut send, &ChannelMessage::Data(out_buf[..n].to_vec())).await? {
                        return send.finish().await.map_err(Into::into);
                    },
                }
            },
            r = stderr.read(&mut err_buf), if !err_done => {
                match r.context("reading stderr")? {
                    0 => err_done = true,
                    n => if !send_msg(&mut send, &ChannelMessage::DataErr(err_buf[..n].to_vec())).await? {
                        return send.finish().await.map_err(Into::into);
                    },
                }
            },
            msg = frames.recv(), if !frames_done => match msg {
                Some(ChannelMessage::Data(d)) => {
                    if let Some(si) = stdin.as_mut() {
                        let _ = si.write_all(&d).await;
                        let _ = si.flush().await;
                    }
                }
                Some(_) => {}
                None => { frames_done = true; stdin = None; } // EOF child stdin
            },
            status = child.wait(), if exit_code.is_none() => {
                exit_code = Some(status.context("waiting on child")?.code().unwrap_or(-1));
            },
        }
        if out_done && err_done && exit_code.is_some() {
            break;
        }
    }

    send_msg(
        &mut send,
        &ChannelMessage::ExitStatus(exit_code.unwrap_or(-1)),
    )
    .await?;
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
