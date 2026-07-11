//! Client channel pump: forward local stdin ⇄ remote channel frames, with raw
//! terminal mode + resize for interactive shells.
//!
//! Cancel-safety: neither the H3 `recv_data` nor `std::io::stdin` reads are
//! `select!`ed directly — each has a dedicated reader feeding an mpsc the pump
//! selects over (both mpsc `recv` and `Signal::recv` are cancel-safe).

use std::io::Read;

use anyhow::{Context, Result};
use bytes::{Buf, Bytes};
use quish_proto::{ChannelMessage, ChannelOpen, LEN_PREFIX, parse_len};
use rustix::termios::{OptionalActions, Termios, tcgetattr, tcgetwinsize, tcsetattr};
use tokio::io::{AsyncWriteExt, stderr, stdout};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

type SendHalf = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type RecvHalf = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

/// Current terminal size, or `(80, 24)` if stdin isn't a tty.
pub fn winsize() -> (u16, u16) {
    match tcgetwinsize(rustix::stdio::stdin()) {
        Ok(ws) if ws.ws_col > 0 && ws.ws_row > 0 => (ws.ws_col, ws.ws_row),
        _ => (80, 24),
    }
}

/// RAII raw-mode guard for stdin; restores the original settings on drop. A
/// no-op when stdin isn't a tty (e.g. piped input).
pub struct RawMode {
    original: Option<Termios>,
}

impl RawMode {
    pub fn enable() -> Self {
        let fd = rustix::stdio::stdin();
        let Ok(original) = tcgetattr(fd) else {
            return Self { original: None };
        };
        let mut raw = original.clone();
        raw.make_raw();
        if tcsetattr(fd, OptionalActions::Now, &raw).is_err() {
            return Self { original: None };
        }
        Self {
            original: Some(original),
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if let Some(original) = &self.original {
            let _ = tcsetattr(rustix::stdio::stdin(), OptionalActions::Now, original);
        }
    }
}

/// Send the opening frame, then pump the channel until the server sends an
/// `ExitStatus`. Returns the remote process exit code. `interactive` enables raw
/// mode + SIGWINCH resize.
pub async fn run_channel(
    send: SendHalf,
    recv: RecvHalf,
    open: ChannelOpen,
    interactive: bool,
) -> Result<i32> {
    let _raw = interactive.then(RawMode::enable);

    let mut send = Some(send);
    send_frame_open(&mut send, &open).await?;

    let mut frames = spawn_frame_reader(recv);
    let mut stdin_rx = spawn_stdin();
    let mut winch = if interactive {
        Some(signal(SignalKind::window_change()).context("SIGWINCH handler")?)
    } else {
        None
    };
    let mut sigint = (!interactive)
        .then(|| signal(SignalKind::interrupt()).context("SIGINT handler"))
        .transpose()?;
    let mut sigquit = (!interactive)
        .then(|| signal(SignalKind::quit()).context("SIGQUIT handler"))
        .transpose()?;
    let mut out = stdout();
    let mut err = stderr();
    let mut stdin_done = false;
    let exit;

    loop {
        tokio::select! {
            // remote → local
            msg = frames.recv() => match msg {
                Some(ChannelMessage::Data(d)) => { out.write_all(&d).await?; out.flush().await?; }
                Some(ChannelMessage::DataErr(d)) => { err.write_all(&d).await?; err.flush().await?; }
                Some(ChannelMessage::ExitStatus(code)) => { exit = code; break; }
                Some(ChannelMessage::Resize { .. }) => {} // server never sends these
                Some(ChannelMessage::Signal(_)) => {} // client never receives signals
                None => { exit = -1; break; } // stream closed without an exit status
            },
            // local stdin → remote
            chunk = stdin_rx.recv(), if !stdin_done => match chunk {
                Some(bytes) => send_frame(&mut send, &ChannelMessage::Data(bytes)).await?,
                None => {
                    stdin_done = true;
                    // Half-close our send side: FIN signals stdin EOF to the remote
                    // process while the recv half keeps delivering its output.
                    if let Some(mut s) = send.take() {
                        let _ = s.finish().await;
                    }
                }
            },
            // terminal resize (interactive only)
            _ = recv_winch(&mut winch) => {
                let (cols, rows) = winsize();
                send_frame(&mut send, &ChannelMessage::Resize { cols, rows }).await?;
            },
            // forward interrupts on exec (non-interactive) channels
            _ = recv_sig(&mut sigint) => {
                send_frame(&mut send, &ChannelMessage::Signal(quish_proto::Signal::Int)).await?;
            }
            _ = recv_sig(&mut sigquit) => {
                send_frame(&mut send, &ChannelMessage::Signal(quish_proto::Signal::Quit)).await?;
            }
        }
    }

    if let Some(mut s) = send.take() {
        let _ = s.finish().await;
    }
    Ok(exit)
}

async fn recv_winch(winch: &mut Option<tokio::signal::unix::Signal>) {
    match winch {
        Some(sig) => {
            sig.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

async fn recv_sig(sig: &mut Option<tokio::signal::unix::Signal>) {
    match sig {
        Some(s) => {
            s.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

async fn send_frame_open(send: &mut Option<SendHalf>, open: &ChannelOpen) -> Result<()> {
    if let Some(s) = send.as_mut() {
        s.send_data(Bytes::from(quish_proto::encode(open)?))
            .await
            .context("sending ChannelOpen")?;
    }
    Ok(())
}

async fn send_frame(send: &mut Option<SendHalf>, msg: &ChannelMessage) -> Result<()> {
    if let Some(s) = send.as_mut() {
        s.send_data(Bytes::from(quish_proto::encode(msg)?))
            .await
            .context("sending frame")?;
    }
    Ok(())
}

/// Blocking stdin reader → mpsc (dropping the sender on EOF closes the channel).
fn spawn_stdin() -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel(64);
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 8192];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

/// Dedicated reader task: decode frames off the recv half into an mpsc so the
/// pump never `select!`s a non-cancel-safe `recv_data` directly.
fn spawn_frame_reader(mut recv: RecvHalf) -> mpsc::Receiver<ChannelMessage> {
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(async move {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            // Emit any complete frames already buffered.
            while buf.len() >= LEN_PREFIX {
                let Ok(len) = parse_len(buf[..LEN_PREFIX].try_into().unwrap()) else {
                    return;
                };
                if buf.len() < LEN_PREFIX + len {
                    break;
                }
                let body = buf[LEN_PREFIX..LEN_PREFIX + len].to_vec();
                buf.drain(..LEN_PREFIX + len);
                match quish_proto::decode::<ChannelMessage>(&body) {
                    Ok(msg) => {
                        if tx.send(msg).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
            match recv.recv_data().await {
                Ok(Some(mut chunk)) => {
                    buf.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref())
                }
                _ => return, // EOF or error: end of channel
            }
        }
    });
    rx
}
