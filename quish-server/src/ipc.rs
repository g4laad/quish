//! Monitor⇄worker IPC message types and framing.
//!
//! Two channels:
//!   * **control** — `tokio_seqpacket::UnixSeqpacket`, async, passes session fds
//!     via `SCM_RIGHTS` (received as `OwnedFd`, so no `unsafe` in our code).
//!     Carries [`Request`]/[`Response`].
//!   * **signing** — a blocking `std::os::unix::net::UnixStream`; the worker's
//!     rustls cert resolver proxies each handshake signature here so the host key
//!     never leaves the monitor. Carries [`SignRequest`]/[`SignResponse`],
//!     length-prefixed (SOCK_STREAM has no message boundaries).

use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::os::fd::{BorrowedFd, OwnedFd};

use anyhow::{Context, Result, bail};
use serde::{Serialize, de::DeserializeOwned};
use tokio_seqpacket::UnixSeqpacket;
use tokio_seqpacket::ancillary::{AncillaryMessageWriter, OwnedAncillaryMessage};
use tracing::warn;

/// Cap on a single IPC message body.
pub(crate) const IPC_CAP: usize = 64 * 1024;
/// Ancillary buffer big enough for a few fds.
const ANC_CAP: usize = 64;

/// Env var names the monitor uses to hand connection info to the re-exec'd worker.
pub const ENV_CTRL_PATH: &str = "QUISH_CTRL_PATH";
pub const ENV_SIGN_PATH: &str = "QUISH_SIGN_PATH";
pub const ENV_LISTEN: &str = "QUISH_LISTEN";
pub const ENV_PATH: &str = "QUISH_PATH";
pub const ENV_CHROOT: &str = "QUISH_CHROOT";
pub const ENV_USER: &str = "QUISH_USER";
pub const ENV_SIGN_SCHEME: &str = "QUISH_SIGN_SCHEME";
pub const ENV_MAX_AUTH_FAILS: &str = "QUISH_MAX_AUTH_FAILS";
/// Server cert chain (public), base64 DER, `\n`-separated — passed to the worker.
pub const ENV_CERT: &str = "QUISH_CERT";

/// Env vars for the `--internal-run-session` helper.
pub const ENV_SESS_UID: &str = "QUISH_SESS_UID";
pub const ENV_SESS_GID: &str = "QUISH_SESS_GID";
pub const ENV_SESS_USER: &str = "QUISH_SESS_USER";
pub const ENV_SESS_HOME: &str = "QUISH_SESS_HOME";
pub const ENV_SESS_SHELL: &str = "QUISH_SESS_SHELL";
pub const ENV_SESS_TERM: &str = "QUISH_SESS_TERM";
pub const ENV_SESS_COMMAND: &str = "QUISH_SESS_COMMAND";
/// Present (= slave pts path) only for shell channels: the helper reopens it
/// after `setsid` to acquire the controlling terminal.
pub const ENV_SESS_TTY: &str = "QUISH_SESS_TTY";

/// Read a required handoff env var (set by the monitor on the worker/session
/// re-exec), or an error naming it.
pub fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing env {key}"))
}

/// [`env`] parsed as a `u32`.
pub fn env_u32(key: &str) -> Result<u32> {
    env(key)?.parse().with_context(|| format!("bad {key}"))
}

/// Control-channel request (worker → monitor).
#[derive(Debug, Serialize, serde::Deserialize)]
pub enum Request {
    /// Verify a connection's `Authorization`. The monitor binds the resulting
    /// identity to `conn_id`; the worker only learns allow/deny.
    Authenticate {
        conn_id: u64,
        authorization: Option<String>,
        peer: String,
        channel_binding: [u8; 32],
    },
    /// Open a PTY shell for `conn_id`'s authed user (response passes the master fd).
    SpawnShell { conn_id: u64, term: String },
    /// Run a command for `conn_id`'s authed user (response passes stdin/out/err fds).
    SpawnExec { conn_id: u64, command: String },
    /// Wait for a spawned session and return its exit code.
    Reap { session_id: u64 },
    /// Connection gone: drop its identity + bookkeeping.
    Close { conn_id: u64 },
}

/// Control-channel response (monitor → worker).
#[derive(Debug, Serialize, serde::Deserialize)]
pub enum Response {
    /// Auth verdict; `true` = allowed (identity kept monitor-side).
    Verdict(bool),
    /// Session spawned; fds ride alongside via `SCM_RIGHTS`.
    Spawned { session_id: u64 },
    /// Reaped exit code.
    Exited(i32),
    /// Request could not be served.
    Failed,
    /// Ack for `Close`.
    Closed,
}

/// Signing request: sign `message` with the host key under the scheme the monitor
/// pinned at startup. The worker does not get to choose the scheme (or send one).
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct SignRequest {
    pub message: Vec<u8>,
}

/// Signing response.
#[derive(Debug, Serialize, serde::Deserialize)]
pub enum SignResponse {
    Signature(Vec<u8>),
    Failed,
}

// ---- control channel (async, fd-passing) --------------------------------

/// Send one control message, optionally passing `fds` via `SCM_RIGHTS`.
pub async fn ctrl_send<T: Serialize>(
    sock: &UnixSeqpacket,
    msg: &T,
    fds: &[BorrowedFd<'_>],
) -> Result<()> {
    let bytes = postcard::to_stdvec(msg).context("encode ipc")?;
    let iov = [IoSlice::new(&bytes)];
    let mut anc_buf = [0u8; ANC_CAP];
    let mut anc = AncillaryMessageWriter::new(&mut anc_buf);
    if !fds.is_empty() {
        anc.add_fds(fds.iter().copied())
            .map_err(|e| anyhow::anyhow!("attaching fds: {e}"))?;
    }
    sock.send_vectored_with_ancillary(&iov, &mut anc)
        .await
        .context("ctrl send")?;
    Ok(())
}

/// Outcome of one control-channel receive.
pub enum Recv<T> {
    /// A decoded message plus any passed fds.
    Msg(T, Vec<OwnedFd>),
    /// The frame could not be decoded (oversized/truncated/garbled). The caller
    /// should skip it and keep serving.
    Bad,
    /// Peer closed the channel cleanly.
    Closed,
}

/// Receive one control message plus any passed fds. A malformed frame yields
/// [`Recv::Bad`] instead of an error so a single bad request can't tear down the
/// control loop; a genuine socket error still propagates.
pub async fn ctrl_recv<T: DeserializeOwned>(sock: &UnixSeqpacket) -> Result<Recv<T>> {
    let mut buf = vec![0u8; IPC_CAP];
    let mut anc_buf = [0u8; ANC_CAP];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let (info, reader) = sock
        .recv_vectored_with_ancillary(&mut iov, &mut anc_buf)
        .await
        .context("ctrl recv")?;

    let mut fds = Vec::new();
    for m in reader.into_messages() {
        if let OwnedAncillaryMessage::FileDescriptors(f) = m {
            fds.extend(f);
        }
    }
    let n = info.bytes_read();
    if n == 0 && fds.is_empty() {
        return Ok(Recv::Closed);
    }
    match postcard::from_bytes(&buf[..n]) {
        Ok(msg) => Ok(Recv::Msg(msg, fds)),
        Err(e) => {
            // A bad request gets no session: drop any received fds (they close
            // on drop) and skip the frame rather than killing the loop.
            warn!(n, error = %e, "undecodable ipc frame; skipping");
            Ok(Recv::Bad)
        }
    }
}

// ---- signing channel (blocking, length-prefixed, no fds) ----------------

/// Write a length-prefixed postcard message to the signing stream.
pub fn sign_write<T: Serialize>(stream: &mut impl Write, msg: &T) -> Result<()> {
    let bytes = postcard::to_stdvec(msg).context("encode sign")?;
    if bytes.len() > IPC_CAP {
        bail!("sign message too large");
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

/// Read a length-prefixed postcard message from the signing stream. `Ok(None)`
/// on clean EOF.
pub fn sign_read<T: DeserializeOwned>(stream: &mut impl Read) -> Result<Option<T>> {
    let mut len = [0u8; 4];
    match stream.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("sign read len"),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n > IPC_CAP {
        bail!("sign message too large");
    }
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body).context("sign read body")?;
    Ok(Some(postcard::from_bytes(&body).context("decode sign")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ctrl_recv_decodes_valid_message() {
        let (a, b) = UnixSeqpacket::pair().unwrap();
        ctrl_send(&a, &Response::Exited(42), &[]).await.unwrap();
        match ctrl_recv::<Response>(&b).await.unwrap() {
            Recv::Msg(Response::Exited(42), fds) => assert!(fds.is_empty()),
            _ => panic!("expected Msg(Exited(42))"),
        }
    }

    #[tokio::test]
    async fn ctrl_recv_skips_undecodable_frame() {
        let (a, b) = UnixSeqpacket::pair().unwrap();
        // A lone 0x7f varint selects Response variant 127, which does not exist.
        a.send(&[0x7fu8]).await.unwrap();
        assert!(matches!(
            ctrl_recv::<Response>(&b).await.unwrap(),
            Recv::Bad
        ));
    }

    #[tokio::test]
    async fn ctrl_recv_reports_clean_close() {
        let (a, b) = UnixSeqpacket::pair().unwrap();
        drop(a);
        assert!(matches!(
            ctrl_recv::<Response>(&b).await.unwrap(),
            Recv::Closed
        ));
    }
}
