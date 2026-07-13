//! quish wire protocol: shared types + frame codec. No I/O — callers own the streams.
//!
//! A quish connection is HTTP/3. Session and channel setup ride Extended CONNECT
//! (see the header/pseudo-header consts below). Once a channel stream is open, both
//! directions exchange length-prefixed postcard frames: a leading [`ChannelOpen`]
//! from the client, then [`ChannelMessage`]s each way.

use bytes::{Buf, Bytes, BytesMut};
use serde::{Serialize, de::DeserializeOwned};

/// Bumped on any incompatible wire change. Sent in the `quish-version` header.
pub const PROTOCOL_VERSION: u32 = 2;

/// ALPN for the QUIC/TLS handshake. quish speaks HTTP/3, so this is `h3`.
pub const ALPN: &[u8] = b"h3";

/// Header carrying [`PROTOCOL_VERSION`] as a decimal string.
pub const HEADER_VERSION: &str = "quish-version";

/// Whether a `quish-version` header value names a protocol version this build
/// speaks. `None` (header absent) and any unparseable/mismatched value are
/// unsupported. Kept here so server and client agree on the rule.
pub fn version_supported(header: Option<&str>) -> bool {
    matches!(header.and_then(|s| s.trim().parse::<u32>().ok()), Some(v) if v == PROTOCOL_VERSION)
}

/// Default secret path; anything else gets a generic 404 before quish logic runs.
pub const DEFAULT_PATH: &str = "/quish";

/// TLS-exporter label both sides feed to `Connection::export_keying_material` to
/// derive the 32-byte channel binding that pubkey tokens are signed over.
pub const CHANNEL_BINDING_LABEL: &[u8] = b"quish channel binding";

/// Length of the exported channel binding.
pub const CHANNEL_BINDING_LEN: usize = 32;

/// Lowercase-hex SHA-256 of a DER certificate — the host-identity fingerprint.
/// The single source of truth for the TOFU pin string: the server logs it and
/// the client pins/compares it in `known_hosts`, so both sides MUST derive it
/// here (identical bytes in, identical string out).
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    Sha256::digest(cert_der)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// HTTP header carrying credentials (`Basic ` password / `Bearer ` pubkey token).
pub const HEADER_AUTHORIZATION: &str = "authorization";

/// Hard cap on a single frame body (postcard-encoded, before the length prefix).
/// Bounds the pre-auth parser. 64 KiB comfortably fits a PTY write plus overhead.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// Width of the big-endian length prefix that precedes every frame body.
pub const LEN_PREFIX: usize = 4;

/// First frame the client sends on a freshly opened channel stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum ChannelOpen {
    /// Interactive session on a PTY of the given terminal type and size.
    Shell { term: String, cols: u16, rows: u16 },
    /// One-shot command, run under the login shell.
    Exec { command: String },
    /// Open a forwarded TCP connection to `host:port` on the server side.
    /// The server enforces its egress policy before connecting.
    Forward { host: String, port: u16 },
    /// Download a regular file from the server, read AS the authenticated user
    /// (open() happens in the setuid'd session helper, never as root/worker).
    /// The server streams the file as `Data` frames + a terminal `ExitStatus`.
    ReadFile { path: String },
    /// Upload a regular file to the server, created/written AS the authenticated
    /// user (open() happens in the setuid'd session helper, never as root/worker).
    /// The client streams the bytes as `Data` frames; the server replies with a
    /// terminal `ExitStatus` (nonzero on open/fstat/write failure). `mode` is the
    /// creation mode, applied subject to the user's umask.
    WriteFile { path: String, mode: u32 },
    /// Create a directory on the server AS the authenticated user (mkdir happens
    /// in the setuid'd session helper, never as root/worker). Single-level (the
    /// client creates parents first, top-down). `mode` is the creation mode,
    /// applied subject to the user's umask. An existing directory at `path` is
    /// success; the server replies with a terminal `ExitStatus` only.
    MkDir { path: String, mode: u32 },
}

/// A forwardable interrupt from the client's terminal (exec channels only).
/// A fixed allowlist — the server maps each to a real signal; the client can
/// never request an arbitrary signum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum Signal {
    /// Ctrl-C → SIGINT.
    Int,
    /// Ctrl-\ → SIGQUIT.
    Quit,
    /// SIGTERM (graceful terminate).
    Term,
}

/// Frames exchanged over an open channel, both directions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum ChannelMessage {
    /// stdin (client→server) or stdout (server→client) bytes.
    Data(Vec<u8>),
    /// stderr bytes (server→client, exec channels only).
    DataErr(Vec<u8>),
    /// Terminal resize (client→server, shell channels only).
    Resize { cols: u16, rows: u16 },
    /// Process exit code; last frame server→client, closes the channel.
    ExitStatus(i32),
    /// Deliver a signal to the remote process (client→server, exec only).
    Signal(Signal),
}

/// Codec errors. Framing (length prefix, cap) is the caller's job; these cover
/// only the body encode/decode.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("frame body {len} exceeds cap {MAX_FRAME_LEN}")]
    TooLarge { len: usize },
    #[error("postcard: {0}")]
    Postcard(#[from] postcard::Error),
}

/// Encode a message into a full frame: `[len: u32 big-endian][postcard body]`.
/// Errors if the body would exceed [`MAX_FRAME_LEN`].
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, CodecError> {
    let body = postcard::to_stdvec(msg)?;
    if body.len() > MAX_FRAME_LEN {
        return Err(CodecError::TooLarge { len: body.len() });
    }
    let mut out = Vec::with_capacity(LEN_PREFIX + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a frame body (the bytes *after* the length prefix) into a message.
/// The caller enforces the cap while reading the prefix; this is the fuzz target.
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, CodecError> {
    Ok(postcard::from_bytes(body)?)
}

/// Parse a 4-byte big-endian length prefix, rejecting anything over the cap.
/// Returns the body length to read next.
pub fn parse_len(prefix: [u8; LEN_PREFIX]) -> Result<usize, CodecError> {
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_FRAME_LEN {
        return Err(CodecError::TooLarge { len });
    }
    Ok(len)
}

/// Split one complete length-prefixed frame body off the front of `buf`.
///
/// Returns `Ok(Some(body))` when a full `[len][body]` frame is buffered (the
/// frame is removed from `buf`), `Ok(None)` when more bytes are needed, and
/// `Err` if the length prefix exceeds [`MAX_FRAME_LEN`]. The split is O(1) and
/// does not shift the remaining bytes; the returned `Bytes` shares the buffer's
/// allocation (no copy). Callers accumulate incoming chunks into `buf` (e.g. via
/// `bytes::BufMut::put`) and call this in a loop.
pub fn take_frame(buf: &mut BytesMut) -> Result<Option<Bytes>, CodecError> {
    if buf.len() < LEN_PREFIX {
        return Ok(None);
    }
    let len = parse_len(buf[..LEN_PREFIX].try_into().unwrap())?;
    if buf.len() < LEN_PREFIX + len {
        return Ok(None);
    }
    let mut frame = buf.split_to(LEN_PREFIX + len); // O(1); `buf` keeps the tail
    frame.advance(LEN_PREFIX); // drop the length prefix, O(1)
    Ok(Some(frame.freeze())) // -> Bytes, no copy
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn frame_roundtrips() {
        let msg = ChannelMessage::Data(b"hello pty".to_vec());
        let frame = encode(&msg).unwrap();
        let len = parse_len(frame[..LEN_PREFIX].try_into().unwrap()).unwrap();
        assert_eq!(len, frame.len() - LEN_PREFIX);
        let got: ChannelMessage = decode(&frame[LEN_PREFIX..]).unwrap();
        assert_eq!(got, msg);
    }

    #[test]
    fn cert_fingerprint_is_lowercase_hex_sha256() {
        // Known vector: SHA-256("") — locks the exact TOFU pin string both the
        // server (log) and client (known_hosts) must agree on.
        assert_eq!(
            cert_fingerprint(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn open_roundtrips() {
        let open = ChannelOpen::Shell {
            term: "xterm-256color".into(),
            cols: 80,
            rows: 24,
        };
        let got: ChannelOpen = decode(&encode(&open).unwrap()[LEN_PREFIX..]).unwrap();
        assert_eq!(got, open);
    }

    #[test]
    fn forward_open_roundtrips() {
        let open = ChannelOpen::Forward {
            host: "127.0.0.1".into(),
            port: 5432,
        };
        let got: ChannelOpen = decode(&encode(&open).unwrap()[LEN_PREFIX..]).unwrap();
        assert_eq!(got, open);
    }

    #[test]
    fn readfile_open_roundtrips() {
        let open = ChannelOpen::ReadFile {
            path: "/etc/hostname".into(),
        };
        let got: ChannelOpen = decode(&encode(&open).unwrap()[LEN_PREFIX..]).unwrap();
        assert_eq!(got, open);
    }

    #[test]
    fn writefile_open_roundtrips() {
        let open = ChannelOpen::WriteFile {
            path: "/tmp/x".into(),
            mode: 0o644,
        };
        let got: ChannelOpen = decode(&encode(&open).unwrap()[LEN_PREFIX..]).unwrap();
        assert_eq!(got, open);
    }

    #[test]
    fn mkdir_open_roundtrips() {
        let open = ChannelOpen::MkDir {
            path: "/tmp/d".into(),
            mode: 0o755,
        };
        let got: ChannelOpen = decode(&encode(&open).unwrap()[LEN_PREFIX..]).unwrap();
        assert_eq!(got, open);
    }

    #[test]
    fn signal_frame_roundtrips() {
        let msg = ChannelMessage::Signal(Signal::Int);
        let got: ChannelMessage = decode(&encode(&msg).unwrap()[LEN_PREFIX..]).unwrap();
        assert_eq!(got, msg);
    }

    #[test]
    fn oversized_body_rejected() {
        let big = ChannelMessage::Data(vec![0u8; MAX_FRAME_LEN + 1]);
        assert!(matches!(encode(&big), Err(CodecError::TooLarge { .. })));
    }

    #[test]
    fn oversized_prefix_rejected() {
        let prefix = ((MAX_FRAME_LEN + 1) as u32).to_be_bytes();
        assert!(matches!(
            parse_len(prefix),
            Err(CodecError::TooLarge { .. })
        ));
    }

    #[test]
    fn garbage_body_errs_not_panics() {
        // Fuzz-target invariant: decode never panics on arbitrary bytes.
        let _: Result<ChannelMessage, _> = decode(&[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn version_supported_accepts_current_rejects_others() {
        assert!(version_supported(Some(&PROTOCOL_VERSION.to_string())));
        // Literal "2" tracks PROTOCOL_VERSION == 2; update if the version is bumped.
        assert!(version_supported(Some("2")));
        assert!(!version_supported(None));
        assert!(!version_supported(Some("1")));
        assert!(!version_supported(Some("3")));
        assert!(!version_supported(Some("abc")));
        assert!(!version_supported(Some("")));
    }

    #[test]
    fn take_frame_returns_one_full_frame() {
        let framed = encode(&ChannelMessage::Data(vec![9, 8, 7])).unwrap();
        let mut buf = BytesMut::from(&framed[..]);
        let body = take_frame(&mut buf).unwrap().expect("one full frame");
        assert!(buf.is_empty(), "frame fully consumed, no leftover");
        assert_eq!(
            decode::<ChannelMessage>(&body).unwrap(),
            ChannelMessage::Data(vec![9, 8, 7])
        );
    }

    #[test]
    fn take_frame_needs_more_when_partial() {
        let framed = encode(&ChannelMessage::Data(vec![1, 2, 3, 4])).unwrap();
        let mut buf = BytesMut::new();
        buf.put_slice(&framed[..2]);
        assert!(take_frame(&mut buf).unwrap().is_none());
        buf.put_slice(&framed[2..framed.len() - 1]);
        assert!(take_frame(&mut buf).unwrap().is_none());
        buf.put_slice(&framed[framed.len() - 1..]);
        let body = take_frame(&mut buf).unwrap().expect("now complete");
        assert_eq!(
            decode::<ChannelMessage>(&body).unwrap(),
            ChannelMessage::Data(vec![1, 2, 3, 4])
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn take_frame_splits_two_frames_in_one_buffer() {
        let mut framed = encode(&ChannelMessage::Data(vec![1])).unwrap();
        framed.extend_from_slice(&encode(&ChannelMessage::Data(vec![2, 2])).unwrap());
        let mut buf = BytesMut::from(&framed[..]);
        let a = take_frame(&mut buf).unwrap().unwrap();
        let b = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(
            decode::<ChannelMessage>(&a).unwrap(),
            ChannelMessage::Data(vec![1])
        );
        assert_eq!(
            decode::<ChannelMessage>(&b).unwrap(),
            ChannelMessage::Data(vec![2, 2])
        );
        assert!(take_frame(&mut buf).unwrap().is_none());
    }

    #[test]
    fn take_frame_rejects_oversized_length() {
        let mut buf = BytesMut::new();
        buf.put_u32((MAX_FRAME_LEN + 1) as u32);
        assert!(take_frame(&mut buf).is_err());
    }
}
