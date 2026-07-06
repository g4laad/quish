//! quish wire protocol: shared types + frame codec. No I/O — callers own the streams.
//!
//! A quish connection is HTTP/3. Session and channel setup ride Extended CONNECT
//! (see the header/pseudo-header consts below). Once a channel stream is open, both
//! directions exchange length-prefixed postcard frames: a leading [`ChannelOpen`]
//! from the client, then [`ChannelMessage`]s each way.

use serde::{Serialize, de::DeserializeOwned};

/// Bumped on any incompatible wire change. Sent in the `quish-version` header.
pub const PROTOCOL_VERSION: u32 = 1;

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

#[cfg(test)]
mod tests {
    use super::*;

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
        // Literal "1" tracks PROTOCOL_VERSION == 1; update if the version is bumped.
        assert!(version_supported(Some("1")));
        assert!(!version_supported(None));
        assert!(!version_supported(Some("2")));
        assert!(!version_supported(Some("abc")));
        assert!(!version_supported(Some("")));
    }
}
