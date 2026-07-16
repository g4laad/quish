//! Public-key auth: signed, channel-bound tokens verified against a per-server
//! `authorized_keys` file (OpenSSH line format, ed25519 only).
//!
//! The token is single-round-trip and replay-proof: its signature covers the
//! TLS channel binding (so it can't be replayed on another connection) plus a
//! timestamp (belt-and-braces against a captured binding). See [`Token`].

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt; // custom_flags -> O_NOFOLLOW
use std::{path::PathBuf, time::SystemTime};

use base64::prelude::{BASE64_STANDARD, Engine};
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};

use crate::{AuthBackend, ConnInfo, Credentials, Verdict};

/// Domain-separation tag prepended to every signature payload.
const TOKEN_DOMAIN: &[u8] = b"quish-pubkey-auth-v1";

/// Accepted clock skew between client and server timestamps, each direction.
const TIMESTAMP_WINDOW_SECS: u64 = 600;

/// Hard cap on how much of an `authorized_keys` file we read. A single ed25519
/// line is ~80 bytes; this comfortably holds hundreds of keys while bounding a
/// hostile file (device/FIFO/huge file) the target user may have planted.
const MAX_AUTHORIZED_KEYS_BYTES: u64 = 64 * 1024;

/// Read up to the cap from `path`, refusing to follow a final-component symlink
/// and refusing anything that isn't a regular file. Returns `None` on any
/// problem (missing, symlink, non-regular, unreadable) — caller treats that as
/// "not authorized", identical to today.
fn read_authorized_keys(path: &std::path::Path) -> Option<String> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let meta = f.metadata().ok()?;
    if !meta.file_type().is_file() {
        return None; // reject FIFO/device/dir/socket
    }
    let mut buf = Vec::new();
    f.by_ref()
        .take(MAX_AUTHORIZED_KEYS_BYTES)
        .read_to_end(&mut buf)
        .ok()?;
    String::from_utf8(buf).ok()
}

/// Does an `authorized_keys` line list `pubkey`? Blank/comment lines never match.
fn key_line_matches(line: &str, pubkey: &[u8; 32]) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    ssh_key::PublicKey::from_openssh(line)
        .ok()
        .and_then(|pk| pk.key_data().ed25519().map(|k| k.as_ref() == pubkey))
        .unwrap_or(false)
}

/// A parsed pubkey auth token (Bearer credential), postcard+base64 on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub username: String,
    /// Raw ed25519 public key (32 bytes).
    pub pubkey: [u8; 32],
    /// Client's unix timestamp (seconds) when the token was minted.
    pub timestamp: u64,
    /// ed25519 signature over [`signing_payload`] (64 bytes; `Vec` because serde
    /// derives only cover arrays up to 32).
    pub signature: Vec<u8>,
}

/// Bytes signed by the client and re-derived by the server. Layout:
/// `DOMAIN || channel_binding(32) || username || timestamp_le(8)`.
fn signing_payload(binding: &[u8; 32], username: &str, timestamp: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(TOKEN_DOMAIN.len() + 32 + username.len() + 8);
    p.extend_from_slice(TOKEN_DOMAIN);
    p.extend_from_slice(binding);
    p.extend_from_slice(username.as_bytes());
    p.extend_from_slice(&timestamp.to_le_bytes());
    p
}

/// Sign a token with an in-memory ed25519 key. Returns the base64 blob that goes
/// in `Authorization: Bearer <...>`.
pub fn sign_token(
    signing: &ed25519_dalek::SigningKey,
    username: &str,
    binding: &[u8; 32],
    timestamp: u64,
) -> String {
    let sig = signing.sign(&signing_payload(binding, username, timestamp));
    let token = Token {
        username: username.to_string(),
        pubkey: signing.verifying_key().to_bytes(),
        timestamp,
        signature: sig.to_bytes().to_vec(),
    };
    BASE64_STANDARD.encode(postcard::to_stdvec(&token).expect("token encodes"))
}

/// Client convenience: load an OpenSSH ed25519 private key and mint a token bound
/// to `binding` for `username`, timestamped now.
pub fn build_token(
    openssh_private_key: &[u8],
    username: &str,
    binding: &[u8; 32],
) -> anyhow::Result<String> {
    let key = ssh_key::PrivateKey::from_openssh(openssh_private_key)
        .map_err(|e| anyhow::anyhow!("parsing private key: {e}"))?;
    let kp = key
        .key_data()
        .ed25519()
        .ok_or_else(|| anyhow::anyhow!("identity is not an ed25519 key"))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&kp.private.to_bytes());
    Ok(sign_token(&signing, username, binding, now_secs()))
}

/// Decode a Bearer credential back into a [`Token`]. `None` on any malformation —
/// the registry maps that to the same generic failure as everything else.
pub(crate) fn parse_token(b64: &str) -> Option<Token> {
    let bytes = BASE64_STANDARD.decode(b64.trim()).ok()?;
    postcard::from_bytes(&bytes).ok()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolves a username to its `authorized_keys` path. Lets the monitor point at
/// the *target* user's home (`~alice/.config/quish/authorized_keys`) while dev
/// mode uses one fixed file.
pub type KeysResolver = Box<dyn Fn(&str) -> Option<PathBuf> + Send + Sync>;

/// Verifies signed tokens against a per-user `authorized_keys` file.
pub struct PubkeyBackend {
    resolver: KeysResolver,
}

impl std::fmt::Debug for PubkeyBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PubkeyBackend").finish()
    }
}

impl PubkeyBackend {
    /// One fixed `authorized_keys` file for every user (dev / single-home setups).
    /// Deliberately separate from `~/.ssh/authorized_keys`.
    pub fn new(authorized_keys: PathBuf) -> Self {
        Self::with_resolver(Box::new(move |_| Some(authorized_keys.clone())))
    }

    /// Resolve the `authorized_keys` path per target username.
    pub fn with_resolver(resolver: KeysResolver) -> Self {
        Self { resolver }
    }
}

#[async_trait::async_trait]
impl AuthBackend for PubkeyBackend {
    fn name(&self) -> &'static str {
        "pubkey"
    }

    fn supports(&self, creds: &Credentials) -> bool {
        matches!(creds, Credentials::SignedToken(_))
    }

    async fn authenticate(&self, conn: &ConnInfo, creds: &Credentials) -> Verdict {
        let Credentials::SignedToken(tok) = creds else {
            return Verdict::Deny;
        };

        // Timestamp window (guards a stolen-then-replayed binding).
        let now = now_secs();
        if tok.timestamp.abs_diff(now) > TIMESTAMP_WINDOW_SECS {
            return Verdict::Deny;
        }
        // Key must be explicitly authorized for the claimed user. The file read is
        // bounded and de-symlinked, and runs off this serial control task so a
        // hostile target file can't stall or freeze the monitor's reactor.
        let authorized = {
            let path = (self.resolver)(&tok.username);
            let pubkey = tok.pubkey;
            tokio::task::spawn_blocking(move || match path {
                Some(p) => match read_authorized_keys(&p) {
                    Some(contents) => contents.lines().any(|line| key_line_matches(line, &pubkey)),
                    None => false,
                },
                None => false,
            })
            .await
            .unwrap_or(false)
        };
        if !authorized {
            return Verdict::Deny;
        }
        // Signature must cover this connection's binding.
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&tok.pubkey) else {
            return Verdict::Deny;
        };
        let Ok(sig_bytes) = <[u8; 64]>::try_from(tok.signature.as_slice()) else {
            return Verdict::Deny;
        };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let payload = signing_payload(&conn.channel_binding, &tok.username, tok.timestamp);
        match vk.verify(&payload, &sig) {
            Ok(()) => Verdict::Allow {
                user: tok.username.clone(),
            },
            Err(_) => Verdict::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn conn(binding: [u8; 32]) -> ConnInfo {
        ConnInfo {
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            channel_binding: binding,
            challenge: None,
        }
    }

    fn authorized_keys_with(pubkey: [u8; 32]) -> PathBuf {
        use ssh_key::public::{Ed25519PublicKey, KeyData};
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let ssh_pub = ssh_key::PublicKey::new(KeyData::Ed25519(Ed25519PublicKey(pubkey)), "test");
        // Unique per call: parallel tests must not clobber each other's file.
        let dir = std::env::temp_dir().join(format!(
            "quish-ak-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("authorized_keys");
        std::fs::write(&path, ssh_pub.to_openssh().unwrap()).unwrap();
        path
    }

    #[tokio::test]
    async fn valid_token_is_allowed() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        let backend = PubkeyBackend::new(authorized_keys_with(pubkey));
        let binding = [3u8; 32];

        let b64 = sign_token(&signing, "alice", &binding, now_secs());
        let creds = Credentials::SignedToken(parse_token(&b64).unwrap());
        assert!(matches!(
            backend.authenticate(&conn(binding), &creds).await,
            Verdict::Allow { user } if user == "alice"
        ));
    }

    #[tokio::test]
    async fn wrong_binding_is_denied() {
        // A token minted for one connection must not verify on another (replay).
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        let backend = PubkeyBackend::new(authorized_keys_with(pubkey));

        let b64 = sign_token(&signing, "bob", &[1u8; 32], now_secs());
        let creds = Credentials::SignedToken(parse_token(&b64).unwrap());
        assert!(matches!(
            backend.authenticate(&conn([2u8; 32]), &creds).await,
            Verdict::Deny
        ));
    }

    #[tokio::test]
    async fn unauthorized_key_is_denied() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        // authorized_keys lists a *different* key.
        let other = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
        let backend = PubkeyBackend::new(authorized_keys_with(other.verifying_key().to_bytes()));
        let binding = [4u8; 32];

        let b64 = sign_token(&signing, "eve", &binding, now_secs());
        let creds = Credentials::SignedToken(parse_token(&b64).unwrap());
        assert!(matches!(
            backend.authenticate(&conn(binding), &creds).await,
            Verdict::Deny
        ));
    }

    // An OpenSSH ed25519 private key + its authorized_keys line. Verifies the
    // `build_token` path (ssh-key parses the private key without its dalek-backed
    // `ed25519` feature; we sign with ed25519-dalek directly).
    const TEST_OPENSSH_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACCICKPLeQiyQYZ/bpQyvnn5XIXQiUXY9nNnD5GQWsQLrQAAAJBJxtGBScbR\n\
gQAAAAtzc2gtZWQyNTUxOQAAACCICKPLeQiyQYZ/bpQyvnn5XIXQiUXY9nNnD5GQWsQLrQ\n\
AAAEBb/hbmL0QEfMX72P8ScsZvhOKZZ4a8yZ9GWUC7sgS8NIgIo8t5CLJBhn9ulDK+eflc\n\
hdCJRdj2c2cPkZBaxAutAAAAB2ZpeHR1cmUBAgMEBQY=\n\
-----END OPENSSH PRIVATE KEY-----\n";
    const TEST_OPENSSH_PUB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIgIo8t5CLJBhn9ulDK+eflchdCJRdj2c2cPkZBaxAut fixture";

    #[tokio::test]
    async fn openssh_private_key_builds_a_valid_token() {
        let dir = std::env::temp_dir().join(format!("quish-bt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("authorized_keys");
        std::fs::write(&path, TEST_OPENSSH_PUB).unwrap();
        let backend = PubkeyBackend::new(path);
        let binding = [11u8; 32];

        let b64 = build_token(TEST_OPENSSH_KEY.as_bytes(), "dave", &binding).unwrap();
        let creds = Credentials::SignedToken(parse_token(&b64).unwrap());
        assert!(matches!(
            backend.authenticate(&conn(binding), &creds).await,
            Verdict::Allow { user } if user == "dave"
        ));
    }

    #[tokio::test]
    async fn stale_timestamp_is_denied() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        let backend = PubkeyBackend::new(authorized_keys_with(pubkey));
        let binding = [7u8; 32];

        let old = now_secs() - TIMESTAMP_WINDOW_SECS - 60;
        let b64 = sign_token(&signing, "carol", &binding, old);
        let creds = Credentials::SignedToken(parse_token(&b64).unwrap());
        assert!(matches!(
            backend.authenticate(&conn(binding), &creds).await,
            Verdict::Deny
        ));
    }

    // Write `content` to a fresh unique `authorized_keys` file and return its path.
    fn keys_file_with(content: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "quish-kf-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("authorized_keys");
        std::fs::write(&path, content).unwrap();
        path
    }

    fn openssh_line(pubkey: [u8; 32]) -> String {
        use ssh_key::public::{Ed25519PublicKey, KeyData};
        ssh_key::PublicKey::new(KeyData::Ed25519(Ed25519PublicKey(pubkey)), "test")
            .to_openssh()
            .unwrap()
    }

    #[tokio::test]
    async fn symlinked_authorized_keys_is_rejected() {
        // A valid key lives in `real_keys`; `authorized_keys` is a symlink to it.
        // O_NOFOLLOW must refuse to follow the final component → DENY, even though
        // the underlying key would otherwise authorize.
        let signing = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        let real = keys_file_with(&openssh_line(pubkey));
        let link = real.with_file_name("symlinked_keys");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let backend = PubkeyBackend::new(link);
        let binding = [21u8; 32];
        let b64 = sign_token(&signing, "frank", &binding, now_secs());
        let creds = Credentials::SignedToken(parse_token(&b64).unwrap());
        assert!(matches!(
            backend.authenticate(&conn(binding), &creds).await,
            Verdict::Deny
        ));

        // Sanity: the very same key in a real (non-symlink) file authorizes, so the
        // DENY above is due to O_NOFOLLOW, not a malformed/mismatched key.
        let backend_real = PubkeyBackend::new(real);
        assert!(matches!(
            backend_real.authenticate(&conn(binding), &creds).await,
            Verdict::Allow { user } if user == "frank"
        ));
    }

    #[tokio::test]
    async fn oversized_authorized_keys_is_bounded() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        let key_line = openssh_line(pubkey);
        let binding = [22u8; 32];
        let b64 = sign_token(&signing, "grace", &binding, now_secs());
        let creds = Credentials::SignedToken(parse_token(&b64).unwrap());

        // Pad past the cap with comment lines, then place the real key BEYOND it.
        // The bounded read stops before the key, so it is never seen → DENY.
        let mut big = String::new();
        while (big.len() as u64) <= MAX_AUTHORIZED_KEYS_BYTES {
            big.push_str("# padding padding padding padding padding padding\n");
        }
        big.push_str(&key_line);
        big.push('\n');
        let backend_big = PubkeyBackend::new(keys_file_with(&big));
        assert!(matches!(
            backend_big.authenticate(&conn(binding), &creds).await,
            Verdict::Deny
        ));

        // A small file with the same key (within the cap) still authorizes.
        let backend_small = PubkeyBackend::new(keys_file_with(&key_line));
        assert!(matches!(
            backend_small.authenticate(&conn(binding), &creds).await,
            Verdict::Allow { user } if user == "grace"
        ));
    }
}
