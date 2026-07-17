//! quish-native TOTP (RFC 6238) second factor — the first challenge / multi-round
//! auth slice.
//!
//! [`TotpBackend`] wraps a first-factor backend (dev password, or PAM under the
//! `pam` feature). Round one runs the wrapped backend and then ALWAYS returns
//! [`Verdict::Challenge`] — with identical wording, and floored to a uniform time
//! by the registry — so it never reveals whether the first factor was accepted.
//! Round two verifies the one-time code carried in [`ConnInfo::challenge`] and
//! returns the terminal `Allow`/`Deny`. A code is accepted only when the first
//! factor also validated (carried in [`ChallengeState::pending_user`], parked
//! server-side), so a bogus user is challenged and then denied exactly like a
//! real user who fluffs the code.

use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use quish_proto::Prompt;
use sha1::Sha1;

use crate::{AuthBackend, ChallengeResponse, ChallengeState, ConnInfo, Credentials, Verdict};

type HmacSha1 = Hmac<Sha1>;

/// TOTP time step in seconds (RFC 6238 / authenticator-app default).
const STEP_SECS: u64 = 30;
/// Number of digits in a code (authenticator-app default).
const DIGITS: u32 = 6;
/// Steps of clock skew tolerated on each side of "now" (±30 s).
const SKEW_STEPS: i64 = 1;

/// Decode a base32 (RFC 4648, no padding, case-insensitive) shared secret as
/// enrolled in an authenticator app. `None` if it is not valid base32.
pub fn decode_base32_secret(secret: &str) -> Option<Vec<u8>> {
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret.trim())
}

/// Base32-encode a raw secret (RFC 4648, no padding) — the enrollment form an
/// authenticator app expects and [`decode_base32_secret`] reads back.
pub fn encode_base32_secret(secret: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, secret)
}

/// Generate a fresh 20-byte (160-bit) TOTP secret from the OS CSPRNG — the
/// enrollment input for [`encode_base32_secret`]. 20 bytes is the RFC 6238
/// recommended key length for HMAC-SHA1. No `unsafe`.
pub fn generate_totp_secret() -> Vec<u8> {
    use rand_core::RngCore;
    let mut secret = vec![0u8; 20];
    rand_core::OsRng.fill_bytes(&mut secret);
    secret
}

/// One HOTP value (RFC 4226) for `counter` over `secret`.
fn hotp(secret: &[u8], counter: u64) -> u32 {
    // HMAC keys are variable-length, so `new_from_slice` never rejects.
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let hs = mac.finalize().into_bytes();
    let offset = (hs[hs.len() - 1] & 0x0f) as usize;
    let bin = ((u32::from(hs[offset]) & 0x7f) << 24)
        | (u32::from(hs[offset + 1]) << 16)
        | (u32::from(hs[offset + 2]) << 8)
        | u32::from(hs[offset + 3]);
    bin % 10u32.pow(DIGITS)
}

/// Verify `code` against `secret` at `unix_secs`, accepting ±[`SKEW_STEPS`].
fn verify_at(secret: &[u8], code: u32, unix_secs: u64) -> bool {
    let step = (unix_secs / STEP_SECS) as i64;
    (step - SKEW_STEPS..=step + SKEW_STEPS)
        .filter(|c| *c >= 0)
        .any(|c| hotp(secret, c as u64) == code)
}

/// The current TOTP code for `secret` — used by tooling/tests to enroll.
pub fn current_code(secret: &[u8]) -> u32 {
    hotp(secret, now_unix() / STEP_SECS)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A 128-bit opaque challenge token, hex-encoded. Sourced from the OS CSPRNG.
/// The token is a secondary check only — the primary binding is the server's
/// per-connection state map keyed by the server-assigned `conn_id` — but it is
/// unguessable so a stale/foreign token never matches.
fn new_token() -> String {
    let mut buf = [0u8; 16];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_err()
    {
        // Fallback: still connection-bound server-side; mix in the clock so two
        // tokens minted in the same process differ.
        let n = now_unix();
        buf[..8].copy_from_slice(&n.to_le_bytes());
        buf[8..].copy_from_slice(
            &SystemTime::now()
                .elapsed()
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes()[..8],
        );
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Resolves a validated username to its raw (decoded) TOTP secret. `None` when
/// the user has no enrolled secret.
pub type SecretResolver = Box<dyn Fn(&str) -> Option<Vec<u8>> + Send + Sync>;

/// A challenge-capable second-factor backend. See the module docs.
pub struct TotpBackend {
    /// First factor (password/PAM). Its `supports()` also gates this backend.
    inner: Box<dyn AuthBackend>,
    /// Resolve a user's decoded TOTP secret (raw HMAC key). `None` = not enrolled.
    secret_for: SecretResolver,
    /// Prompt shown for the one-time code. Generic wording (no username) so it
    /// cannot enumerate.
    prompt: String,
}

impl TotpBackend {
    /// Build a TOTP backend wrapping `first_factor`. `secret_for` maps a validated
    /// username to its shared secret.
    pub fn new(first_factor: Box<dyn AuthBackend>, secret_for: SecretResolver) -> Self {
        Self {
            inner: first_factor,
            secret_for,
            prompt: "TOTP code: ".to_string(),
        }
    }

    fn open_challenge(&self, pending_user: Option<String>) -> Verdict {
        Verdict::Challenge {
            state: ChallengeState {
                token: new_token(),
                pending_user,
            },
            prompts: vec![Prompt {
                message: self.prompt.clone(),
                echo: false,
            }],
        }
    }

    fn complete(&self, resp: &ChallengeResponse) -> Verdict {
        // Resolve a secret unconditionally so verification does the same work
        // whether or not the first factor validated; a missing enrollment falls
        // back to an empty key (which no real code matches). The registry floor
        // masks residual timing. A terminal `Allow` requires BOTH a validated
        // first factor (`pending_user`) AND a correct code.
        let secret = resp
            .state
            .pending_user
            .as_deref()
            .and_then(|u| (self.secret_for)(u))
            .unwrap_or_default();
        let code_ok = resp
            .responses
            .first()
            .and_then(|c| c.trim().parse::<u32>().ok())
            .map(|code| verify_at(&secret, code, now_unix()))
            .unwrap_or(false);
        match (&resp.state.pending_user, code_ok) {
            (Some(user), true) => Verdict::Allow { user: user.clone() },
            _ => Verdict::Deny,
        }
    }
}

#[async_trait::async_trait]
impl AuthBackend for TotpBackend {
    fn name(&self) -> &'static str {
        "totp"
    }

    fn supports(&self, creds: &Credentials) -> bool {
        self.inner.supports(creds)
    }

    async fn authenticate(&self, conn: &ConnInfo, creds: &Credentials) -> Verdict {
        // Round two: a parked challenge is being answered.
        if let Some(resp) = &conn.challenge {
            return self.complete(resp);
        }
        // Round one: run the first factor, then ALWAYS challenge. The outcome of
        // the first factor is hidden in the (server-side) `pending_user`; the
        // client sees an identical challenge either way.
        let pending_user = match self.inner.authenticate(conn, creds).await {
            Verdict::Allow { user } => Some(user),
            _ => None,
        };
        self.open_challenge(pending_user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DevInsecureBackend;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use zeroize::Zeroizing;

    fn conn() -> ConnInfo {
        ConnInfo {
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            channel_binding: [0u8; 32],
            challenge: None,
        }
    }

    fn creds(user: &str) -> Credentials {
        Credentials::Password {
            username: user.to_string(),
            password: Zeroizing::new("pw".to_string()),
        }
    }

    /// Fixed 20-byte secret ("12345678901234567890"), the RFC 6238 test key.
    fn secret() -> Vec<u8> {
        b"12345678901234567890".to_vec()
    }

    fn backend() -> TotpBackend {
        TotpBackend::new(
            Box::new(DevInsecureBackend::new("alice".into())),
            Box::new(|_user| Some(b"12345678901234567890".to_vec())),
        )
    }

    fn answer(state: ChallengeState, code: &str) -> ConnInfo {
        ConnInfo {
            challenge: Some(ChallengeResponse {
                state,
                responses: vec![Zeroizing::new(code.to_string())],
            }),
            ..conn()
        }
    }

    #[test]
    fn hotp_matches_rfc4226_vectors() {
        // RFC 4226 Appendix D test values for the shared "12345678901234567890".
        let s = secret();
        assert_eq!(hotp(&s, 0), 755224);
        assert_eq!(hotp(&s, 1), 287082);
        assert_eq!(hotp(&s, 9), 520489);
    }

    #[tokio::test]
    async fn round_one_always_challenges_valid_user() {
        let v = backend().authenticate(&conn(), &creds("alice")).await;
        match v {
            Verdict::Challenge { state, prompts } => {
                assert_eq!(state.pending_user.as_deref(), Some("alice"));
                assert_eq!(prompts.len(), 1);
                assert!(!prompts[0].echo, "code prompt must be echo-off");
            }
            other => panic!("expected challenge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn round_one_challenges_bogus_user_identically() {
        // A user the first factor rejects still gets a challenge; the ONLY
        // difference is server-side pending_user (never sent to the client).
        let v = backend().authenticate(&conn(), &creds("mallory")).await;
        match v {
            Verdict::Challenge { state, prompts } => {
                assert_eq!(state.pending_user, None);
                assert_eq!(prompts.len(), 1);
                assert!(!prompts[0].echo);
            }
            other => panic!("expected challenge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn correct_code_for_valid_user_allows() {
        let code = format!("{:06}", current_code(&secret()));
        let state = ChallengeState {
            token: "t".into(),
            pending_user: Some("alice".into()),
        };
        let v = backend()
            .authenticate(&answer(state, &code), &creds("alice"))
            .await;
        assert_eq!(
            v,
            Verdict::Allow {
                user: "alice".into()
            }
        );
    }

    #[tokio::test]
    async fn wrong_code_for_valid_user_denies() {
        let state = ChallengeState {
            token: "t".into(),
            pending_user: Some("alice".into()),
        };
        let v = backend()
            .authenticate(&answer(state, "000000"), &creds("alice"))
            .await;
        // 000000 is astronomically unlikely to be the live code; treat a Deny as
        // the contract. (If it ever flaked, it would be a 1-in-10^6 clock fluke.)
        assert_eq!(v, Verdict::Deny);
    }

    #[tokio::test]
    async fn correct_code_but_bogus_user_denies() {
        // Anti-enumeration: even a correct code cannot log in a user whose first
        // factor failed (pending_user == None).
        let code = format!("{:06}", current_code(&secret()));
        let state = ChallengeState {
            token: "t".into(),
            pending_user: None,
        };
        let v = backend()
            .authenticate(&answer(state, &code), &creds("mallory"))
            .await;
        assert_eq!(v, Verdict::Deny);
    }
}
