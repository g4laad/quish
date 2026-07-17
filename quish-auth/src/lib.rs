//! quish authentication: the `AuthBackend` plugin trait, credential types, and
//! the registry that owns the anti-enumeration contract.
//!
//! Adding an auth method = a new module implementing [`AuthBackend`] + one line
//! wiring it into the server's registry. Backends never shape failures: the
//! [`Registry`] parses the `Authorization` header once, dispatches to the first
//! backend that `supports()` the credential, and forces every failure through an
//! identical, constant-time-floored `Deny` so nothing can be enumerated.

use std::{net::SocketAddr, time::Duration};

use base64::prelude::{BASE64_STANDARD, Engine};
use tokio::time::Instant;
use zeroize::Zeroizing;

pub mod pubkey;
pub mod totp;

#[cfg(feature = "pam")]
pub mod pam;

/// Per-connection facts a backend may need. `channel_binding` is the 32-byte
/// TLS exporter output (see `quish_proto::CHANNEL_BINDING_LABEL`) that ties a
/// pubkey token to this exact TLS session.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub peer_addr: SocketAddr,
    pub channel_binding: [u8; 32],
    /// Set only on a challenge follow-up round: the server-held state parked at
    /// the end of the previous round plus the client's responses. `None` on a
    /// first (round-one) attempt. A challenge-capable backend inspects this to
    /// decide whether to open a fresh challenge or complete a parked one.
    pub challenge: Option<ChallengeResponse>,
}

/// A credential parsed from the `Authorization` header.
pub enum Credentials {
    /// HTTP Basic → PAM password.
    Password {
        username: String,
        password: Zeroizing<String>,
    },
    /// HTTP Bearer → signed, channel-bound pubkey token.
    SignedToken(pubkey::Token),
}

/// The outcome of an authentication attempt. `Allow` carries the *authenticated*
/// identity — the server binds this to the connection, never a client-supplied
/// username.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow {
        user: String,
    },
    /// A further factor is required before a terminal verdict. `state` is parked
    /// server-side (keyed by connection) and `prompts` is sent to the client,
    /// which answers on a follow-up round. Emitted identically for valid and
    /// invalid first-factor input, so it leaks nothing about account existence;
    /// the registry still floors its outward timing (see [`Registry::authenticate`]).
    Challenge {
        state: ChallengeState,
        prompts: Vec<quish_proto::Prompt>,
    },
    Deny,
}

/// Challenge state parked between rounds. Held ONLY server-side (the registry's
/// owner keeps a per-connection map keyed by `conn_id`, bounded + TTL'd), so a
/// client can never resume another connection's challenge. The client sees only
/// the opaque [`token`](Self::token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeState {
    /// Opaque handle echoed to the client and back; the server matches it against
    /// the parked state for this connection before completing the round.
    pub token: String,
    /// The identity to bind on success, IF the first factor validated; `None`
    /// otherwise. Never sent to the client — this is what keeps a challenge for a
    /// bogus user indistinguishable from one for a real user.
    pub pending_user: Option<String>,
}

/// A client's answer to a parked [`ChallengeState`], assembled server-side from
/// the follow-up request. `responses` line up with the round's prompts.
#[derive(Clone)]
pub struct ChallengeResponse {
    pub state: ChallengeState,
    pub responses: Vec<Zeroizing<String>>,
}

impl std::fmt::Debug for ChallengeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the secret responses (they are one-time codes / factors).
        f.debug_struct("ChallengeResponse")
            .field("state", &self.state)
            .field(
                "responses",
                &format_args!("<{} redacted>", self.responses.len()),
            )
            .finish()
    }
}

impl ChallengeResponse {
    /// Assemble from a wire answer: plain response strings are wrapped in
    /// `Zeroizing` so they are scrubbed on drop. Lets callers (the server) build
    /// a response without depending on `zeroize` themselves.
    pub fn new(state: ChallengeState, responses: Vec<String>) -> Self {
        Self {
            state,
            responses: responses.into_iter().map(Zeroizing::new).collect(),
        }
    }
}

/// An authentication method. Object-safe + async via `async_trait`.
#[async_trait::async_trait]
pub trait AuthBackend: Send + Sync {
    /// Stable identifier, for config + logging.
    fn name(&self) -> &'static str;
    /// Whether this backend handles the given credential kind.
    fn supports(&self, creds: &Credentials) -> bool;
    /// Verify the credential. Must not vary its timing or output by failure cause;
    /// the registry enforces the outward-facing floor regardless.
    async fn authenticate(&self, conn: &ConnInfo, creds: &Credentials) -> Verdict;
}

/// Operator policy applied to every successful authentication, centralized in
/// the registry so a policy denial is indistinguishable from any other failure
/// (identical verdict, same constant-time floor).
///
/// Semantics (sshd-like): `deny_users` always wins; a non-empty `allow_users`
/// is an exhaustive allowlist; both empty = every authenticated user permitted.
#[derive(Debug, Clone, Default)]
pub struct UserPolicy {
    pub allow_users: Vec<String>,
    pub deny_users: Vec<String>,
}
impl UserPolicy {
    pub fn permits(&self, user: &str) -> bool {
        if self.deny_users.iter().any(|u| u == user) {
            return false;
        }
        self.allow_users.is_empty() || self.allow_users.iter().any(|u| u == user)
    }
}

/// The compiled-in set of backends + the centralized failure contract.
pub struct Registry {
    backends: Vec<Box<dyn AuthBackend>>,
    fail_delay: Duration,
    policy: UserPolicy,
}

impl Registry {
    /// Build a registry. `fail_delay` is the constant-time floor every failure is
    /// padded to (mask backend timing differences, e.g. PAM vs a fast reject).
    /// `policy` filters otherwise-successful authentications (allow/deny users).
    pub fn new(
        backends: Vec<Box<dyn AuthBackend>>,
        fail_delay: Duration,
        policy: UserPolicy,
    ) -> Self {
        Self {
            backends,
            fail_delay,
            policy,
        }
    }

    /// Parse the `Authorization` header, dispatch, and enforce anti-enumeration:
    /// every non-success (missing/garbled header, unsupported scheme, backend
    /// deny, OR an intermediate challenge) blocks until `started + fail_delay`,
    /// so neither the terminal `Deny` nor a `Challenge` round leaks timing. Only
    /// a successful `Allow` returns without the floor.
    pub async fn authenticate(&self, authorization: Option<&str>, conn: &ConnInfo) -> Verdict {
        let started = Instant::now();
        let verdict = self.verdict(authorization, conn).await;
        if !matches!(verdict, Verdict::Allow { .. }) {
            // Pad every non-success (terminal `Deny` AND intermediate `Challenge`)
            // to the floor. Backends already returned; timing carries no signal —
            // and flooring the challenge too keeps a slow first factor (e.g. PAM)
            // from leaking account existence on the non-terminal round.
            tokio::time::sleep_until(started + self.fail_delay).await;
        }
        verdict
    }

    /// Raw verdict without the timing floor. Used across the privsep boundary: the
    /// monitor returns this, and the worker applies [`Self::fail_delay`] itself so
    /// a slow PAM never stalls the monitor's serial RPC loop. Still uniform in
    /// outcome — the caller maps every `Deny` to the same 401.
    pub async fn verdict(&self, authorization: Option<&str>, conn: &ConnInfo) -> Verdict {
        let verdict = match parse_authorization(authorization) {
            Some(creds) => self.dispatch(&creds, conn).await,
            None => Verdict::Deny,
        };
        match verdict {
            Verdict::Allow { user } if !self.policy.permits(&user) => {
                tracing::info!(%user, "authenticated but denied by policy (allow_users/deny_users)");
                Verdict::Deny
            }
            v => v,
        }
    }

    /// The constant-time failure floor (for callers applying it themselves).
    pub fn fail_delay(&self) -> Duration {
        self.fail_delay
    }

    async fn dispatch(&self, creds: &Credentials, conn: &ConnInfo) -> Verdict {
        for backend in &self.backends {
            if backend.supports(creds) {
                return backend.authenticate(conn, creds).await;
            }
        }
        Verdict::Deny
    }
}

/// Parse an `Authorization` header value into structured [`Credentials`].
/// `None` for anything we don't understand — the registry treats it as failure.
fn parse_authorization(header: Option<&str>) -> Option<Credentials> {
    let header = header?;
    if let Some(rest) = header.strip_prefix("Basic ") {
        let decoded = BASE64_STANDARD.decode(rest.trim()).ok()?;
        let s = String::from_utf8(decoded).ok()?;
        let (user, pass) = s.split_once(':')?;
        Some(Credentials::Password {
            username: user.to_string(),
            password: Zeroizing::new(pass.to_string()),
        })
    } else if let Some(rest) = header.strip_prefix("Bearer ") {
        Some(Credentials::SignedToken(pubkey::parse_token(rest)?))
    } else {
        None
    }
}

/// Build an `Authorization: Basic ...` value (client side).
pub fn basic_header(username: &str, password: &str) -> String {
    let b64 = BASE64_STANDARD.encode(format!("{username}:{password}"));
    format!("Basic {b64}")
}

/// Build an `Authorization: Bearer ...` value from a token blob (client side).
pub fn bearer_header(token_b64: &str) -> String {
    format!("Bearer {token_b64}")
}

/// Dev-mode backend: accepts *any* password for one fixed username. Never compile
/// this into a real deployment — it exists so local e2e can run without root/PAM.
#[derive(Debug)]
pub struct DevInsecureBackend {
    user: String,
}

impl DevInsecureBackend {
    pub fn new(user: String) -> Self {
        Self { user }
    }
}

#[async_trait::async_trait]
impl AuthBackend for DevInsecureBackend {
    fn name(&self) -> &'static str {
        "dev-insecure"
    }

    fn supports(&self, creds: &Credentials) -> bool {
        matches!(creds, Credentials::Password { .. })
    }

    async fn authenticate(&self, _conn: &ConnInfo, creds: &Credentials) -> Verdict {
        match creds {
            Credentials::Password { username, .. } if *username == self.user => Verdict::Allow {
                user: self.user.clone(),
            },
            _ => Verdict::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn conn() -> ConnInfo {
        ConnInfo {
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            channel_binding: [0u8; 32],
            challenge: None,
        }
    }

    #[test]
    fn basic_header_roundtrips_through_parser() {
        let header = basic_header("alice", "s3cret");
        let creds = parse_authorization(Some(&header)).unwrap();
        match creds {
            Credentials::Password { username, password } => {
                assert_eq!(username, "alice");
                assert_eq!(&*password, "s3cret");
            }
            _ => panic!("expected password"),
        }
    }

    #[test]
    fn garbage_header_is_none() {
        assert!(parse_authorization(Some("Bogus xyz")).is_none());
        assert!(parse_authorization(Some("Basic !!!notbase64")).is_none());
        assert!(parse_authorization(None).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn every_failure_pads_to_the_floor() {
        let reg = Registry::new(
            vec![Box::new(DevInsecureBackend::new("alice".into()))],
            Duration::from_millis(500),
            UserPolicy::default(),
        );
        // No header at all: still floored (paused clock makes this exact + instant).
        let start = Instant::now();
        assert_eq!(reg.authenticate(None, &conn()).await, Verdict::Deny);
        assert_eq!(start.elapsed(), Duration::from_millis(500));
    }

    #[tokio::test]
    async fn dev_backend_allows_matching_user_any_password() {
        let reg = Registry::new(
            vec![Box::new(DevInsecureBackend::new("alice".into()))],
            Duration::from_millis(0),
            UserPolicy::default(),
        );
        let h = basic_header("alice", "whatever");
        assert_eq!(
            reg.authenticate(Some(&h), &conn()).await,
            Verdict::Allow {
                user: "alice".into()
            }
        );
        let wrong = basic_header("mallory", "whatever");
        assert_eq!(reg.authenticate(Some(&wrong), &conn()).await, Verdict::Deny);
    }
    #[test]
    fn policy_permits_semantics() {
        // (allow_users, deny_users, user, expected)
        let cases: &[(&[&str], &[&str], &str, bool)] = &[
            (&[], &[], "anyone", true),
            (&["alice"], &[], "alice", true),
            (&["alice"], &[], "bob", false),
            (&["alice"], &["alice"], "alice", false),
            (&[], &["bob"], "alice", true),
        ];
        for (allow, deny, user, expected) in cases {
            let policy = UserPolicy {
                allow_users: allow.iter().map(|s| s.to_string()).collect(),
                deny_users: deny.iter().map(|s| s.to_string()).collect(),
            };
            assert_eq!(
                policy.permits(user),
                *expected,
                "allow={allow:?} deny={deny:?} user={user}"
            );
        }
    }

    #[tokio::test]
    async fn policy_denied_user_gets_plain_deny() {
        // A user the backend authenticates, but the allowlist excludes: the raw
        // `verdict()` must fold the `Allow` into an indistinguishable `Deny`.
        let reg = Registry::new(
            vec![Box::new(DevInsecureBackend::new("dave".into()))],
            Duration::from_millis(0),
            UserPolicy {
                allow_users: vec!["alice".into()],
                deny_users: vec![],
            },
        );
        let h = basic_header("dave", "whatever");
        assert_eq!(reg.verdict(Some(&h), &conn()).await, Verdict::Deny);
    }

    #[tokio::test(start_paused = true)]
    async fn policy_denial_is_floored() {
        // A policy denial must be padded to the same constant-time floor as any
        // other failure, so it is indistinguishable through `authenticate()`.
        let reg = Registry::new(
            vec![Box::new(DevInsecureBackend::new("dave".into()))],
            Duration::from_millis(500),
            UserPolicy {
                allow_users: vec!["alice".into()],
                deny_users: vec![],
            },
        );
        let h = basic_header("dave", "whatever");
        let start = Instant::now();
        assert_eq!(reg.authenticate(Some(&h), &conn()).await, Verdict::Deny);
        assert_eq!(start.elapsed(), Duration::from_millis(500));
    }
}
