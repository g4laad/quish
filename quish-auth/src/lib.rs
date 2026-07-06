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

#[cfg(feature = "pam")]
pub mod pam;

/// Per-connection facts a backend may need. `channel_binding` is the 32-byte
/// TLS exporter output (see `quish_proto::CHANNEL_BINDING_LABEL`) that ties a
/// pubkey token to this exact TLS session.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub peer_addr: SocketAddr,
    pub channel_binding: [u8; 32],
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
    Allow { user: String },
    Deny,
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

/// The compiled-in set of backends + the centralized failure contract.
pub struct Registry {
    backends: Vec<Box<dyn AuthBackend>>,
    fail_delay: Duration,
}

impl Registry {
    /// Build a registry. `fail_delay` is the constant-time floor every failure is
    /// padded to (mask backend timing differences, e.g. PAM vs a fast reject).
    pub fn new(backends: Vec<Box<dyn AuthBackend>>, fail_delay: Duration) -> Self {
        Self {
            backends,
            fail_delay,
        }
    }

    /// Parse the `Authorization` header, dispatch, and enforce anti-enumeration:
    /// every failure (missing/garbled header, unsupported scheme, backend deny)
    /// returns an identical `Deny` and blocks until `started + fail_delay`.
    pub async fn authenticate(&self, authorization: Option<&str>, conn: &ConnInfo) -> Verdict {
        let started = Instant::now();

        let verdict = match parse_authorization(authorization) {
            Some(creds) => self.dispatch(&creds, conn).await,
            None => Verdict::Deny,
        };

        if verdict == Verdict::Deny {
            // Pad to the floor. Backends already returned; timing carries no signal.
            tokio::time::sleep_until(started + self.fail_delay).await;
        }
        verdict
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
}
