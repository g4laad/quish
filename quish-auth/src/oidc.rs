//! OIDC bearer auth backend.
//!
//! Validates a compact JWT (a `Bearer` value containing `.`, discriminated in
//! [`crate::parse_authorization`]) against an operator-provisioned **static JWKS
//! file** read from disk on every attempt. There is deliberately **no network
//! I/O**: the monitor never fetches keys or reaches an IdP (a JWKS fetcher
//! process is a recorded follow-up, out of this slice). A validated token maps a
//! configured claim verbatim to the local username.
//!
//! ## Crypto backend
//!
//! `jsonwebtoken` v10 dropped its `ring` backend for pluggable
//! [`CryptoProvider`](jsonwebtoken::crypto::CryptoProvider)s. Its bundled
//! providers are unusable here: `rust_crypto` drags in the `rsa` crate
//! (RUSTSEC-2023-0071, which fails `cargo deny`), and `aws-lc-rs` bundles the
//! OpenSSL license (outside our allow-list). So this slice installs a **custom,
//! EdDSA-only provider** backed by the `ed25519-dalek` we already depend on —
//! pure Rust, no problematic transitive deps. `jsonwebtoken` still parses the
//! JWKS, decodes the token, and enforces every registered-claim check
//! (`exp`/`nbf`/`iss`/`aud`); we only supply the Ed25519 signature primitive.
//! RS256 is a recorded follow-up (needs a gate-passing RSA backend).
//!
//! Anti-enumeration: every failure path returns a plain [`Verdict::Deny`] with
//! no distinct error and no claim values in logs; the registry's centralized,
//! constant-time-floored 401 does the rest.

use std::path::PathBuf;
use std::sync::Once;

use jsonwebtoken::crypto::{CryptoProvider, JwkUtils, JwtSigner, JwtVerifier};
use jsonwebtoken::errors::{Error as JwtError, ErrorKind};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Validation, decode, decode_header, get_current_timestamp,
};

use crate::{AuthBackend, ConnInfo, Credentials, Verdict};

/// Default claim mapped to the local username.
pub const DEFAULT_USER_CLAIM: &str = "preferred_username";
/// Default maximum accepted age (seconds) of a token, measured from `iat`.
pub const DEFAULT_MAX_TOKEN_AGE_SECS: u64 = 300;

// --- custom EdDSA-only crypto provider ------------------------------------

/// Verifies an Ed25519 JWT signature with `ed25519-dalek`. Wraps the public key
/// recovered from the OKP JWK.
struct EdVerifier(ed25519_dalek::VerifyingKey);

impl signature::Verifier<Vec<u8>> for EdVerifier {
    fn verify(&self, msg: &[u8], sig: &Vec<u8>) -> Result<(), signature::Error> {
        let sig = ed25519_dalek::Signature::from_slice(sig).map_err(|_| signature::Error::new())?;
        // Strict verification rejects non-canonical / weak signatures.
        self.0
            .verify_strict(msg, &sig)
            .map_err(|_| signature::Error::new())
    }
}

impl JwtVerifier for EdVerifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

fn verifier_factory(
    alg: &Algorithm,
    key: &DecodingKey,
) -> jsonwebtoken::errors::Result<Box<dyn JwtVerifier>> {
    if *alg != Algorithm::EdDSA {
        return Err(JwtError::from(ErrorKind::InvalidAlgorithm));
    }
    let raw: [u8; 32] = key
        .as_bytes()
        .get(..32)
        .and_then(|s| <[u8; 32]>::try_from(s).ok())
        .ok_or_else(|| JwtError::from(ErrorKind::InvalidEddsaKey))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&raw)
        .map_err(|_| JwtError::from(ErrorKind::InvalidEddsaKey))?;
    Ok(Box::new(EdVerifier(vk)))
}

fn signer_factory(
    _alg: &Algorithm,
    _key: &EncodingKey,
) -> jsonwebtoken::errors::Result<Box<dyn JwtSigner>> {
    // The server only ever verifies OIDC tokens; signing is never wired.
    Err(JwtError::from(ErrorKind::InvalidAlgorithm))
}

static PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory,
    verifier_factory,
    // We never process RSA/EC JWKs or thumbprints, so the JWK utils stay unused.
    jwk_utils: JwkUtils::new_unimplemented(),
};

/// Install our provider process-wide, exactly once. Must run before the first
/// `jsonwebtoken` decode so its `OnceLock` default is never initialized from the
/// (absent) crate-feature provider.
fn ensure_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = PROVIDER.install_default();
    });
}

// --- config + backend -----------------------------------------------------

/// OIDC backend configuration. Mirrored by a serde struct in `quish-server`.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Required `iss` claim value.
    pub issuer: String,
    /// Required `aud` claim value.
    pub audience: String,
    /// Path to a static JWKS document (JSON), re-read on each attempt.
    pub jwks_file: PathBuf,
    /// Claim whose value becomes the local username (verbatim). Default
    /// [`DEFAULT_USER_CLAIM`].
    pub user_claim: String,
    /// Maximum age in seconds, checked against `iat` when the token carries one.
    /// Default [`DEFAULT_MAX_TOKEN_AGE_SECS`].
    pub max_token_age_secs: u64,
}

/// Verifies OIDC JWTs against a static JWKS file. See the module docs.
#[derive(Debug)]
pub struct OidcBackend {
    cfg: OidcConfig,
}

impl OidcBackend {
    pub fn new(cfg: OidcConfig) -> Self {
        ensure_provider();
        Self { cfg }
    }

    /// The whole validation pipeline, returning the mapped username on success.
    /// Every rejection is a plain `None` — the caller maps it to `Verdict::Deny`
    /// so no failure cause is ever distinguishable.
    fn verify(&self, token: &str) -> Option<String> {
        // (1) Read + parse the JWKS file. Any I/O or parse failure -> Deny.
        let jwks_bytes = std::fs::read(&self.cfg.jwks_file).ok()?;
        let jwks: JwkSet = serde_json::from_slice(&jwks_bytes).ok()?;

        // (2) Select the signing key: by `kid` when present, else the sole key.
        let header = decode_header(token).ok()?;
        let jwk = match &header.kid {
            Some(kid) => jwks.find(kid)?,
            None if jwks.keys.len() == 1 => &jwks.keys[0],
            None => return None,
        };
        let key = DecodingKey::from_jwk(jwk).ok()?;

        // (3) Validate signature + registered claims under an EdDSA allowlist.
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.algorithms = vec![Algorithm::EdDSA];
        validation.set_issuer(&[self.cfg.issuer.as_str()]);
        validation.set_audience(&[self.cfg.audience.as_str()]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        // `exp`, `iss`, `aud` are mandatory (a token without `exp` is refused).
        validation.required_spec_claims = ["exp", "iss", "aud"]
            .into_iter()
            .map(str::to_string)
            .collect();

        let data = decode::<serde_json::Value>(token, &key, &validation).ok()?;
        let claims = data.claims;

        // (4) Bound token age against `iat` when present. An IdP JWT is not
        // channel-bound (unlike a pubkey token), so short lifetimes are the
        // mitigation; see the README replay caveat.
        if let Some(iat) = claims.get("iat").and_then(serde_json::Value::as_u64) {
            let now = get_current_timestamp();
            if now.saturating_sub(iat) > self.cfg.max_token_age_secs {
                return None;
            }
        }

        // (5) Map the configured claim to a non-empty local username.
        let user = claims.get(&self.cfg.user_claim)?.as_str()?;
        if user.is_empty() {
            return None;
        }
        Some(user.to_string())
    }
}

#[async_trait::async_trait]
impl AuthBackend for OidcBackend {
    fn name(&self) -> &'static str {
        "oidc"
    }

    fn supports(&self, creds: &Credentials) -> bool {
        matches!(creds, Credentials::Jwt(_))
    }

    async fn authenticate(&self, _conn: &ConnInfo, creds: &Credentials) -> Verdict {
        let Credentials::Jwt(token) = creds else {
            return Verdict::Deny;
        };
        match self.verify(token) {
            Some(user) => Verdict::Allow { user },
            None => {
                // Counter-style only: never log claim contents on failure.
                tracing::debug!("oidc token rejected");
                Verdict::Deny
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn conn() -> ConnInfo {
        ConnInfo {
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            channel_binding: [0u8; 32],
            challenge: None,
        }
    }

    fn b64url(bytes: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(bytes)
    }

    /// A signing key plus its single-key JWKS document (OKP JWK) written to disk.
    struct TestIdp {
        signing: SigningKey,
        jwks_path: PathBuf,
    }

    fn idp(kid: &str) -> TestIdp {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        let jwks = format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"{kid}","x":"{}"}}]}}"#,
            b64url(&pubkey)
        );
        // Unique per call so a test that rewrites its JWKS (e.g. the garbage-file
        // case) can't race a sibling reading the same path under parallel runs.
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "quish-oidc-test-{}-{kid}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let jwks_path = dir.join("jwks.json");
        std::fs::write(&jwks_path, jwks).unwrap();
        TestIdp { signing, jwks_path }
    }

    fn cfg_for(idp: &TestIdp) -> OidcConfig {
        OidcConfig {
            issuer: "https://issuer.example".into(),
            audience: "quish".into(),
            jwks_file: idp.jwks_path.clone(),
            user_claim: DEFAULT_USER_CLAIM.into(),
            max_token_age_secs: DEFAULT_MAX_TOKEN_AGE_SECS,
        }
    }

    /// Mint a compact JWT signed by `signing`. Kept deliberately hand-rolled so
    /// the tests do not depend on a `jsonwebtoken` signing backend.
    fn mint(signing: &SigningKey, kid: Option<&str>, claims: &serde_json::Value) -> String {
        let header = match kid {
            Some(k) => serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": k}),
            None => serde_json::json!({"alg": "EdDSA", "typ": "JWT"}),
        };
        let h = b64url(&serde_json::to_vec(&header).unwrap());
        let p = b64url(&serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = signing.sign(signing_input.as_bytes());
        format!("{h}.{p}.{}", b64url(&sig.to_bytes()))
    }

    fn now() -> u64 {
        get_current_timestamp()
    }

    fn valid_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": "https://issuer.example",
            "aud": "quish",
            "sub": "abc",
            "preferred_username": "alice",
            "iat": now(),
            "exp": now() + 60,
        })
    }

    async fn verdict(cfg: OidcConfig, token: &str) -> Verdict {
        OidcBackend::new(cfg)
            .authenticate(&conn(), &Credentials::Jwt(token.to_string()))
            .await
    }

    #[tokio::test]
    async fn happy_path_allows_mapped_user() {
        let idp = idp("k1");
        let token = mint(&idp.signing, Some("k1"), &valid_claims());
        assert_eq!(
            verdict(cfg_for(&idp), &token).await,
            Verdict::Allow {
                user: "alice".into()
            }
        );
    }

    #[tokio::test]
    async fn no_kid_single_key_allows() {
        let idp = idp("k1");
        // Header carries no `kid`; the sole JWKS key must still be selected.
        let token = mint(&idp.signing, None, &valid_claims());
        assert_eq!(
            verdict(cfg_for(&idp), &token).await,
            Verdict::Allow {
                user: "alice".into()
            }
        );
    }

    #[tokio::test]
    async fn wrong_issuer_denies() {
        let idp = idp("k1");
        let mut claims = valid_claims();
        claims["iss"] = serde_json::json!("https://evil.example");
        let token = mint(&idp.signing, Some("k1"), &claims);
        assert_eq!(verdict(cfg_for(&idp), &token).await, Verdict::Deny);
    }

    #[tokio::test]
    async fn wrong_audience_denies() {
        let idp = idp("k1");
        let mut claims = valid_claims();
        claims["aud"] = serde_json::json!("someone-else");
        let token = mint(&idp.signing, Some("k1"), &claims);
        assert_eq!(verdict(cfg_for(&idp), &token).await, Verdict::Deny);
    }

    #[tokio::test]
    async fn expired_denies() {
        let idp = idp("k1");
        let mut claims = valid_claims();
        // Well beyond the default 60s validation leeway.
        claims["iat"] = serde_json::json!(now() - 7200);
        claims["exp"] = serde_json::json!(now() - 3600);
        let token = mint(&idp.signing, Some("k1"), &claims);
        assert_eq!(verdict(cfg_for(&idp), &token).await, Verdict::Deny);
    }

    #[tokio::test]
    async fn stale_iat_beyond_max_age_denies() {
        let idp = idp("k1");
        // Not yet expired, but minted long ago -> fails max_token_age_secs.
        let mut claims = valid_claims();
        claims["iat"] = serde_json::json!(now() - 10_000);
        claims["exp"] = serde_json::json!(now() + 3600);
        let token = mint(&idp.signing, Some("k1"), &claims);
        assert_eq!(verdict(cfg_for(&idp), &token).await, Verdict::Deny);
    }

    #[tokio::test]
    async fn unknown_kid_denies() {
        let idp = idp("k1");
        let token = mint(&idp.signing, Some("does-not-exist"), &valid_claims());
        assert_eq!(verdict(cfg_for(&idp), &token).await, Verdict::Deny);
    }

    #[tokio::test]
    async fn garbage_jwks_file_denies() {
        let idp = idp("k1");
        let token = mint(&idp.signing, Some("k1"), &valid_claims());
        std::fs::write(&idp.jwks_path, b"not json at all").unwrap();
        assert_eq!(verdict(cfg_for(&idp), &token).await, Verdict::Deny);
    }

    #[tokio::test]
    async fn missing_user_claim_denies() {
        let idp = idp("k1");
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("preferred_username");
        let token = mint(&idp.signing, Some("k1"), &claims);
        assert_eq!(verdict(cfg_for(&idp), &token).await, Verdict::Deny);
    }

    #[tokio::test]
    async fn empty_user_claim_denies() {
        let idp = idp("k1");
        let mut claims = valid_claims();
        claims["preferred_username"] = serde_json::json!("");
        let token = mint(&idp.signing, Some("k1"), &claims);
        assert_eq!(verdict(cfg_for(&idp), &token).await, Verdict::Deny);
    }

    #[tokio::test]
    async fn wrong_key_signature_denies() {
        // Token signed by a *different* key than the JWKS advertises.
        let idp = idp("k1");
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let token = mint(&other, Some("k1"), &valid_claims());
        assert_eq!(verdict(cfg_for(&idp), &token).await, Verdict::Deny);
    }
}
