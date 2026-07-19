//! Optional TOML config file (see `dist/server.toml`). Every field is optional;
//! precedence is CLI flag → config file → built-in default.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub listen: Option<SocketAddr>,
    pub path: Option<String>,
    pub privsep_user: Option<String>,
    pub privsep_dir: Option<String>,
    pub host_key: Option<PathBuf>,
    pub max_auth_fails: Option<u32>,
    /// Enable local (`-L`) TCP port forwarding. OFF by default; set `true` to
    /// allow it. When enabled, forwarding is loopback-only — the server connects
    /// only to `127.0.0.0/8` / `::1`, so a forward channel cannot pivot to other
    /// hosts. Overridden by the `--allow-forward` CLI flag. Takes effect in both
    /// dev and privsep (daemon) modes.
    pub allow_forward: Option<bool>,
    /// Enable remote (`-R`) TCP port forwarding. OFF by default; set `true` to
    /// allow it. When enabled, the server binds a loopback-only listener
    /// (`127.0.0.0/8` / `::1`, port >= 1024) and forwards each inbound connection
    /// back to the client, which dials the client-side target — so a remote
    /// forward cannot expose a service to non-loopback peers. Overridden by the
    /// `--allow-remote-forward` CLI flag. Takes effect in both dev and privsep
    /// (daemon) modes.
    pub allow_remote_forward: Option<bool>,
    /// Disable the worker's seccomp-bpf syscall filter (privsep mode only). OFF
    /// by default (`false` = the filter is enforcing). An escape hatch for a
    /// kernel/glibc/tokio version where the allowlist starts SIGSYS-killing the
    /// worker; the real fix is re-auditing the allowlist. Overridden by the
    /// `--no-seccomp` CLI flag. No effect in dev mode (which does no privilege
    /// drop and installs no filter).
    pub no_seccomp: Option<bool>,
    /// Require a per-user TOTP second factor (privsep mode). Reads each user's
    /// base32 secret from `~/.config/quish/totp`. Needs the `pam` feature for the
    /// password first factor. Overridden by the `--totp` CLI flag. No effect in
    /// dev mode (use `--dev-insecure-totp-secret` there).
    pub totp: Option<bool>,
    /// Users permitted to log in. Empty or unset = every authenticated user is
    /// allowed. A non-empty list is an exhaustive allowlist (sshd-like); anyone
    /// not named is refused even after a valid credential. `deny_users` still
    /// wins over this. Overridden wholesale by any `--allow-user` CLI flag.
    /// Takes effect in both dev and privsep (daemon) modes.
    pub allow_users: Option<Vec<String>>,
    /// Users refused even if they authenticate. Always wins over `allow_users`.
    /// Overridden wholesale by any `--deny-user` CLI flag. Takes effect in both
    /// dev and privsep (daemon) modes.
    pub deny_users: Option<Vec<String>>,
    /// OIDC bearer auth (experimental). Config-file only — there are no CLI flags
    /// for it this slice. When present, a validated JWT (a `Bearer` value
    /// containing `.`) authenticates via a static, operator-provisioned JWKS
    /// file; see [`OidcConfig`]. Takes effect in both dev and privsep modes.
    pub oidc: Option<OidcConfig>,
}

impl FileConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
    }
}

/// The `[oidc]` config table. Converted into [`quish_auth::oidc::OidcConfig`]
/// via [`OidcConfig::into_backend`], applying the built-in claim/age defaults.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Required `iss` claim value.
    pub issuer: String,
    /// Required `aud` claim value.
    pub audience: String,
    /// Path to a static JWKS document (JSON), re-read on each attempt.
    pub jwks_file: PathBuf,
    /// Claim mapped verbatim to the local username. Defaults to
    /// `preferred_username`.
    pub user_claim: Option<String>,
    /// Max accepted token age (seconds), checked against `iat` when present.
    /// Defaults to 300.
    pub max_token_age_secs: Option<u64>,
}

impl OidcConfig {
    pub fn into_backend(self) -> quish_auth::oidc::OidcConfig {
        quish_auth::oidc::OidcConfig {
            issuer: self.issuer,
            audience: self.audience,
            jwks_file: self.jwks_file,
            user_claim: self
                .user_claim
                .unwrap_or_else(|| quish_auth::oidc::DEFAULT_USER_CLAIM.to_string()),
            max_token_age_secs: self
                .max_token_age_secs
                .unwrap_or(quish_auth::oidc::DEFAULT_MAX_TOKEN_AGE_SECS),
        }
    }
}
