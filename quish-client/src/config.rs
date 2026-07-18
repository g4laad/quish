//! Optional client TOML config (`~/.config/quish/config.toml`). Gives the
//! flags-only CLI an `ssh_config`-style equivalent: a `[defaults]` table and
//! per-alias `[hosts.<alias>]` blocks. Every field is optional; precedence is
//! CLI flag → host block → `[defaults]` → built-in default (see the merge
//! matrix in `resolve_target`). A missing file is not an error; a malformed one
//! is (`deny_unknown_fields`, so a typo'd key fails loud rather than being
//! silently ignored).

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientConfig {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub hosts: std::collections::HashMap<String, HostBlock>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Defaults {
    pub identity: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostBlock {
    pub host: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub path: Option<String>,
    pub identity: Option<String>,
    #[serde(default)]
    pub local_forward: Vec<String>,
    #[serde(default)]
    pub remote_forward: Vec<String>,
}

/// Load the client config: `$QUISH_CONFIG` if set, else
/// `$HOME/.config/quish/config.toml`. A missing file is not an error (returns
/// the empty default); a read/parse error is (with the file path in context).
pub(crate) fn load() -> Result<ClientConfig> {
    let path = match std::env::var_os("QUISH_CONFIG") {
        Some(p) => PathBuf::from(p),
        None => {
            let home = std::env::var_os("HOME").context("HOME is not set")?;
            PathBuf::from(home)
                .join(".config")
                .join("quish")
                .join("config.toml")
        }
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ClientConfig::default()),
        Err(e) => return Err(e).with_context(|| format!("reading config {}", path.display())),
    };
    toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
}

/// Expand a leading `~/` against `$HOME`; anything else passes through. Only
/// `~/…` is handled (not `~user/…`), matching the plan's scope.
pub(crate) fn expand_tilde(p: &str) -> Result<PathBuf> {
    match p.strip_prefix("~/") {
        Some(rest) => {
            let home = std::env::var_os("HOME").context("HOME is not set")?;
            Ok(PathBuf::from(home).join(rest))
        }
        None => Ok(PathBuf::from(p)),
    }
}
