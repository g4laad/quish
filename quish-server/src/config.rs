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
}

impl FileConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
    }
}
