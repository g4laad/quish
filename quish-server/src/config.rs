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
    /// Enable local (`-L`) TCP port forwarding. Loopback-only when enabled;
    /// forwarding is refused unless this is `true`. Default (unset) = disabled.
    ///
    /// Parsed here so the knob is documented and stable, but not yet threaded to
    /// the frontends: this slice enables forwarding via the `QUISH_ALLOW_FORWARD`
    /// env override (see `session::forwarding_enabled`). Wiring this field to a
    /// `--allow-forward` CLI flag and the privsep monitor→worker handoff is a
    /// documented follow-up, hence `allow(dead_code)` for now.
    #[allow(dead_code)]
    pub allow_forward: Option<bool>,
}

impl FileConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
    }
}
