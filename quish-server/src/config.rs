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
}

impl FileConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
    }
}
