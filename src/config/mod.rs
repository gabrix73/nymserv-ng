use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub hostname: String,
    pub data_dir: PathBuf,
    #[serde(default = "default_keys_dir")]
    pub keys_dir: PathBuf,
    pub mta_command: String,
    pub max_msg_per_day: u32,
    pub require_confirm: bool,
    pub nym_key_id: Option<String>,
}

fn default_keys_dir() -> PathBuf {
    PathBuf::from("/var/lib/nymserv/keys")
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hostname: "nymserv-ng.virebent.art".to_string(),
            data_dir: PathBuf::from("/var/lib/nymserv/data"),
            keys_dir: default_keys_dir(),
            mta_command: "/usr/sbin/sendmail -t -oi".to_string(),
            max_msg_per_day: 512,
            require_confirm: false,
            nym_key_id: None,
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, anyhow::Error> {
        let p = path.as_ref();
        if p.exists() {
            let content = fs::read_to_string(p)?;
            let cfg: Config = toml::from_str(&content)?;
            Ok(cfg)
        } else {
            Ok(Self::default())
        }
    }
}
