use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub hostname: String,
    pub data_dir: PathBuf,
    pub mta_command: String,
    pub max_msg_per_day: u32,
    pub require_confirm: bool,
    pub nym_key_id: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hostname: "nymserv-ng.virebent.art".to_string(),
            data_dir: PathBuf::from("/var/lib/nymserv"),
            mta_command: "/usr/sbin/sendmail -t -oi".to_string(),
            max_msg_per_day: 512,
            require_confirm: false,
            nym_key_id: None,
        }
    }
}
