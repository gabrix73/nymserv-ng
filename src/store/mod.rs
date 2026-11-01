use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::protocol::ghio::AccountFlags;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("database error: {0}")]
    DbError(String),
    #[error("alias already exists: {0}")]
    AliasExists(String),
    #[error("alias not found: {0}")]
    AliasNotFound(String),
    #[error("daily quota exceeded for alias: {0}")]
    QuotaExceeded(String),
    #[error("replayed or expired message detected")]
    ReplayDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NymRecord {
    pub alias: String,
    pub created_at: u64,
    pub last_active_at: u64,
    pub flags: u32,
    pub public_key_armor: Option<String>,
    pub reply_blocks: Vec<String>,
    pub msg_count_today: u32,
    pub current_day: u32,
}

impl NymRecord {
    pub fn new(alias: String, public_key_armor: Option<String>, reply_blocks: Vec<String>, flags: AccountFlags, now: u64) -> Self {
        Self {
            alias,
            created_at: now,
            last_active_at: now,
            flags: flags.0,
            public_key_armor,
            reply_blocks,
            msg_count_today: 0,
            current_day: (now / 86400) as u32,
        }
    }
}
