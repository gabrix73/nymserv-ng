use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use redb::{Database, ReadableTable, TableDefinition};

use crate::protocol::ghio::AccountFlags;

const ALIASES_TABLE: TableDefinition<&str, &str> = TableDefinition::new("aliases");
const REPLAY_TABLE: TableDefinition<&str, u64> = TableDefinition::new("replay_cache");

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("database error: {0}")]
    DbError(String),
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("alias already exists: {0}")]
    AliasExists(String),
    #[error("alias not found: {0}")]
    AliasNotFound(String),
    #[error("daily quota exceeded for alias: {0}")]
    QuotaExceeded(String),
    #[error("replayed or expired message detected")]
    ReplayDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Clone)]
pub struct NymStore {
    db: Arc<Database>,
}

impl NymStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(|e| StoreError::DbError(e.to_string()))?;
        
        // Ensure tables exist
        let write_txn = db.begin_write().map_err(|e| StoreError::DbError(e.to_string()))?;
        {
            let _ = write_txn.open_table(ALIASES_TABLE).map_err(|e| StoreError::DbError(e.to_string()))?;
            let _ = write_txn.open_table(REPLAY_TABLE).map_err(|e| StoreError::DbError(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| StoreError::DbError(e.to_string()))?;

        Ok(Self { db: Arc::new(db) })
    }

    pub fn get_alias(&self, alias: &str) -> Result<Option<NymRecord>, StoreError> {
        let norm_alias = alias.to_ascii_lowercase();
        let read_txn = self.db.begin_read().map_err(|e| StoreError::DbError(e.to_string()))?;
        let table = read_txn.open_table(ALIASES_TABLE).map_err(|e| StoreError::DbError(e.to_string()))?;
        
        if let Some(val) = table.get(norm_alias.as_str()).map_err(|e| StoreError::DbError(e.to_string()))? {
            let record: NymRecord = serde_json::from_str(val.value())
                .map_err(|e| StoreError::SerializationError(e.to_string()))?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    pub fn insert_alias(&self, record: &NymRecord) -> Result<(), StoreError> {
        let norm_alias = record.alias.to_ascii_lowercase();
        let json_str = serde_json::to_string(record)
            .map_err(|e| StoreError::SerializationError(e.to_string()))?;

        let write_txn = self.db.begin_write().map_err(|e| StoreError::DbError(e.to_string()))?;
        {
            let mut table = write_txn.open_table(ALIASES_TABLE).map_err(|e| StoreError::DbError(e.to_string()))?;
            if table.get(norm_alias.as_str()).map_err(|e| StoreError::DbError(e.to_string()))?.is_some() {
                return Err(StoreError::AliasExists(norm_alias));
            }
            table.insert(norm_alias.as_str(), json_str.as_str()).map_err(|e| StoreError::DbError(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| StoreError::DbError(e.to_string()))?;
        Ok(())
    }

    pub fn update_alias(&self, record: &NymRecord) -> Result<(), StoreError> {
        let norm_alias = record.alias.to_ascii_lowercase();
        let json_str = serde_json::to_string(record)
            .map_err(|e| StoreError::SerializationError(e.to_string()))?;

        let write_txn = self.db.begin_write().map_err(|e| StoreError::DbError(e.to_string()))?;
        {
            let mut table = write_txn.open_table(ALIASES_TABLE).map_err(|e| StoreError::DbError(e.to_string()))?;
            table.insert(norm_alias.as_str(), json_str.as_str()).map_err(|e| StoreError::DbError(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| StoreError::DbError(e.to_string()))?;
        Ok(())
    }

    pub fn check_and_record_replay(&self, msg_id: &str, expiry: u64, now: u64) -> Result<(), StoreError> {
        let write_txn = self.db.begin_write().map_err(|e| StoreError::DbError(e.to_string()))?;
        {
            let mut table = write_txn.open_table(REPLAY_TABLE).map_err(|e| StoreError::DbError(e.to_string()))?;
            if let Some(exp) = table.get(msg_id).map_err(|e| StoreError::DbError(e.to_string()))? {
                if exp.value() > now {
                    return Err(StoreError::ReplayDetected);
                }
            }
            table.insert(msg_id, expiry).map_err(|e| StoreError::DbError(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| StoreError::DbError(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nym_store_crud() {
        let tmp_dir = std::env::temp_dir().join(format!("nymserv_test_{}.redb", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = NymStore::open(&tmp_dir).expect("failed to open test store");

        let mut flags = AccountFlags::new();
        flags.set(AccountFlags::FL_ACKSEND, true);
        let record = NymRecord::new(
            "alice".to_string(),
            Some("-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----".to_string()),
            vec!["::\nAnon-To: bob@example.com".to_string()],
            flags,
            1700000000,
        );

        // Insert
        store.insert_alias(&record).expect("insert failed");

        // Duplicate insert fails
        assert!(matches!(store.insert_alias(&record), Err(StoreError::AliasExists(_))));

        // Get
        let fetched = store.get_alias("alice").expect("get failed").expect("not found");
        assert_eq!(fetched.alias, "alice");
        assert_eq!(fetched.reply_blocks.len(), 1);

        // Update
        let mut updated = fetched.clone();
        updated.reply_blocks.push("::\nAnon-To: charlie@example.com".to_string());
        store.update_alias(&updated).expect("update failed");

        let fetched2 = store.get_alias("ALICE").expect("case-insensitive get failed").expect("not found");
        assert_eq!(fetched2.reply_blocks.len(), 2);

        // Replay cache test
        assert!(store.check_and_record_replay("msg123", 2000000000, 1700000000).is_ok());
        assert!(matches!(store.check_and_record_replay("msg123", 2000000000, 1700000000), Err(StoreError::ReplayDetected)));

        let _ = std::fs::remove_file(&tmp_dir);
    }
}
