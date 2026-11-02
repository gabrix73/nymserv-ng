use clap::Parser;
use std::fs;
use std::io::{self, Read};
use tracing::{error, info, warn};

use nymserv_ng::config::Config;
use nymserv_ng::crypto::openpgp::decrypt_message;
use nymserv_ng::protocol::ghio::{parse_config_message, validate_alias};
use nymserv_ng::store::{NymRecord, NymStore, StoreError};

#[derive(Parser, Debug)]
#[command(author, version, about = "nymserv-ng Local Delivery Agent (Postfix integration)")]
struct Args {
    #[arg(short, long, default_value = "/etc/nymserv/nymserv.toml")]
    config: String,

    #[arg(short, long)]
    recipient: Option<String>,
}

fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    info!("nymserv-lda invoked for recipient: {:?}", args.recipient);

    let cfg = match Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            error!("failed to load config {}: {}", args.config, e);
            std::process::exit(75); // EX_TEMPFAIL
        }
    };

    // Ensure data directory exists
    if let Err(e) = fs::create_dir_all(&cfg.data_dir) {
        error!("failed to create data dir {:?}: {}", cfg.data_dir, e);
        std::process::exit(75);
    }

    // Open persistent database
    let db_path = cfg.data_dir.join("nymserv.redb");
    let store = match NymStore::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            error!("failed to open database at {:?}: {}", db_path, e);
            std::process::exit(75);
        }
    };

    // Read email from stdin (provided by Postfix pipe)
    let mut raw_bytes = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut raw_bytes) {
        error!("failed to read stdin: {}", e);
        std::process::exit(75); // EX_TEMPFAIL
    }

    info!("received {} bytes from stdin", raw_bytes.len());

    let recipient_raw = args.recipient.as_deref().unwrap_or("config");
    let local_part = extract_local_part(recipient_raw);

    info!("processing message for local part: '{}'", local_part);

    match local_part.to_ascii_lowercase().as_str() {
        "config" => {
            if let Err(e) = handle_config_message(&cfg, &store, &raw_bytes) {
                error!("error handling config message: {}", e);
                // Return 0 so Postfix does not bounce indefinitely on bad client formatting
                std::process::exit(0);
            }
        }
        "send" => {
            info!("send request received (queued for dispatch)");
        }
        alias => {
            info!("inbound message for alias '{}'", alias);
            match store.get_alias(alias) {
                Ok(Some(record)) => {
                    info!("alias '{}' found in store with {} reply blocks", record.alias, record.reply_blocks.len());
                }
                Ok(None) => {
                    warn!("alias '{}' does not exist in store, dropping or bouncing", alias);
                }
                Err(e) => {
                    error!("database error fetching alias '{}': {}", alias, e);
                    std::process::exit(75);
                }
            }
        }
    }

    info!("nymserv-lda completed successfully");
    std::process::exit(0);
}

fn extract_local_part(recipient: &str) -> &str {
    let clean = recipient.trim();
    if let Some((local, _)) = clean.split_once('@') {
        local
    } else {
        clean
    }
}

fn extract_pgp_message(input: &[u8]) -> Option<&[u8]> {
    let start_tag = b"-----BEGIN PGP MESSAGE-----";
    let end_tag = b"-----END PGP MESSAGE-----";

    let start_idx = input.windows(start_tag.len()).position(|w| w == start_tag)?;
    let end_offset = input[start_idx..].windows(end_tag.len()).position(|w| w == end_tag)?;
    let end_idx = start_idx + end_offset + end_tag.len();

    Some(&input[start_idx..end_idx])
}

fn handle_config_message(cfg: &Config, store: &NymStore, raw_bytes: &[u8]) -> Result<(), anyhow::Error> {
    let secret_key_path = cfg.keys_dir.join("nymserver-secret.asc");
    
    let decrypted_text = if let Some(pgp_data) = extract_pgp_message(raw_bytes) {
        info!("found PGP encrypted block ({} bytes), attempting decryption...", pgp_data.len());
        if !secret_key_path.exists() {
            anyhow::bail!("server secret key not found at {:?}", secret_key_path);
        }
        let secret_armor = fs::read_to_string(&secret_key_path)?;
        let decrypted_bytes = decrypt_message(&secret_armor, pgp_data)
            .map_err(|e| anyhow::anyhow!("PGP decryption error: {}", e))?;
        String::from_utf8(decrypted_bytes)
            .map_err(|e| anyhow::anyhow!("decrypted payload is not valid UTF-8: {}", e))?
    } else {
        info!("no PGP block detected, checking for plain text Config payload...");
        String::from_utf8_lossy(raw_bytes).to_string()
    };

    let req = parse_config_message(&decrypted_text, &cfg.hostname)
        .map_err(|e| anyhow::anyhow!("failed to parse Config: message: {}", e))?;

    validate_alias(&req.alias)
        .map_err(|e| anyhow::anyhow!("alias '{}' invalid: {}", req.alias, e))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let record = NymRecord::new(
        req.alias.clone(),
        req.public_key_armor,
        req.reply_blocks,
        req.updated_flags,
        now,
    );

    match store.insert_alias(&record) {
        Ok(()) => {
            info!("successfully registered new alias '{}' with {} reply block(s)", record.alias, record.reply_blocks.len());
        }
        Err(StoreError::AliasExists(alias)) => {
            warn!("alias '{}' already exists, updating existing alias record", alias);
            store.update_alias(&record)?;
            info!("successfully updated alias '{}'", record.alias);
        }
        Err(e) => {
            anyhow::bail!("failed to store alias record: {}", e);
        }
    }

    Ok(())
}
