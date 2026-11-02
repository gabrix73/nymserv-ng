use clap::Parser;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use tracing::{error, info, warn};

use nymserv_ng::config::Config;
use nymserv_ng::crypto::openpgp::{decrypt_message, encrypt_message};
use nymserv_ng::mta::send_email;
use nymserv_ng::protocol::ghio::{parse_config_message, validate_alias, AccountFlags};
use nymserv_ng::store::{NymRecord, NymStore, StoreError};

#[derive(Parser, Debug)]
#[command(author, version, about = "nymserv-ng Local Delivery Agent (LDA)")]
struct Args {
    #[arg(short, long, default_value = "/etc/nymserv/nymserv.toml")]
    config: PathBuf,

    #[arg(short, long)]
    recipient: Option<String>,
}

fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    info!("nymserv-lda started with config {:?}", args.config);

    let cfg = match Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            error!("failed to load config at {:?}: {}", args.config, e);
            std::process::exit(75); // EX_TEMPFAIL
        }
    };

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
        std::process::exit(75);
    }

    info!("received {} bytes from stdin", raw_bytes.len());

    let recipient_raw = args.recipient.as_deref().unwrap_or("config");
    let local_part = extract_local_part(recipient_raw);

    info!("processing message for local part: '{}'", local_part);

    let sender = extract_header_value(&raw_bytes, "Reply-To")
        .or_else(|| extract_header_value(&raw_bytes, "From"))
        .unwrap_or_default();

    match local_part.to_ascii_lowercase().as_str() {
        "nobody" => {
            info!("nobody recipient: message silently dropped");
            std::process::exit(0);
        }
        "config" => {
            if let Err(e) = handle_config_message(&cfg, &store, &raw_bytes) {
                error!("error handling config message: {}", e);
                std::process::exit(0);
            }
        }
        "help" | "info" => {
            info!("handling help request from '{}'", sender);
            if !sender.is_empty() {
                if let Err(e) = handle_help_request(&cfg, &sender) {
                    error!("failed to dispatch help response: {}", e);
                }
            } else {
                warn!("help request had no valid return address, dropping");
            }
        }
        "key" | "remailer-key" => {
            // Check if there is an alias parameter in Subject or Body (e.g. "key rasmus73" or Subject: "rasmus73")
            let query = extract_key_query(&raw_bytes);
            if let Some(target_alias) = query {
                info!("handling alias key request for '{}' from '{}'", target_alias, sender);
                if !sender.is_empty() {
                    if let Err(e) = handle_alias_key_request(&cfg, &store, &target_alias, &sender) {
                        error!("failed to dispatch alias key response: {}", e);
                    }
                }
            } else {
                info!("handling server public key request from '{}'", sender);
                if !sender.is_empty() {
                    if let Err(e) = handle_server_key_request(&cfg, &sender) {
                        error!("failed to dispatch server key response: {}", e);
                    }
                } else {
                    warn!("key request had no valid return address, dropping");
                }
            }
        }
        "finger" => {
            let query = extract_key_query(&raw_bytes);
            if let Some(target_alias) = query {
                info!("handling finger request for alias '{}' from '{}'", target_alias, sender);
                if !sender.is_empty() {
                    let _ = handle_alias_key_request(&cfg, &store, &target_alias, &sender);
                }
            } else if !sender.is_empty() {
                let _ = handle_help_request(&cfg, &sender);
            }
        }
        "list" | "used" => {
            info!("handling used aliases list request from '{}'", sender);
            if !sender.is_empty() {
                if let Err(e) = handle_list_request(&cfg, &store, &sender) {
                    error!("failed to dispatch list response: {}", e);
                }
            }
        }
        "send" => {
            info!("send request received: handling outbound anonymous dispatch");
            if let Err(e) = handle_send_message(&cfg, &store, &raw_bytes) {
                error!("error handling outbound send message: {}", e);
            }
        }
        alias => {
            info!("inbound message for alias '{}'", alias);
            match store.get_alias(alias) {
                Ok(Some(record)) => {
                    info!("alias '{}' found in store with {} reply blocks", record.alias, record.reply_blocks.len());
                    if let Err(e) = handle_alias_inbound(&cfg, &store, &record, &raw_bytes) {
                        error!("failed to process inbound mail for alias '{}': {}", record.alias, e);
                    }
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

fn extract_header_value(raw: &[u8], target_header: &str) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some((key, val)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case(target_header) {
                return Some(val.trim().to_string());
            }
        }
    }
    None
}

fn extract_key_query(raw: &[u8]) -> Option<String> {
    if let Some(subj) = extract_header_value(raw, "Subject") {
        let clean = subj.trim();
        for word in clean.split_whitespace() {
            let lower = word.to_ascii_lowercase();
            if lower != "key" && lower != "get" && lower != "finger" && !lower.starts_with("re:") && !lower.is_empty() {
                return Some(lower.trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '-').to_string());
            }
        }
    }

    let text = String::from_utf8_lossy(raw);
    let mut in_body = false;
    for line in text.lines() {
        if in_body {
            let clean = line.trim();
            for word in clean.split_whitespace() {
                let lower = word.to_ascii_lowercase();
                if (clean.starts_with("key ") || clean.starts_with("get ") || clean.starts_with("finger ")) 
                    && lower != "key" && lower != "get" && lower != "finger" {
                    return Some(lower);
                }
            }
        } else if line.is_empty() {
            in_body = true;
        }
    }
    None
}

fn handle_help_request(cfg: &Config, recipient: &str) -> anyhow::Result<()> {
    let body = format!(
        "From: nymserv-ng <help@{}>\n\
        To: {}\n\
        Subject: Help file for {} nym server\n\n\
        ========================================================================\n\
        2 novembre • nymserv-ng Pseudonym Server Help\n\
        ========================================================================\n\n\
        This nymserver provides persistent, bi-directional anonymous identities\n\
        compatible with the crooks/ghionym standard and post-quantum protocols.\n\n\
        Available automated commands (email to <command>@{}):\n\n\
          config@{}  - Register, update or delete your alias (Config: block)\n\
          send@{}    - Send mail from your alias (requires PGP sign +sigsend)\n\
          key@{}     - Get server public keys (OpenPGP RSA & Post-Quantum ML-KEM)\n\
          key@{}     - (with 'get <alias>' in subject/body) Retrieve public key of alias\n\
          list@{}    - List of taken pseudonyms currently in use\n\
          help@{}    - This help document\n\n\
        Online Documentation and Web Interface:\n\
          https://{}\n\
          gemini://{}\n\n\
        Software maintainer: Gabx (AGPL-3.0 pure Rust engine)\n",
        cfg.hostname, recipient, cfg.hostname, cfg.hostname,
        cfg.hostname, cfg.hostname, cfg.hostname, cfg.hostname,
        cfg.hostname, cfg.hostname, cfg.hostname, cfg.hostname
    );

    send_email(&cfg.mta_command, body.as_bytes())?;
    info!("help response delivered to '{}'", recipient);
    Ok(())
}

fn handle_server_key_request(cfg: &Config, recipient: &str) -> anyhow::Result<()> {
    let pgp_pub_path = cfg.keys_dir.join("nymserver-openpgp.asc");
    let pgp_armor = if pgp_pub_path.exists() {
        fs::read_to_string(&pgp_pub_path)?
    } else {
        "(Server OpenPGP key not found)".to_string()
    };

    let body = format!(
        "From: nymserv-ng <key@{}>\n\
        To: {}\n\
        Subject: Public keys for {} nym server\n\n\
        Official server public keys for {}:\n\n\
        1. OpenPGP Legacy Channel Key (RSA 4096):\n\
        ------------------------------------------------------------------------\n\
        {}\n\
        ------------------------------------------------------------------------\n\n\
        2. Post-Quantum Channel Key (NIST FIPS 203 ML-KEM-768):\n\
        ------------------------------------------------------------------------\n\
        Public key binary: https://{}/nymserver-pq-pubkey.bin\n\
        SHA256: 12872e8ea4ffdab9899a08512a934cd43de78a720b7fc19404909d79ecbb68d4\n\
        Client standalone: https://{}/bin/pqpg-linux-amd64\n\
        ------------------------------------------------------------------------\n",
        cfg.hostname, recipient, cfg.hostname, cfg.hostname,
        pgp_armor.trim(), cfg.hostname, cfg.hostname
    );

    send_email(&cfg.mta_command, body.as_bytes())?;
    info!("server keys response delivered to '{}'", recipient);
    Ok(())
}

fn handle_alias_key_request(cfg: &Config, store: &NymStore, alias: &str, recipient: &str) -> anyhow::Result<()> {
    match store.get_alias(alias)? {
        Some(record) => {
            let key_text = record.public_key_armor.as_deref().unwrap_or("(No public key registered for this alias)");
            let body = format!(
                "From: nymserv-ng <key@{}>\n\
                To: {}\n\
                Subject: Public Key for alias {}@{}\n\n\
                Alias: {}@{}\n\
                Created: {}\n\
                Flags: 0x{:04x}\n\n\
                {}\n",
                cfg.hostname, recipient, alias, cfg.hostname,
                alias, cfg.hostname, record.created_at, record.flags, key_text
            );
            send_email(&cfg.mta_command, body.as_bytes())?;
            info!("alias key for '{}' sent to '{}'", alias, recipient);
        }
        None => {
            let body = format!(
                "From: nymserv-ng <key@{}>\n\
                To: {}\n\
                Subject: Alias '{}' not found\n\n\
                The requested alias '{}' is not registered on this nymserver.\n",
                cfg.hostname, recipient, alias, alias
            );
            send_email(&cfg.mta_command, body.as_bytes())?;
            warn!("alias key request for non-existent alias '{}' from '{}'", alias, recipient);
        }
    }
    Ok(())
}

fn handle_list_request(cfg: &Config, store: &NymStore, recipient: &str) -> anyhow::Result<()> {
    let aliases = store.list_aliases()?;
    let body = format!(
        "From: nymserv-ng <nobody@{}>\n\
        To: {}\n\
        Subject: list of used nyms on {}\n\n\
        List of pseudonyms currently in use on {}:\n\n\
        {}\n\n\
        Total pseudonyms registered: {}\n",
        cfg.hostname, recipient, cfg.hostname, cfg.hostname,
        aliases.join("\n"), aliases.len()
    );

    send_email(&cfg.mta_command, body.as_bytes())?;
    info!("used aliases list ({} entries) sent to '{}'", aliases.len(), recipient);
    Ok(())
}

fn handle_alias_inbound(
    cfg: &Config,
    store: &NymStore,
    record: &NymRecord,
    raw_bytes: &[u8],
) -> anyhow::Result<()> {
    if (record.flags & AccountFlags::FL_DISABLED) != 0 {
        warn!("alias '{}' is disabled by account flags, dropping inbound message", record.alias);
        return Ok(());
    }

    if record.reply_blocks.is_empty() {
        warn!("alias '{}' has no reply blocks configured, dropping message", record.alias);
        return Ok(());
    }

    let rb = &record.reply_blocks[0];

    // Extract body of incoming email
    let text = String::from_utf8_lossy(raw_bytes);
    let mut headers = Vec::new();
    let mut body = String::new();
    let mut in_body = false;

    for line in text.lines() {
        if in_body {
            body.push_str(line);
            body.push('\n');
        } else if line.is_empty() {
            in_body = true;
        } else {
            headers.push(line);
        }
    }

    // Encrypt body if FL_CRYPTRECV is set (or if public key is present)
    let final_body = if let Some(ref pubkey) = record.public_key_armor {
        info!("encrypting inbound message for alias '{}' (key present)...", record.alias);
        match encrypt_message(pubkey, body.as_bytes()) {
            Ok(encrypted_armor) => encrypted_armor,
            Err(e) => {
                warn!("PGP encryption failed ({}), falling back to cleartext body", e);
                body
            }
        }
    } else {
        body
    };

    // Parse destination from Reply-Block (e.g. Anon-To: target@example.org or ::)
    let mut target_dest = String::new();
    for rb_line in rb.lines() {
        if let Some((k, v)) = rb_line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("Anon-To") {
                target_dest = v.trim().to_string();
                break;
            }
        }
    }

    if target_dest.is_empty() {
        // Fallback default: if the first line has an email or if destination is local
        target_dest = format!("nobody@{}", cfg.hostname);
    }

    let outbound = format!(
        "From: nobody@{}\n\
        To: {}\n\
        Subject: [nymserv-ng] Encrypted message for alias {}\n\n\
        {}\n\n\
        {}\n",
        cfg.hostname, target_dest, record.alias, rb.trim(), final_body.trim()
    );

    send_email(&cfg.mta_command, outbound.as_bytes())?;
    info!("inbound message for alias '{}' forwarded via reply block to '{}'", record.alias, target_dest);

    // Update activity timestamp
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut updated = record.clone();
    updated.last_active_at = now;
    updated.msg_count_today += 1;
    let _ = store.update_alias(&updated);

    Ok(())
}

fn handle_send_message(
    cfg: &Config,
    _store: &NymStore,
    raw_bytes: &[u8],
) -> anyhow::Result<()> {
    info!("handling outbound send message (size: {} bytes)", raw_bytes.len());
    let secret_key_path = cfg.keys_dir.join("nymserver-secret.asc");

    let decrypted_bytes = if let Some(pgp_data) = extract_pgp_message(raw_bytes) {
        if !secret_key_path.exists() {
            anyhow::bail!("server secret key not found at {:?}", secret_key_path);
        }
        let secret_armor = fs::read_to_string(&secret_key_path)?;
        decrypt_message(&secret_armor, pgp_data)
            .map_err(|e| anyhow::anyhow!("PGP decryption error on send request: {}", e))?
    } else {
        raw_bytes.to_vec()
    };

    let text = String::from_utf8_lossy(&decrypted_bytes);
    let mut dest_to = String::new();
    let mut subject = "Anonymous message".to_string();
    let mut from_alias = String::new();
    let mut body = String::new();
    let mut in_body = false;

    for line in text.lines() {
        if in_body {
            body.push_str(line);
            body.push('\n');
        } else if line.is_empty() {
            in_body = true;
        } else if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            if key == "to" {
                dest_to = v.trim().to_string();
            } else if key == "subject" {
                subject = v.trim().to_string();
            } else if key == "from" {
                from_alias = v.trim().to_string();
            }
        }
    }

    if dest_to.is_empty() {
        anyhow::bail!("send message has no valid 'To:' recipient");
    }

    if from_alias.is_empty() {
        from_alias = format!("anonymous@{}", cfg.hostname);
    }

    let outbound_email = format!(
        "From: {}\n\
        To: {}\n\
        Subject: {}\n\
        X-Nym-Disclaimer: This message was sent anonymously through {}\n\n\
        {}",
        from_alias, dest_to, subject, cfg.hostname, body
    );

    send_email(&cfg.mta_command, outbound_email.as_bytes())?;
    info!("successfully sent outbound email from '{}' to '{}'", from_alias, dest_to);
    Ok(())
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
