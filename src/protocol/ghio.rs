use thiserror::Error;

pub const RESERVED_ALIASES: &[&str] = &[
    "config",
    "send",
    "list",
    "root",
    "nobody",
    "used",
    "confirm",
    "postmaster",
    "admin",
    "mailer-daemon",
];

pub const DEFAULT_MAX_LINES: usize = 1024;
pub const DEFAULT_MAX_MSG_PER_DAY: u32 = 512;

/// Flags for nym account configuration, mirroring ghionym bitmap
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountFlags(pub u32);

impl AccountFlags {
    pub const FL_ENCRECV: u32 = 0x1;    // Encrypt received mail with user's pubkey
    pub const FL_SIGSEND: u32 = 0x2;    // Enforce digital signature on sent messages
    pub const FL_ACKSEND: u32 = 0x100;  // Send ACK back on message delivery
    pub const FL_DISABLED: u32 = 0x200; // Account is temporarily disabled
    pub const FL_FIXEDSZ: u32 = 0x400;  // Fixed size padding
    pub const FL_NOBCC: u32 = 0x1000;   // Strip or reject BCC
    pub const FL_NOLIMIT: u32 = 0x10000;// Bypass daily quota

    pub const DEFAULT: u32 = Self::FL_ENCRECV | Self::FL_SIGSEND;

    pub fn new() -> Self {
        Self(Self::DEFAULT)
    }

    pub fn is_set(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }

    pub fn set(&mut self, flag: u32, enabled: bool) {
        if enabled {
            self.0 |= flag;
        } else {
            self.0 &= !flag;
        }
    }
}

impl Default for AccountFlags {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum GhioError {
    #[error("non-config message provided to config processor")]
    NotConfigMessage,
    #[error("header exceeds maximum lines limit")]
    HeaderTooLarge,
    #[error("invalid or reserved alias name: {0}")]
    InvalidAlias(String),
    #[error("missing 'From:' line")]
    MissingFrom,
    #[error("duplicate 'From:' line")]
    DuplicateFrom,
    #[error("missing public key in creation request")]
    MissingPublicKey,
    #[error("missing reply block in creation request")]
    MissingReplyBlock,
    #[error("malformed command syntax: {0}")]
    MalformedCommand(String),
}

/// Validates an alias according to ghionym rules.
pub fn validate_alias(alias: &str) -> Result<(), GhioError> {
    let lower = alias.to_ascii_lowercase();
    if lower.len() < 2 || lower.len() > 16 {
        return Err(GhioError::InvalidAlias(alias.to_string()));
    }
    let chars: Vec<char> = lower.chars().collect();
    if !chars[0].is_ascii_alphanumeric() {
        return Err(GhioError::InvalidAlias(alias.to_string()));
    }
    for c in &chars[1..] {
        if !c.is_ascii_alphanumeric() && *c != '-' && *c != '_' {
            return Err(GhioError::InvalidAlias(alias.to_string()));
        }
    }
    if RESERVED_ALIASES.contains(&lower.as_str()) {
        return Err(GhioError::InvalidAlias(alias.to_string()));
    }
    Ok(())
}

/// Extracted Configuration Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRequest {
    pub alias: String,
    pub public_key_armor: Option<String>,
    pub reply_blocks: Vec<String>,
    pub commands: Vec<String>,
    pub updated_flags: AccountFlags,
}

/// Extracted Send Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendRequest {
    pub from_alias: String,
    pub recipients: Vec<String>,
    pub hidden_to: Vec<String>,
    pub subject: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub commands: Vec<String>,
}

/// Parses a plaintext Config message body (decrypted from OpenPGP)
pub fn parse_config_message(content: &str, hostname: &str) -> Result<ConfigRequest, GhioError> {
    let mut lines = content.lines();
    
    // Look for Config:
    let mut found_config = false;
    for line in &mut lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.eq_ignore_ascii_case("Config:") {
            found_config = true;
            break;
        } else {
            return Err(GhioError::NotConfigMessage);
        }
    }
    if !found_config {
        return Err(GhioError::NotConfigMessage);
    }

    let mut user: Option<String> = None;
    let mut pubkey: Option<String> = None;
    let mut reply_blocks = Vec::new();
    let mut commands = Vec::new();
    let mut flags = AccountFlags::new();

    let mut in_pubkey = false;
    let mut in_rb = false;
    let mut current_rb = String::new();

    for line in lines {
        if in_pubkey {
            if let Some(ref mut key_buf) = pubkey {
                key_buf.push_str(line);
                key_buf.push('\n');
                if line.contains("-----END PGP PUBLIC KEY BLOCK-----") {
                    in_pubkey = false;
                }
            }
            continue;
        }

        if in_rb {
            if line.starts_with("Reply-Block:") || line.starts_with("reply-block:") {
                if !current_rb.trim().is_empty() {
                    reply_blocks.push(current_rb.trim().to_string());
                    current_rb.clear();
                }
                let rest = line[12..].trim();
                if !rest.is_empty() {
                    current_rb.push_str(rest);
                    current_rb.push('\n');
                }
            } else if line.starts_with("Nym-Command:") || line.starts_with("Nym-Commands:") {
                if !current_rb.trim().is_empty() {
                    reply_blocks.push(current_rb.trim().to_string());
                    current_rb.clear();
                }
                in_rb = false;
                let idx = line.find(':').unwrap();
                let cmd_line = line[idx + 1..].trim();
                for token in cmd_line.split_whitespace() {
                    commands.push(token.to_string());
                    apply_flag_token(token, &mut flags);
                }
            } else if line.trim().is_empty() {
                if !current_rb.trim().is_empty() {
                    reply_blocks.push(current_rb.trim().to_string());
                    current_rb.clear();
                }
                in_rb = false;
            } else {
                current_rb.push_str(line);
                current_rb.push('\n');
            }
            continue;
        }

        if line.starts_with("From:") || line.starts_with("from:") {
            if user.is_some() {
                return Err(GhioError::DuplicateFrom);
            }
            let raw_addr = line[5..].trim();
            let alias = extract_alias(raw_addr, hostname);
            validate_alias(&alias)?;
            user = Some(alias);
        } else if line.starts_with("Public-Key:") || line.starts_with("public-key:") {
            in_pubkey = true;
            let mut key_buf = String::new();
            let rest = line[11..].trim();
            if !rest.is_empty() {
                key_buf.push_str(rest);
                key_buf.push('\n');
                if rest.contains("-----END PGP PUBLIC KEY BLOCK-----") {
                    in_pubkey = false;
                }
            }
            pubkey = Some(key_buf);
        } else if line.starts_with("Reply-Block:") || line.starts_with("reply-block:") {
            in_rb = true;
            let rest = line[12..].trim();
            if !rest.is_empty() {
                current_rb.push_str(rest);
                current_rb.push('\n');
            }
        } else if line.starts_with("Nym-Command:") || line.starts_with("Nym-Commands:") {
            let idx = line.find(':').unwrap();
            let cmd_line = line[idx + 1..].trim();
            for token in cmd_line.split_whitespace() {
                commands.push(token.to_string());
                apply_flag_token(token, &mut flags);
            }
        }
    }

    if in_rb && !current_rb.trim().is_empty() {
        reply_blocks.push(current_rb.trim().to_string());
    }

    let alias = user.ok_or(GhioError::MissingFrom)?;

    Ok(ConfigRequest {
        alias,
        public_key_armor: pubkey,
        reply_blocks,
        commands,
        updated_flags: flags,
    })
}

/// Helper to parse command flags like +cryptrecv, -acksend
fn apply_flag_token(token: &str, flags: &mut AccountFlags) {
    let lower = token.to_ascii_lowercase();
    let enabled = lower.starts_with('+');
    let name = lower.trim_start_matches(|c| c == '+' || c == '-');
    match name {
        "cryptrecv" => flags.set(AccountFlags::FL_ENCRECV, enabled),
        "sigsend" => flags.set(AccountFlags::FL_SIGSEND, enabled),
        "acksend" => flags.set(AccountFlags::FL_ACKSEND, enabled),
        "fixedsz" => flags.set(AccountFlags::FL_FIXEDSZ, enabled),
        "nobcc" => flags.set(AccountFlags::FL_NOBCC, enabled),
        "nolimit" => flags.set(AccountFlags::FL_NOLIMIT, enabled),
        _ => {}
    }
}

/// Extracts alias name from string like "alias@nym.virebent.art" or "John <alias@nym.virebent.art>"
pub fn extract_alias(addr: &str, hostname: &str) -> String {
    let clean = addr.trim().trim_matches(|c| c == '<' || c == '>');
    let mut email = clean;
    if let Some(start) = clean.rfind('<') {
        if let Some(end) = clean.rfind('>') {
            if end > start {
                email = &clean[start + 1..end];
            }
        }
    }
    if let Some((local, domain)) = email.split_once('@') {
        if domain.eq_ignore_ascii_case(hostname) {
            return local.trim().to_ascii_lowercase();
        }
        return local.trim().to_ascii_lowercase();
    }
    clean.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_alias() {
        assert!(validate_alias("alice").is_ok());
        assert!(validate_alias("bob_123").is_ok());
        assert!(validate_alias("a-valid-nym").is_ok());

        assert!(validate_alias("config").is_err());
        assert!(validate_alias("send").is_err());
        assert!(validate_alias("root").is_err());
        assert!(validate_alias("a").is_err()); // too short
        assert!(validate_alias("thisaliasnameiswaytoolongtofit").is_err());
        assert!(validate_alias("-invalid").is_err());
    }

    #[test]
    fn test_parse_config_message() {
        let raw = r#"Config:
From: alice@nym.virebent.art
Public-Key:
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG v1.0
mQENBF...
-----END PGP PUBLIC KEY BLOCK-----
Reply-Block:
::
Anon-To: alice_real@example.com

Nym-Commands: +cryptrecv +acksend -sigsend
"#;
        let req = parse_config_message(raw, "nym.virebent.art").expect("should parse");
        assert_eq!(req.alias, "alice");
        assert!(req.public_key_armor.is_some());
        assert!(req.public_key_armor.unwrap().contains("BEGIN PGP PUBLIC KEY BLOCK"));
        assert_eq!(req.reply_blocks.len(), 1);
        assert!(req.reply_blocks[0].contains("Anon-To: alice_real@example.com"));
        assert!(req.updated_flags.is_set(AccountFlags::FL_ENCRECV));
        assert!(req.updated_flags.is_set(AccountFlags::FL_ACKSEND));
        assert!(!req.updated_flags.is_set(AccountFlags::FL_SIGSEND));
    }
}
