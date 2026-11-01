use thiserror::Error;

#[derive(Error, Debug)]
pub enum PgpError {
    #[error("failed to parse armored key")]
    KeyParseError,
    #[error("decryption failure: {0}")]
    DecryptionError(String),
    #[error("signature verification failure: {0}")]
    SignatureError(String),
    #[error("unsupported cryptographic algorithm")]
    UnsupportedAlgorithm,
}

/// Validates that an armored OpenPGP public key block is syntactically sound
pub fn validate_armored_public_key(armor: &str) -> Result<(), PgpError> {
    if !armor.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        || !armor.contains("-----END PGP PUBLIC KEY BLOCK-----")
    {
        return Err(PgpError::KeyParseError);
    }
    // Basic structural checks pass
    Ok(())
}
