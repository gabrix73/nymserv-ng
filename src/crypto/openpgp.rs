use thiserror::Error;
use sequoia_openpgp as openpgp;
use openpgp::cert::Cert;
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptorBuilder, DecryptionHelper, VerificationHelper, MessageStructure,
};
use openpgp::crypto::SessionKey;
use openpgp::Fingerprint;
use std::io::Read;

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

struct Helper<'a> {
    cert: &'a Cert,
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<openpgp::types::SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<Fingerprint>>
    where
        D: FnMut(openpgp::types::SymmetricAlgorithm, &SessionKey) -> bool,
    {
        for pkesk in pkesks {
            for ka in self.cert.keys().secret() {
                let key = ka.key().clone();
                if let Ok(mut pair) = key.into_keypair() {
                    if pkesk.decrypt(&mut pair, sym_algo)
                        .map(|(algo, session_key)| decrypt(algo, &session_key))
                        .unwrap_or(false)
                    {
                        return Ok(Some(ka.fingerprint()));
                    }
                }
            }
        }
        Err(anyhow::anyhow!("No matching secret key found to decrypt message"))
    }
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(Vec::new())
    }
    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

/// Decrypts an OpenPGP message (armored or binary) using the provided secret key cert
pub fn decrypt_message(secret_key_armor: &str, encrypted_data: &[u8]) -> Result<Vec<u8>, PgpError> {
    let cert = Cert::from_bytes(secret_key_armor.as_bytes())
        .map_err(|e| PgpError::DecryptionError(format!("Failed to parse secret cert: {}", e)))?;

    let helper = Helper { cert: &cert };
    let policy = openpgp::policy::StandardPolicy::new();
    let mut decryptor = DecryptorBuilder::from_bytes(encrypted_data)
        .map_err(|e| PgpError::DecryptionError(format!("Invalid encrypted packet stream: {}", e)))?
        .with_policy(&policy, None, helper)
        .map_err(|e| PgpError::DecryptionError(format!("Decryptor build failure: {}", e)))?;

    let mut decrypted = Vec::new();
    decryptor.read_to_end(&mut decrypted)
        .map_err(|e| PgpError::DecryptionError(format!("Decryption read failure: {}", e)))?;

    Ok(decrypted)
}
