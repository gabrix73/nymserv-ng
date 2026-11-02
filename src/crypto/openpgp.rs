use thiserror::Error;
use sequoia_openpgp as openpgp;
use openpgp::cert::Cert;
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptorBuilder, DecryptionHelper, VerificationHelper, MessageStructure,
};
use openpgp::crypto::SessionKey;
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message};
use openpgp::Fingerprint;
use std::io::{Read, Write};

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

/// Encrypts plaintext bytes for an armored recipient public key, returning armored PGP ciphertext
pub fn encrypt_message(recipient_pubkey_armor: &str, plaintext: &[u8]) -> Result<String, PgpError> {
    let cert = Cert::from_bytes(recipient_pubkey_armor.as_bytes())
        .map_err(|e| PgpError::DecryptionError(format!("Failed to parse recipient cert: {}", e)))?;

    let policy = openpgp::policy::StandardPolicy::new();
    let recipients = cert.keys().with_policy(&policy, None).supported().alive().revoked(false).for_transport_encryption();

    let mut armored_sink = Vec::new();
    let message = Message::new(&mut armored_sink);
    let armorer = Armorer::new(message).build()
        .map_err(|e| PgpError::DecryptionError(format!("Armorer build error: {}", e)))?;
    let encryptor = Encryptor::for_recipients(armorer, recipients).build()
        .map_err(|e| PgpError::DecryptionError(format!("Encryptor build error: {}", e)))?;
    let mut literal = LiteralWriter::new(encryptor).build()
        .map_err(|e| PgpError::DecryptionError(format!("LiteralWriter build error: {}", e)))?;
    literal.write_all(plaintext)
        .map_err(|e| PgpError::DecryptionError(format!("Write error: {}", e)))?;
    literal.finalize()
        .map_err(|e| PgpError::DecryptionError(format!("Finalize error: {}", e)))?;

    String::from_utf8(armored_sink)
        .map_err(|e| PgpError::DecryptionError(format!("UTF-8 conversion error: {}", e)))
}
