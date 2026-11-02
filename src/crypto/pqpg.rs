use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

#[derive(Error, Debug)]
pub enum PqpgError {
    #[error("invalid key length or magic identifier")]
    InvalidKeyFormat,
    #[error("cryptographic key parsing error")]
    KeyParsingError,
    #[error("KEM encapsulation/decapsulation failure")]
    KemError,
    #[error("AEAD encryption/decryption error")]
    AeadError,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("invalid message format or length")]
    InvalidMessageFormat,
    #[error("header '{0}' not found in armored text")]
    MissingArmorHeader(String),
    #[error("footer '{0}' not found in armored text")]
    MissingArmorFooter(String),
    #[error("base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}

// ----------------------------------------------------------------------------
// Armor
// ----------------------------------------------------------------------------

pub fn encode_armored(header_type: &str, data: &[u8]) -> String {
    let b64 = B64.encode(data);
    let mut out = String::with_capacity(b64.len() + 128);
    out.push_str(&format!("-----BEGIN PQPG {}-----\n\n", header_type));

    for chunk in b64.as_bytes().chunks(64) {
        if let Ok(line) = std::str::from_utf8(chunk) {
            out.push_str(line);
            out.push('\n');
        }
    }

    out.push_str(&format!("-----END PQPG {}-----\n", header_type));
    out
}

pub fn decode_armored(armored: &str, header_type: &str) -> Result<Vec<u8>, PqpgError> {
    let begin_tag = format!("-----BEGIN PQPG {}-----", header_type);
    let end_tag = format!("-----END PQPG {}-----", header_type);

    let start_pos = armored
        .find(&begin_tag)
        .ok_or_else(|| PqpgError::MissingArmorHeader(begin_tag.clone()))?;
    let content_start = start_pos + begin_tag.len();

    let end_pos = armored[content_start..]
        .find(&end_tag)
        .ok_or_else(|| PqpgError::MissingArmorFooter(end_tag.clone()))?;

    let inner = &armored[content_start..content_start + end_pos];

    let mut clean_b64 = String::with_capacity(inner.len());
    for line in inner.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.contains(':') {
            continue;
        }
        clean_b64.push_str(trimmed);
    }

    let decoded = B64.decode(clean_b64)?;
    Ok(decoded)
}

// ----------------------------------------------------------------------------
// Keys
// ----------------------------------------------------------------------------

pub struct PublicKey {
    pub ed25519_pk: VerifyingKey,
    pub x25519_pk: X25519PublicKey,
    pub kem_pk_bytes: Vec<u8>,
}

pub struct PrivateKey {
    pub ed25519_sk: SigningKey,
    pub x25519_sk: StaticSecret,
    pub kem_sk_bytes: Vec<u8>,
}

impl PublicKey {
    pub const MAGIC: &'static [u8; 4] = b"PQPK";
    pub const VERSION: u8 = 0x01;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 1 + 32 + 32 + self.kem_pk_bytes.len());
        buf.extend_from_slice(Self::MAGIC);
        buf.push(Self::VERSION);
        buf.extend_from_slice(self.ed25519_pk.as_bytes());
        buf.extend_from_slice(self.x25519_pk.as_bytes());
        buf.extend_from_slice(&self.kem_pk_bytes);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PqpgError> {
        if data.len() < 4 + 1 + 32 + 32 + 1184 {
            return Err(PqpgError::InvalidKeyFormat);
        }
        if &data[0..4] != Self::MAGIC || data[4] != Self::VERSION {
            return Err(PqpgError::InvalidKeyFormat);
        }
        let ed_bytes: [u8; 32] = data[5..37].try_into().map_err(|_| PqpgError::InvalidKeyFormat)?;
        let ed25519_pk = VerifyingKey::from_bytes(&ed_bytes).map_err(|_| PqpgError::KeyParsingError)?;

        let x_bytes: [u8; 32] = data[37..69].try_into().map_err(|_| PqpgError::InvalidKeyFormat)?;
        let x25519_pk = X25519PublicKey::from(x_bytes);

        let kem_pk_bytes = data[69..69 + 1184].to_vec();

        Ok(Self {
            ed25519_pk,
            x25519_pk,
            kem_pk_bytes,
        })
    }

    pub fn from_armored(armored: &str) -> Result<Self, PqpgError> {
        let bytes = decode_armored(armored, "PUBLIC KEY")?;
        Self::from_bytes(&bytes)
    }

    pub fn to_armored(&self) -> String {
        encode_armored("PUBLIC KEY", &self.to_bytes())
    }
}

impl PrivateKey {
    pub const MAGIC: &'static [u8; 4] = b"PQSK";
    pub const VERSION: u8 = 0x01;

    pub fn from_bytes(data: &[u8]) -> Result<Self, PqpgError> {
        if data.len() < 4 + 1 + 32 + 32 + 2400 {
            return Err(PqpgError::InvalidKeyFormat);
        }
        if &data[0..4] != Self::MAGIC || data[4] != Self::VERSION {
            return Err(PqpgError::InvalidKeyFormat);
        }
        let ed_bytes: [u8; 32] = data[5..37].try_into().map_err(|_| PqpgError::InvalidKeyFormat)?;
        let ed25519_sk = SigningKey::from_bytes(&ed_bytes);

        let x_bytes: [u8; 32] = data[37..69].try_into().map_err(|_| PqpgError::InvalidKeyFormat)?;
        let x25519_sk = StaticSecret::from(x_bytes);

        let kem_sk_bytes = data[69..69 + 2400].to_vec();

        Ok(Self {
            ed25519_sk,
            x25519_sk,
            kem_sk_bytes,
        })
    }

    pub fn from_armored(armored: &str) -> Result<Self, PqpgError> {
        let bytes = decode_armored(armored, "PRIVATE KEY")?;
        Self::from_bytes(&bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 1 + 32 + 32 + self.kem_sk_bytes.len());
        buf.extend_from_slice(Self::MAGIC);
        buf.push(Self::VERSION);
        buf.extend_from_slice(self.ed25519_sk.as_bytes());
        buf.extend_from_slice(&self.x25519_sk.to_bytes());
        buf.extend_from_slice(&self.kem_sk_bytes);
        buf
    }

    pub fn to_armored(&self) -> String {
        encode_armored("PRIVATE KEY", &self.to_bytes())
    }
}

// ----------------------------------------------------------------------------
// Crypto Operations
// ----------------------------------------------------------------------------

pub const MESSAGE_MAGIC: &[u8; 4] = b"PQPM";
pub const MESSAGE_VERSION: u8 = 0x01;

pub const KEM_CT_LEN: usize = 1088;
pub const X25519_PK_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const HEADER_LEN: usize = 4 + 1 + KEM_CT_LEN + X25519_PK_LEN + NONCE_LEN; // 1137 bytes

fn derive_hybrid_key(kem_ss: &[u8], x25519_ss: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(kem_ss.len() + x25519_ss.len());
    ikm.extend_from_slice(kem_ss);
    ikm.extend_from_slice(x25519_ss);

    let hk = Hkdf::<Sha256>::new(Some(b"PQPG-HYBRID-KEM-V1"), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"chacha20-poly1305-key", &mut okm)
        .expect("32 bytes is valid length for HKDF");
    okm
}

pub fn encrypt_message(recipient: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, PqpgError> {
    if recipient.kem_pk_bytes.len() != 1184 {
        return Err(PqpgError::InvalidMessageFormat);
    }

    let ek_encoded = Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::clone_from_slice(&recipient.kem_pk_bytes);
    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_encoded);
    let (kem_ct, kem_ss) = ek.encapsulate(&mut OsRng).map_err(|_| PqpgError::KemError)?;

    let ephemeral_x_sk = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_x_pk = X25519PublicKey::from(&ephemeral_x_sk);
    let x25519_ss = ephemeral_x_sk.diffie_hellman(&recipient.x25519_pk);

    let aead_key = derive_hybrid_key(kem_ss.as_slice(), x25519_ss.as_bytes());

    let cipher = ChaCha20Poly1305::new((&aead_key).into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_payload = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| PqpgError::AeadError)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext_payload.len());
    out.extend_from_slice(MESSAGE_MAGIC);
    out.push(MESSAGE_VERSION);
    out.extend_from_slice(kem_ct.as_slice());
    out.extend_from_slice(ephemeral_x_pk.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext_payload);

    Ok(out)
}

pub fn decrypt_message(recipient_sk: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, PqpgError> {
    if ciphertext.len() < HEADER_LEN + 16 {
        return Err(PqpgError::InvalidMessageFormat);
    }
    if &ciphertext[0..4] != MESSAGE_MAGIC || ciphertext[4] != MESSAGE_VERSION {
        return Err(PqpgError::InvalidMessageFormat);
    }

    let kem_ct_bytes = &ciphertext[5..5 + KEM_CT_LEN];
    let x25519_pk_bytes: [u8; 32] = ciphertext[5 + KEM_CT_LEN..5 + KEM_CT_LEN + 32]
        .try_into()
        .map_err(|_| PqpgError::InvalidMessageFormat)?;
    let nonce_bytes = &ciphertext[5 + KEM_CT_LEN + 32..HEADER_LEN];
    let payload = &ciphertext[HEADER_LEN..];

    let dk_encoded = Encoded::<<MlKem768 as KemCore>::DecapsulationKey>::clone_from_slice(&recipient_sk.kem_sk_bytes);
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_encoded);
    let ct_encoded = ml_kem::Ciphertext::<MlKem768>::clone_from_slice(kem_ct_bytes);
    let kem_ss = dk.decapsulate(&ct_encoded).map_err(|_| PqpgError::KemError)?;

    let ephemeral_x_pk = X25519PublicKey::from(x25519_pk_bytes);
    let x25519_ss = recipient_sk.x25519_sk.diffie_hellman(&ephemeral_x_pk);

    let aead_key = derive_hybrid_key(kem_ss.as_slice(), x25519_ss.as_bytes());

    let cipher = ChaCha20Poly1305::new((&aead_key).into());
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| PqpgError::AeadError)?;

    Ok(plaintext)
}

pub fn sign_data(signing_key: &SigningKey, data: &[u8]) -> Vec<u8> {
    let signature: Signature = signing_key.sign(data);
    signature.to_bytes().to_vec()
}

pub fn verify_data(verifying_key: &VerifyingKey, data: &[u8], sig_bytes: &[u8]) -> Result<(), PqpgError> {
    let sig = Signature::from_slice(sig_bytes).map_err(|_| PqpgError::SignatureVerificationFailed)?;
    verifying_key.verify(data, &sig).map_err(|_| PqpgError::SignatureVerificationFailed)?;
    Ok(())
}
