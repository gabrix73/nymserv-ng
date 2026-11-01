use thiserror::Error;

/// The Next-Generation Envelope wire layout for YAMN transport
/// Magic: b"NYMNG\x01\x00\x00" (8 bytes)
pub const NG_MAGIC: &[u8; 8] = b"NYMNG\x01\x00\x00";

#[derive(Error, Debug, PartialEq, Eq)]
pub enum NgError {
    #[error("invalid magic bytes in envelope")]
    InvalidMagic,
    #[error("truncated envelope payload")]
    TruncatedPayload,
    #[error("cryptographic verification failed")]
    CryptoFailure,
}

/// Header of the NG envelope
#[derive(Debug, Clone)]
pub struct NgHeader {
    pub key_id: [u8; 8],
    pub epk_classical: [u8; 32], // X25519 ephemeral key
    pub epk_pq: Vec<u8>,         // ML-KEM encapsulation ciphertext
    pub nonce: [u8; 24],         // XChaCha20 nonce
}
