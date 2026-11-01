use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PqError {
    #[error("key generation failure")]
    KeyGenError,
    #[error("decapsulation failure")]
    DecapsulationError,
}

/// Generates a new ML-KEM-768 keypair for the post-quantum server key
pub fn generate_kem_keypair() -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    (dk.as_bytes().as_slice().to_vec(), ek.as_bytes().as_slice().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_kem_keypair() {
        let (dk, ek) = generate_kem_keypair();
        // ML-KEM-768 private key is 2400 bytes, public key is 1184 bytes
        assert_eq!(dk.len(), 2400);
        assert_eq!(ek.len(), 1184);
    }
}
