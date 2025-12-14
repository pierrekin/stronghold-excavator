// Crypto operations for Stronghold extraction
// Uses iota-crypto for Age decryption and XChaCha20-Poly1305

use iota_crypto::{
    ciphers::{chacha::XChaCha20Poly1305, traits::Aead},
    keys::age,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Age decryption failed: {0:?}")]
    AgeDecrypt(age::DecError),

    #[error("XChaCha20-Poly1305 decryption failed")]
    ChaChaDecrypt,

    #[error("Invalid ciphertext length")]
    InvalidLength,
}

impl From<age::DecError> for CryptoError {
    fn from(e: age::DecError) -> Self {
        CryptoError::AgeDecrypt(e)
    }
}

/// Decrypt Age-encrypted data using a 32-byte key
pub fn age_decrypt(key: &[u8; 32], max_work_factor: u8, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    age::decrypt_vec(key, max_work_factor, ciphertext).map_err(CryptoError::from)
}

/// XChaCha20-Poly1305 constants
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// Decrypt XChaCha20-Poly1305 encrypted data
/// Format: [tag(16)][nonce(24)][ciphertext]
pub fn xchacha_decrypt(key: &[u8], ad: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < TAG_LEN + NONCE_LEN {
        return Err(CryptoError::InvalidLength);
    }

    let (tag, ct) = data.split_at(TAG_LEN);
    let (nonce, cipher) = ct.split_at(NONCE_LEN);

    let mut plain = vec![0u8; cipher.len()];

    XChaCha20Poly1305::try_decrypt(key, nonce, ad, &mut plain, cipher, tag)
        .map_err(|_| CryptoError::ChaChaDecrypt)?;

    Ok(plain)
}
