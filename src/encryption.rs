//! Raw AES-256-GCM encryption on byte slices.
//!
//! This module operates on `&[u8]` and `Vec<u8>` only — no dependency on
//! KFDB's `Value` type. The caller is responsible for serializing/deserializing
//! their data before and after encryption.
//!
//! ## Wire format
//!
//! The output of [`encrypt_bytes`] is `base64(nonce || ciphertext || tag)` where:
//! - `nonce`: 12 bytes (randomly generated per call)
//! - `ciphertext`: variable length
//! - `tag`: 16 bytes (AES-GCM authentication tag, appended by aes-gcm crate)
//!
//! Total overhead: 12 (nonce) + 16 (tag) bytes per encrypted value.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use zeroize::Zeroize;

/// Errors that can occur during encryption/decryption.
#[derive(Debug, Clone, PartialEq)]
pub enum EncryptionError {
    /// The encryption key is invalid (wrong length — must be 32 bytes).
    InvalidKey,
    /// AES-GCM encryption failed (internal error).
    EncryptionFailed,
    /// AES-GCM decryption failed (wrong key or tampered/corrupted data).
    DecryptionFailed,
    /// The encrypted payload format is invalid (bad base64, truncated, etc.).
    InvalidFormat,
    /// The key version embedded in the wire format is not known to the caller.
    UnknownKeyVersion(String),
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid encryption key (must be exactly 32 bytes)"),
            Self::EncryptionFailed => write!(f, "AES-GCM encryption failed"),
            Self::DecryptionFailed => {
                write!(f, "AES-GCM decryption failed (wrong key or tampered data)")
            }
            Self::InvalidFormat => write!(f, "invalid encrypted payload format"),
            Self::UnknownKeyVersion(v) => {
                write!(f, "unknown key version '{v}' — not in registry")
            }
        }
    }
}

impl std::error::Error for EncryptionError {}

/// Encrypt arbitrary bytes with AES-256-GCM.
///
/// Returns a base64-encoded string containing `nonce (12B) || ciphertext || tag (16B)`.
/// The nonce is randomly generated per call (non-deterministic).
///
/// # Errors
///
/// Returns [`EncryptionError::InvalidKey`] if `key` is not exactly 32 bytes (it is,
/// since the type guarantees it — but the underlying crate validates anyway).
/// Returns [`EncryptionError::EncryptionFailed`] on AES-GCM internal failure (extremely rare).
pub fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8]) -> Result<String, EncryptionError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncryptionError::InvalidKey)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let mut pt = plaintext.to_vec();
    let ciphertext = cipher.encrypt(&nonce, pt.as_slice()).map_err(|_| {
        pt.zeroize();
        EncryptionError::EncryptionFailed
    })?;
    pt.zeroize();

    // nonce (12 bytes) || ciphertext (includes 16-byte GCM tag)
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(nonce.as_slice());
    combined.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&combined))
}

/// Decrypt bytes that were encrypted with [`encrypt_bytes`].
///
/// Expects a base64-encoded string containing `nonce (12B) || ciphertext || tag (16B)`.
///
/// # Errors
///
/// - [`EncryptionError::InvalidFormat`] — bad base64 or payload too short (< 28 bytes)
/// - [`EncryptionError::InvalidKey`] — key rejected by AES-GCM (should not happen with `[u8; 32]`)
/// - [`EncryptionError::DecryptionFailed`] — wrong key or data tampered
pub fn decrypt_bytes(key: &[u8; 32], b64_data: &str) -> Result<Vec<u8>, EncryptionError> {
    let combined = BASE64
        .decode(b64_data)
        .map_err(|_| EncryptionError::InvalidFormat)?;

    // Minimum: 12 (nonce) + 16 (GCM tag) = 28 bytes
    if combined.len() < 28 {
        return Err(EncryptionError::InvalidFormat);
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncryptionError::InvalidKey)?;
    let mut plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    // Caller owns the plaintext — they should zeroize when done if it contains secrets
    let result = plaintext.clone();
    plaintext.zeroize();

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    #[test]
    fn test_roundtrip_bytes() {
        let plaintext = b"hello world";
        let encrypted = encrypt_bytes(&TEST_KEY, plaintext).unwrap();
        let decrypted = decrypt_bytes(&TEST_KEY, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_roundtrip_empty() {
        let plaintext = b"";
        let encrypted = encrypt_bytes(&TEST_KEY, plaintext).unwrap();
        let decrypted = decrypt_bytes(&TEST_KEY, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_roundtrip_large() {
        let plaintext: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let encrypted = encrypt_bytes(&TEST_KEY, &plaintext).unwrap();
        let decrypted = decrypt_bytes(&TEST_KEY, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_nonce_is_random() {
        let plaintext = b"same plaintext";
        let enc1 = encrypt_bytes(&TEST_KEY, plaintext).unwrap();
        let enc2 = encrypt_bytes(&TEST_KEY, plaintext).unwrap();
        // Two encryptions of the same plaintext must produce different ciphertexts (random nonce)
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_wrong_key_fails() {
        let plaintext = b"secret data";
        let encrypted = encrypt_bytes(&TEST_KEY, plaintext).unwrap();

        let mut wrong_key = TEST_KEY;
        wrong_key[0] ^= 0xFF;
        let result = decrypt_bytes(&wrong_key, &encrypted);
        assert_eq!(result, Err(EncryptionError::DecryptionFailed));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let plaintext = b"secret data";
        let encrypted = encrypt_bytes(&TEST_KEY, plaintext).unwrap();

        // Flip a bit in the middle of the base64 payload
        let mut bytes = BASE64.decode(&encrypted).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        let tampered = BASE64.encode(&bytes);

        let result = decrypt_bytes(&TEST_KEY, &tampered);
        assert_eq!(result, Err(EncryptionError::DecryptionFailed));
    }

    #[test]
    fn test_invalid_base64_fails() {
        let result = decrypt_bytes(&TEST_KEY, "not-valid-base64!!!");
        assert_eq!(result, Err(EncryptionError::InvalidFormat));
    }

    #[test]
    fn test_too_short_fails() {
        // Valid base64 but fewer than 28 bytes
        let short = BASE64.encode(b"short");
        let result = decrypt_bytes(&TEST_KEY, &short);
        assert_eq!(result, Err(EncryptionError::InvalidFormat));
    }

    #[test]
    fn test_error_display() {
        assert!(EncryptionError::InvalidKey.to_string().contains("32 bytes"));
        assert!(EncryptionError::DecryptionFailed
            .to_string()
            .contains("wrong key"));
        assert!(EncryptionError::InvalidFormat
            .to_string()
            .contains("format"));
        assert!(EncryptionError::UnknownKeyVersion("k99".to_string())
            .to_string()
            .contains("k99"));
    }

    #[test]
    fn test_output_is_base64() {
        let encrypted = encrypt_bytes(&TEST_KEY, b"test").unwrap();
        // Should decode without error
        let decoded = BASE64.decode(&encrypted).unwrap();
        // Minimum 28 bytes (12 nonce + 16 tag + 0 plaintext... + 4 plaintext)
        assert!(decoded.len() >= 28);
    }
}
