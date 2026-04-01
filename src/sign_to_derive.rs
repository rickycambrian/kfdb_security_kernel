//! Sign-to-derive key derivation from Ethereum ECDSA signatures.
//!
//! Derives a 32-byte AES encryption key from a 65-byte Ethereum signature using
//! `SHA-256(r || s || v)`. This is identical to the gateway's `deriveKeyFromSignature()`.
//!
//! # Protocol
//!
//! 1. Server generates a deterministic challenge message (wallet-specific, versioned)
//! 2. User signs the challenge with their Ethereum wallet (EIP-191 personal_sign)
//! 3. Client calls `derive_key_from_signature(sig_bytes)` → 32-byte AES key
//! 4. Client uses the key for AES-256-GCM encryption/decryption
//!
//! The server **never sees the derived key** — it only receives encrypted data.
//!
//! # Signature Format
//!
//! Ethereum signatures are 65 bytes: `r (32) || s (32) || v (1)`.
//! - `r`: x-coordinate of the ephemeral public key (big-endian)
//! - `s`: signature scalar (big-endian)
//! - `v`: recovery ID (27 or 28 for legacy; 0 or 1 for modern)

use sha2::{Digest, Sha256};

/// Derive a 32-byte encryption key from a 65-byte Ethereum signature.
///
/// Uses `SHA-256(r || s || v)` — identical to gateway's `deriveKeyFromSignature()`.
/// The signature must be exactly 65 bytes: `r (32) || s (32) || v (1)`.
///
/// This function is deterministic: the same signature always produces the same key.
/// Different signatures (including different `v` values) produce different keys.
pub fn derive_key_from_signature(sig_bytes: &[u8; 65]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(sig_bytes);
    hasher.finalize().into()
}

/// Derive a 32-byte encryption key from separate r, s, v components.
///
/// Convenience wrapper around [`derive_key_from_signature`].
pub fn derive_key_from_components(r: &[u8; 32], s: &[u8; 32], v: u8) -> [u8; 32] {
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..64].copy_from_slice(s);
    sig_bytes[64] = v;
    derive_key_from_signature(&sig_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sig(r: u8, s: u8, v: u8) -> [u8; 65] {
        let mut sig = [0u8; 65];
        sig[..32].fill(r);
        sig[32..64].fill(s);
        sig[64] = v;
        sig
    }

    #[test]
    fn test_deterministic() {
        let sig = make_sig(0xAA, 0xBB, 27);
        let k1 = derive_key_from_signature(&sig);
        let k2 = derive_key_from_signature(&sig);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_different_r_different_key() {
        let sig1 = make_sig(0xAA, 0xBB, 27);
        let sig2 = make_sig(0xCC, 0xBB, 27);
        let k1 = derive_key_from_signature(&sig1);
        let k2 = derive_key_from_signature(&sig2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_different_s_different_key() {
        let sig1 = make_sig(0xAA, 0xBB, 27);
        let sig2 = make_sig(0xAA, 0xCC, 27);
        let k1 = derive_key_from_signature(&sig1);
        let k2 = derive_key_from_signature(&sig2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_different_v_different_key() {
        let sig1 = make_sig(0xAA, 0xBB, 27);
        let sig2 = make_sig(0xAA, 0xBB, 28);
        let k1 = derive_key_from_signature(&sig1);
        let k2 = derive_key_from_signature(&sig2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_key_is_32_bytes() {
        let sig = make_sig(0xAA, 0xBB, 27);
        let key = derive_key_from_signature(&sig);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_key_is_not_zero() {
        let sig = make_sig(0xAA, 0xBB, 27);
        let key = derive_key_from_signature(&sig);
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn test_components_match_bytes() {
        let r = [0xAAu8; 32];
        let s = [0xBBu8; 32];
        let v = 27u8;
        let sig = make_sig(0xAA, 0xBB, 27);

        let from_bytes = derive_key_from_signature(&sig);
        let from_components = derive_key_from_components(&r, &s, v);
        assert_eq!(from_bytes, from_components);
    }

    #[test]
    fn test_zero_sig_produces_nonzero_key() {
        // SHA-256 of all-zero input is non-zero
        let sig = [0u8; 65];
        let key = derive_key_from_signature(&sig);
        assert_ne!(key, [0u8; 32]);
    }
}
