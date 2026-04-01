//! Key hierarchy for zero-knowledge graph encryption.
//!
//! Derives purpose-specific sub-keys from a root encryption key using HKDF-SHA256.
//! This ensures domain separation: even with the same root key, each sub-system
//! (graph properties, vectors, FTS, per-property) gets a cryptographically
//! independent key.
//!
//! # Key Hierarchy
//!
//! ```text
//! Root Key (32 bytes)
//!   ├── Graph Key    ("kfdb-graph-key-v1")       → encrypt node/edge properties
//!   ├── Vector Key   ("kfdb-vector-key-v1")       → encrypt embedding vectors
//!   ├── FTS Key      ("kfdb-fts-key-v1")          → encrypt full-text search tokens
//!   └── Property Key ("kfdb-property-key-v1:{name}") → per-property-name key
//! ```
//!
//! # Sign-to-Derive
//!
//! For wallet-based auth, the root key is derived from an ECDSA signature:
//! `SHA-256(r || s || v)` where r,s are 32 bytes and v is 1 byte (recovery id).

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Info strings for HKDF domain separation.
const GRAPH_KEY_INFO: &str = "kfdb-graph-key-v1";
const VECTOR_KEY_INFO: &str = "kfdb-vector-key-v1";
const FTS_KEY_INFO: &str = "kfdb-fts-key-v1";
const PROPERTY_KEY_PREFIX: &str = "kfdb-property-key-v1:";

/// A complete set of derived keys for a tenant.
#[derive(Clone)]
pub struct KeyHierarchy {
    /// Key for encrypting graph node/edge properties.
    pub graph_key: [u8; 32],
    /// Key for encrypting embedding vectors.
    pub vector_key: [u8; 32],
    /// Key for encrypting full-text search tokens.
    pub fts_key: [u8; 32],
    /// The root key (kept for deriving per-property keys on demand).
    root_key: [u8; 32],
}

impl KeyHierarchy {
    /// Derive a full key hierarchy from a root encryption key.
    pub fn from_root_key(root_key: &[u8; 32]) -> Self {
        Self {
            graph_key: derive_subkey(root_key, GRAPH_KEY_INFO),
            vector_key: derive_subkey(root_key, VECTOR_KEY_INFO),
            fts_key: derive_subkey(root_key, FTS_KEY_INFO),
            root_key: *root_key,
        }
    }

    /// Derive a per-property-name encryption key.
    ///
    /// This allows different properties to be encrypted with different keys,
    /// enabling selective disclosure (e.g., reveal "name" without revealing "salary").
    pub fn property_key(&self, property_name: &str) -> [u8; 32] {
        let info = format!("{PROPERTY_KEY_PREFIX}{property_name}");
        derive_subkey(&self.root_key, &info)
    }

    /// Derive a key hierarchy from an ECDSA signature (sign-to-derive).
    ///
    /// The root key is `SHA-256(r || s || v)` where:
    /// - `r`: 32 bytes (signature r component)
    /// - `s`: 32 bytes (signature s component)
    /// - `v`: 1 byte (recovery id)
    ///
    /// This allows wallet-based key derivation without storing any secrets:
    /// the user signs a deterministic challenge, and we derive all keys from that.
    pub fn from_signature(r: &[u8; 32], s: &[u8; 32], v: u8) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(r);
        hasher.update(s);
        hasher.update([v]);
        let root: [u8; 32] = hasher.finalize().into();
        Self::from_root_key(&root)
    }

    /// Derive from raw signature bytes (65 bytes: r[32] || s[32] || v[1]).
    pub fn from_signature_bytes(sig: &[u8; 65]) -> Self {
        let r: [u8; 32] = sig[..32].try_into().unwrap();
        let s: [u8; 32] = sig[32..64].try_into().unwrap();
        let v = sig[64];
        Self::from_signature(&r, &s, v)
    }
}

/// Zeroize the root key on drop for defense-in-depth.
impl Drop for KeyHierarchy {
    fn drop(&mut self) {
        self.root_key.fill(0);
        self.graph_key.fill(0);
        self.vector_key.fill(0);
        self.fts_key.fill(0);
    }
}

/// Derive a 32-byte sub-key from a root key using HKDF-SHA256.
fn derive_subkey(root_key: &[u8; 32], info: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, root_key);
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ROOT: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    #[test]
    fn test_deterministic_derivation() {
        let h1 = KeyHierarchy::from_root_key(&TEST_ROOT);
        let h2 = KeyHierarchy::from_root_key(&TEST_ROOT);
        assert_eq!(h1.graph_key, h2.graph_key);
        assert_eq!(h1.vector_key, h2.vector_key);
        assert_eq!(h1.fts_key, h2.fts_key);
    }

    #[test]
    fn test_domain_separation() {
        let h = KeyHierarchy::from_root_key(&TEST_ROOT);
        // All sub-keys must be different from each other
        assert_ne!(h.graph_key, h.vector_key);
        assert_ne!(h.graph_key, h.fts_key);
        assert_ne!(h.vector_key, h.fts_key);
        // And different from root
        assert_ne!(h.graph_key, TEST_ROOT);
    }

    #[test]
    fn test_different_roots_different_keys() {
        let mut other_root = TEST_ROOT;
        other_root[0] = 0xFF;
        let h1 = KeyHierarchy::from_root_key(&TEST_ROOT);
        let h2 = KeyHierarchy::from_root_key(&other_root);
        assert_ne!(h1.graph_key, h2.graph_key);
        assert_ne!(h1.vector_key, h2.vector_key);
        assert_ne!(h1.fts_key, h2.fts_key);
    }

    #[test]
    fn test_property_key_deterministic() {
        let h = KeyHierarchy::from_root_key(&TEST_ROOT);
        let k1 = h.property_key("name");
        let k2 = h.property_key("name");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_property_key_different_names() {
        let h = KeyHierarchy::from_root_key(&TEST_ROOT);
        let k1 = h.property_key("name");
        let k2 = h.property_key("salary");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_property_key_differs_from_graph_key() {
        let h = KeyHierarchy::from_root_key(&TEST_ROOT);
        let pk = h.property_key("name");
        assert_ne!(pk, h.graph_key);
    }

    #[test]
    fn test_sign_to_derive() {
        let r = [0xAAu8; 32];
        let s = [0xBBu8; 32];
        let v = 27u8;

        let h1 = KeyHierarchy::from_signature(&r, &s, v);
        let h2 = KeyHierarchy::from_signature(&r, &s, v);
        assert_eq!(h1.graph_key, h2.graph_key);
    }

    #[test]
    fn test_sign_to_derive_different_sigs() {
        let r1 = [0xAAu8; 32];
        let r2 = [0xCCu8; 32];
        let s = [0xBBu8; 32];
        let v = 27u8;

        let h1 = KeyHierarchy::from_signature(&r1, &s, v);
        let h2 = KeyHierarchy::from_signature(&r2, &s, v);
        assert_ne!(h1.graph_key, h2.graph_key);
    }

    #[test]
    fn test_from_signature_bytes() {
        let r = [0xAAu8; 32];
        let s = [0xBBu8; 32];
        let v = 27u8;

        let mut sig_bytes = [0u8; 65];
        sig_bytes[..32].copy_from_slice(&r);
        sig_bytes[32..64].copy_from_slice(&s);
        sig_bytes[64] = v;

        let from_parts = KeyHierarchy::from_signature(&r, &s, v);
        let from_bytes = KeyHierarchy::from_signature_bytes(&sig_bytes);
        assert_eq!(from_parts.graph_key, from_bytes.graph_key);
        assert_eq!(from_parts.vector_key, from_bytes.vector_key);
        assert_eq!(from_parts.fts_key, from_bytes.fts_key);
    }

    #[test]
    fn test_recovery_id_matters() {
        let r = [0xAAu8; 32];
        let s = [0xBBu8; 32];

        let h1 = KeyHierarchy::from_signature(&r, &s, 27);
        let h2 = KeyHierarchy::from_signature(&r, &s, 28);
        assert_ne!(h1.graph_key, h2.graph_key);
    }

    #[test]
    fn test_keys_are_not_zero() {
        let h = KeyHierarchy::from_root_key(&TEST_ROOT);
        assert_ne!(h.graph_key, [0u8; 32]);
        assert_ne!(h.vector_key, [0u8; 32]);
        assert_ne!(h.fts_key, [0u8; 32]);
    }
}
