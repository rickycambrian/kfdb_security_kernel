//! # kfdb-security-kernel
//!
//! Public auditable security kernel for KnowledgeFlowDB.
//!
//! This crate contains the cryptographic primitives used by KFDB for zero-knowledge
//! graph encryption. It has **zero dependency on private KFDB types** — all operations
//! work on raw `&[u8]` bytes.
//!
//! ## Modules
//!
//! - [`encryption`] — AES-256-GCM encryption/decryption on raw bytes
//! - [`wire_format`] — Wire format prefix constants and parsing utilities
//! - [`key_hierarchy`] — HKDF-SHA256 key derivation hierarchy
//! - [`key_registry`] — Versioned key registry (no secrets stored)
//! - [`sign_to_derive`] — Sign-to-derive key derivation from ECDSA signatures
//! - [`trust_state`] — TEE trust posture and release decision types
//!
//! ## Security Properties
//!
//! - AES-256-GCM with random 12-byte nonces (one per encryption)
//! - HKDF-SHA256 domain separation per subsystem (graph, vector, FTS, per-property)
//! - Sign-to-derive: `SHA-256(r || s || v)` — deterministic, wallet-gated
//! - No secrets stored in the registry — only public derivation parameters
//! - Zeroize on drop for all key material

pub mod encryption;
pub mod key_hierarchy;
pub mod key_registry;
pub mod sign_to_derive;
pub mod trust_state;
pub mod wire_format;

/// Version of this crate (from Cargo.toml).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Re-export primary types for convenience
pub use encryption::{decrypt_bytes, encrypt_bytes, EncryptionError};
pub use key_hierarchy::KeyHierarchy;
pub use key_registry::{ClientKeyVersion, KeyRegistry, KeyStatus, ServerKeyVersion};
pub use sign_to_derive::derive_key_from_signature;
pub use trust_state::{ReleaseDecision, TrustPosture, TrustState};
pub use wire_format::{
    format_v1, format_v2, is_client_encrypted_str, is_encrypted_str, parse_key_version,
};
