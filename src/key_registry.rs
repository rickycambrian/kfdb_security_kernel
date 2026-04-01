//! Key version registry for versioned encryption.
//!
//! Stores derivation parameters for both server-side (HKDF) and client-side
//! (Sign-to-Derive) encryption. The registry contains NO secrets — only public
//! metadata about how keys are derived for each version.
//!
//! For client-side encryption, this is the backup: the derivation message is
//! public, but only the wallet holder can sign it to produce the AES key.

use std::collections::HashMap;
use std::sync::Arc;

/// Status of a key version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    /// New data is encrypted with this version.
    Active,
    /// Can decrypt existing data but new writes use a different version.
    DecryptOnly,
    /// Fully retired — data should have been re-encrypted.
    Retired,
}

/// Server-side key version (HKDF derivation parameters).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerKeyVersion {
    /// Short identifier embedded in wire format (e.g. "k1", "k2").
    pub id: String,
    /// HKDF info string for domain separation.
    pub hkdf_info: String,
    /// Status of this version.
    pub status: KeyStatus,
}

/// Client-side key version (Sign-to-Derive parameters).
///
/// These are PUBLIC — anyone can see the derivation message.
/// Only the wallet holder can sign it to produce the encryption key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClientKeyVersion {
    /// Short identifier embedded in wire format (e.g. "k1", "k2").
    pub id: String,
    /// The deterministic message the user signs with their wallet.
    pub derive_message: String,
    /// Hash algorithm applied to the signature.
    pub hash_algorithm: String,
    /// Encryption algorithm used with the derived key.
    pub cipher_algorithm: String,
    /// Status of this version.
    pub status: KeyStatus,
}

/// Registry of all key versions for both encryption layers.
#[derive(Debug, Clone)]
pub struct KeyRegistry {
    server_versions: HashMap<String, ServerKeyVersion>,
    client_versions: HashMap<String, ClientKeyVersion>,
    active_server_id: String,
    active_client_id: String,
}

impl KeyRegistry {
    /// Create a registry with the compiled-in defaults (k1 for both layers).
    /// This always works — no config dependency.
    pub fn defaults() -> Self {
        let mut server_versions = HashMap::new();
        server_versions.insert(
            "k1".to_string(),
            ServerKeyVersion {
                id: "k1".to_string(),
                hkdf_info: "kfdb-tenant-encryption-v1".to_string(),
                status: KeyStatus::Active,
            },
        );

        let mut client_versions = HashMap::new();
        client_versions.insert(
            "k1".to_string(),
            ClientKeyVersion {
                id: "k1".to_string(),
                derive_message: "KFDB Encryption Key\nVersion: 1\nChain: 8453".to_string(),
                hash_algorithm: "sha256".to_string(),
                cipher_algorithm: "AES-256-GCM".to_string(),
                status: KeyStatus::Active,
            },
        );

        Self {
            server_versions,
            client_versions,
            active_server_id: "k1".to_string(),
            active_client_id: "k1".to_string(),
        }
    }

    /// Get the active server key version.
    pub fn active_server(&self) -> Option<&ServerKeyVersion> {
        self.server_versions.get(&self.active_server_id)
    }

    /// Get the active server key version ID.
    pub fn active_server_id(&self) -> &str {
        &self.active_server_id
    }

    /// Get the active client key version ID.
    pub fn active_client_id(&self) -> &str {
        &self.active_client_id
    }

    /// Look up a server key version by ID.
    pub fn server_version(&self, id: &str) -> Option<&ServerKeyVersion> {
        self.server_versions.get(id)
    }

    /// Look up a client key version by ID.
    pub fn client_version(&self, id: &str) -> Option<&ClientKeyVersion> {
        self.client_versions.get(id)
    }

    /// Get all server version IDs.
    pub fn server_version_ids(&self) -> Vec<String> {
        self.server_versions.keys().cloned().collect()
    }

    /// Get all client versions (for the public API endpoint).
    pub fn client_versions(&self) -> &HashMap<String, ClientKeyVersion> {
        &self.client_versions
    }

    /// Add a server key version (for runtime loading from env/config).
    pub fn add_server_version(&mut self, version: ServerKeyVersion) {
        if version.status == KeyStatus::Active {
            // Demote current active to DecryptOnly
            if let Some(prev) = self.server_versions.get_mut(&self.active_server_id) {
                prev.status = KeyStatus::DecryptOnly;
            }
            self.active_server_id = version.id.clone();
        }
        self.server_versions.insert(version.id.clone(), version);
    }

    /// Add a client key version.
    pub fn add_client_version(&mut self, version: ClientKeyVersion) {
        if version.status == KeyStatus::Active {
            if let Some(prev) = self.client_versions.get_mut(&self.active_client_id) {
                prev.status = KeyStatus::DecryptOnly;
            }
            self.active_client_id = version.id.clone();
        }
        self.client_versions.insert(version.id.clone(), version);
    }

    /// Wrap in Arc for shared ownership across threads.
    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }
}

impl Default for KeyRegistry {
    fn default() -> Self {
        Self::defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_have_k1() {
        let reg = KeyRegistry::defaults();
        assert_eq!(reg.active_server_id(), "k1");
        assert_eq!(reg.active_client_id(), "k1");

        let sv = reg.server_version("k1").unwrap();
        assert_eq!(sv.hkdf_info, "kfdb-tenant-encryption-v1");
        assert_eq!(sv.status, KeyStatus::Active);

        let cv = reg.client_version("k1").unwrap();
        assert!(cv.derive_message.contains("Version: 1"));
        assert_eq!(cv.status, KeyStatus::Active);
    }

    #[test]
    fn test_add_server_version_demotes_active() {
        let mut reg = KeyRegistry::defaults();
        reg.add_server_version(ServerKeyVersion {
            id: "k2".to_string(),
            hkdf_info: "kfdb-tenant-encryption-v2".to_string(),
            status: KeyStatus::Active,
        });

        assert_eq!(reg.active_server_id(), "k2");
        assert_eq!(
            reg.server_version("k1").unwrap().status,
            KeyStatus::DecryptOnly
        );
        assert_eq!(
            reg.server_version("k2").unwrap().status,
            KeyStatus::Active
        );
    }

    #[test]
    fn test_add_decrypt_only_doesnt_change_active() {
        let mut reg = KeyRegistry::defaults();
        reg.add_server_version(ServerKeyVersion {
            id: "k2".to_string(),
            hkdf_info: "kfdb-tenant-encryption-v2".to_string(),
            status: KeyStatus::DecryptOnly,
        });

        assert_eq!(reg.active_server_id(), "k1");
        assert_eq!(
            reg.server_version("k1").unwrap().status,
            KeyStatus::Active
        );
    }

    #[test]
    fn test_client_versions_serializable() {
        let reg = KeyRegistry::defaults();
        let json = serde_json::to_string(reg.client_versions()).unwrap();
        assert!(json.contains("KFDB Encryption Key"));
        assert!(json.contains("sha256"));
    }

    #[test]
    fn test_active_server_returns_version() {
        let reg = KeyRegistry::defaults();
        let sv = reg.active_server().unwrap();
        assert_eq!(sv.id, "k1");
    }

    #[test]
    fn test_server_version_ids() {
        let mut reg = KeyRegistry::defaults();
        reg.add_server_version(ServerKeyVersion {
            id: "k2".to_string(),
            hkdf_info: "info".to_string(),
            status: KeyStatus::DecryptOnly,
        });
        let ids = reg.server_version_ids();
        assert!(ids.contains(&"k1".to_string()));
        assert!(ids.contains(&"k2".to_string()));
    }

    #[test]
    fn test_into_arc() {
        let reg = KeyRegistry::defaults();
        let arc = reg.into_arc();
        assert_eq!(arc.active_server_id(), "k1");
    }

    #[test]
    fn test_default_trait() {
        let reg = KeyRegistry::default();
        assert_eq!(reg.active_server_id(), "k1");
    }
}
