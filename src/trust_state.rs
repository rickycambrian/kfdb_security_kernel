//! TEE trust posture and release decision types.
//!
//! Controls trust posture for TEE-encrypted deployments.
//! Determines whether the server should enforce TEE platform requirements.
//!
//! The release guard gates data release paths (decryption of node properties,
//! session fields, etc.) with trust-level awareness. In **Audit** mode it
//! always allows release but records when the decision *would* block in Enforced
//! mode.

use serde::{Deserialize, Serialize};

/// Trust posture levels for TEE enforcement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustPosture {
    /// No TEE checks — any environment allowed (development default).
    Permissive,
    /// Log warnings when TEE is missing but allow operation.
    Audit,
    /// Require TEE platform — refuse to serve without it.
    Enforced,
}

impl std::fmt::Display for TrustPosture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustPosture::Permissive => write!(f, "Permissive"),
            TrustPosture::Audit => write!(f, "Audit"),
            TrustPosture::Enforced => write!(f, "Enforced"),
        }
    }
}

impl std::str::FromStr for TrustPosture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "permissive" => Ok(TrustPosture::Permissive),
            "audit" => Ok(TrustPosture::Audit),
            "enforced" => Ok(TrustPosture::Enforced),
            other => Err(format!(
                "Unknown trust posture '{}' (expected: permissive, audit, enforced)",
                other
            )),
        }
    }
}

/// Trust state derived from the current key source at decision time.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustState {
    /// Key sourced from TPM/PCR — hardware-rooted trust.
    Trusted,
    /// Key present but from a non-TPM source (env fallback, legacy).
    Degraded,
    /// No encryption key available.
    Unavailable,
}

impl std::fmt::Display for TrustState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustState::Trusted => write!(f, "trusted"),
            TrustState::Degraded => write!(f, "degraded"),
            TrustState::Unavailable => write!(f, "unavailable"),
        }
    }
}

/// Result of a release guard decision on a data release path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseDecision {
    /// Whether the data release is allowed.
    pub allowed: bool,
    /// Whether this would block in Enforced mode (observability for Audit).
    pub would_block_if_enforced: bool,
    /// Current trust state at decision time.
    pub state: TrustState,
    /// Human-readable reason for the decision.
    pub reason: String,
}

impl ReleaseDecision {
    /// Create a decision that allows release unconditionally.
    pub fn allow(state: TrustState, reason: impl Into<String>) -> Self {
        Self {
            allowed: true,
            would_block_if_enforced: false,
            state,
            reason: reason.into(),
        }
    }

    /// Create a decision that blocks release.
    pub fn block(state: TrustState, reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            would_block_if_enforced: true,
            state,
            reason: reason.into(),
        }
    }

    /// Create an audit decision: allowed now, but would block if enforced.
    pub fn audit(state: TrustState, reason: impl Into<String>) -> Self {
        Self {
            allowed: true,
            would_block_if_enforced: true,
            state,
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_posture_display() {
        assert_eq!(TrustPosture::Permissive.to_string(), "Permissive");
        assert_eq!(TrustPosture::Audit.to_string(), "Audit");
        assert_eq!(TrustPosture::Enforced.to_string(), "Enforced");
    }

    #[test]
    fn test_trust_posture_from_str() {
        assert_eq!("permissive".parse::<TrustPosture>().unwrap(), TrustPosture::Permissive);
        assert_eq!("audit".parse::<TrustPosture>().unwrap(), TrustPosture::Audit);
        assert_eq!("enforced".parse::<TrustPosture>().unwrap(), TrustPosture::Enforced);
        // Case insensitive
        assert_eq!("AUDIT".parse::<TrustPosture>().unwrap(), TrustPosture::Audit);
        assert_eq!("Enforced".parse::<TrustPosture>().unwrap(), TrustPosture::Enforced);
    }

    #[test]
    fn test_trust_posture_from_str_invalid() {
        let result = "unknown".parse::<TrustPosture>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown"));
    }

    #[test]
    fn test_trust_state_display() {
        assert_eq!(TrustState::Trusted.to_string(), "trusted");
        assert_eq!(TrustState::Degraded.to_string(), "degraded");
        assert_eq!(TrustState::Unavailable.to_string(), "unavailable");
    }

    #[test]
    fn test_trust_posture_serialize() {
        let json = serde_json::to_string(&TrustPosture::Audit).unwrap();
        assert_eq!(json, "\"Audit\"");
        let back: TrustPosture = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TrustPosture::Audit);
    }

    #[test]
    fn test_trust_state_serialize() {
        let json = serde_json::to_string(&TrustState::Trusted).unwrap();
        let back: TrustState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TrustState::Trusted);
    }

    #[test]
    fn test_release_decision_allow() {
        let d = ReleaseDecision::allow(TrustState::Trusted, "TPM verified");
        assert!(d.allowed);
        assert!(!d.would_block_if_enforced);
        assert_eq!(d.state, TrustState::Trusted);
        assert_eq!(d.reason, "TPM verified");
    }

    #[test]
    fn test_release_decision_block() {
        let d = ReleaseDecision::block(TrustState::Unavailable, "no key");
        assert!(!d.allowed);
        assert!(d.would_block_if_enforced);
        assert_eq!(d.state, TrustState::Unavailable);
    }

    #[test]
    fn test_release_decision_audit() {
        let d = ReleaseDecision::audit(TrustState::Degraded, "env key fallback");
        assert!(d.allowed);
        assert!(d.would_block_if_enforced);
        assert_eq!(d.state, TrustState::Degraded);
    }

    #[test]
    fn test_release_decision_serialize() {
        let d = ReleaseDecision {
            allowed: true,
            would_block_if_enforced: false,
            state: TrustState::Trusted,
            reason: "ok".to_string(),
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("allowed"));
        assert!(json.contains("Trusted"));
    }
}
