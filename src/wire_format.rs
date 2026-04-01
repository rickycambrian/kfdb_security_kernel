//! Wire format constants and parsing utilities for KFDB encrypted values.
//!
//! KFDB uses typed, versioned wire format strings to store encrypted properties
//! in ScyllaDB. The format encodes the encryption layer (server vs. client), the
//! key version (for safe rotation), and the original value type so it can be
//! restored on decryption.
//!
//! ## Format Reference
//!
//! | Format | Pattern | Notes |
//! |--------|---------|-------|
//! | v1 (server) | `__enc_v1_{type}:{base64}` | Implicit key version k1 |
//! | v2 (server) | `__enc_v2_k{N}.{type}:{base64}` | Explicit key version |
//! | Legacy | `__enc_{type}:{base64}` | Pre-versioning, read-only |
//! | Client v1 | `__cenc_v1_{type}:{base64}` | Implicit key version k1 |
//! | Client v2 | `__cenc_v2_k{N}.{type}:{base64}` | Explicit key version |
//!
//! ## Type Tags
//!
//! | Tag | Original type |
//! |-----|---------------|
//! | `str` | UTF-8 string |
//! | `int` | 64-bit signed integer |
//! | `float` | 64-bit float |
//! | `bool` | Boolean |
//! | `vec` | f32 vector (embedding) |
//! | `arr` | JSON array |
//! | `obj` | JSON object |
//! | `null` | Null |

// ── Server-side prefix constants ──

/// v1 server prefix (implicit key version k1): `__enc_v1_`
pub const ENC_PREFIX_V1: &str = "__enc_v1_";

/// v2 server prefix (explicit key version): `__enc_v2_`
pub const ENC_PREFIX_V2: &str = "__enc_v2_";

/// Legacy server prefix (pre-versioning, read-only): `__enc_`
pub const ENC_PREFIX_LEGACY: &str = "__enc_";

// ── Client-side prefix constants ──

/// v1 client prefix (implicit key version k1): `__cenc_v1_`
pub const CLIENT_ENC_PREFIX_V1: &str = "__cenc_v1_";

/// v2 client prefix (explicit key version): `__cenc_v2_`
pub const CLIENT_ENC_PREFIX_V2: &str = "__cenc_v2_";

// ── Type tag constants ──

pub const TYPE_STR: &str = "str";
pub const TYPE_INT: &str = "int";
pub const TYPE_FLOAT: &str = "float";
pub const TYPE_BOOL: &str = "bool";
pub const TYPE_VEC: &str = "vec";
pub const TYPE_ARR: &str = "arr";
pub const TYPE_OBJ: &str = "obj";
pub const TYPE_NULL: &str = "null";

/// Format a v1 encrypted string (implicit key version k1).
///
/// Output: `__enc_v1_{type_tag}:{b64}`
pub fn format_v1(type_tag: &str, b64: &str) -> String {
    format!("{ENC_PREFIX_V1}{type_tag}:{b64}")
}

/// Format a v2 encrypted string (explicit key version).
///
/// Output: `__enc_v2_{key_version}.{type_tag}:{b64}`
///
/// Example: `format_v2("k1", "str", "abc...")` → `__enc_v2_k1.str:abc...`
pub fn format_v2(key_version: &str, type_tag: &str, b64: &str) -> String {
    format!("{ENC_PREFIX_V2}{key_version}.{type_tag}:{b64}")
}

/// Format a client v1 encrypted string.
///
/// Output: `__cenc_v1_{type_tag}:{b64}`
pub fn format_client_v1(type_tag: &str, b64: &str) -> String {
    format!("{CLIENT_ENC_PREFIX_V1}{type_tag}:{b64}")
}

/// Format a client v2 encrypted string.
///
/// Output: `__cenc_v2_{key_version}.{type_tag}:{b64}`
pub fn format_client_v2(key_version: &str, type_tag: &str, b64: &str) -> String {
    format!("{CLIENT_ENC_PREFIX_V2}{key_version}.{type_tag}:{b64}")
}

/// Parse the key version from an encrypted wire format string.
///
/// Returns:
/// - `None` — the string is not encrypted (no recognized prefix)
/// - `Some("k1")` — v1, legacy, or client-v1 (implicit key version k1)
/// - `Some("k2")` etc. — v2 or client-v2 with explicit key version
pub fn parse_key_version(s: &str) -> Option<String> {
    if let Some(after) = s.strip_prefix(ENC_PREFIX_V2) {
        // v2: `k{N}.{type}:{data}` — extract up to the dot
        let dot_pos = after.find('.')?;
        Some(after[..dot_pos].to_string())
    } else if s.starts_with(ENC_PREFIX_V1) || s.starts_with(ENC_PREFIX_LEGACY) {
        Some("k1".to_string())
    } else if let Some(after) = s.strip_prefix(CLIENT_ENC_PREFIX_V2) {
        let dot_pos = after.find('.')?;
        Some(after[..dot_pos].to_string())
    } else if s.starts_with(CLIENT_ENC_PREFIX_V1) {
        Some("k1".to_string())
    } else {
        None
    }
}

/// Parse (type_tag, base64_payload) from a server-encrypted string.
///
/// Returns `None` for non-encrypted strings or client-encrypted strings.
pub fn parse_server_encrypted(s: &str) -> Option<(&str, &str)> {
    if let Some(after) = s.strip_prefix(ENC_PREFIX_V2) {
        // v2: `k{N}.{type}:{data}`
        let dot_pos = after.find('.')?;
        let rest = &after[dot_pos + 1..];
        let colon_pos = rest.find(':')?;
        Some((&rest[..colon_pos], &rest[colon_pos + 1..]))
    } else if let Some(after) = s.strip_prefix(ENC_PREFIX_V1) {
        let colon_pos = after.find(':')?;
        Some((&after[..colon_pos], &after[colon_pos + 1..]))
    } else if let Some(after) = s.strip_prefix(ENC_PREFIX_LEGACY) {
        let colon_pos = after.find(':')?;
        Some((&after[..colon_pos], &after[colon_pos + 1..]))
    } else {
        None
    }
}

/// Returns true if the string uses any server-side or client-side encryption prefix.
pub fn is_encrypted_str(s: &str) -> bool {
    s.starts_with(ENC_PREFIX_V2)
        || s.starts_with(ENC_PREFIX_V1)
        || s.starts_with(ENC_PREFIX_LEGACY)
        || s.starts_with(CLIENT_ENC_PREFIX_V2)
        || s.starts_with(CLIENT_ENC_PREFIX_V1)
}

/// Returns true if the string uses a client-side encryption prefix (SDK-encrypted).
///
/// Client-encrypted values cannot be decrypted by the server.
pub fn is_client_encrypted_str(s: &str) -> bool {
    s.starts_with(CLIENT_ENC_PREFIX_V1) || s.starts_with(CLIENT_ENC_PREFIX_V2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_v1() {
        let s = format_v1("str", "abc123");
        assert_eq!(s, "__enc_v1_str:abc123");
        assert!(is_encrypted_str(&s));
        assert!(!is_client_encrypted_str(&s));
    }

    #[test]
    fn test_format_v2() {
        let s = format_v2("k1", "int", "xyz");
        assert_eq!(s, "__enc_v2_k1.int:xyz");
        assert!(is_encrypted_str(&s));
        assert!(!is_client_encrypted_str(&s));
    }

    #[test]
    fn test_format_client_v1() {
        let s = format_client_v1("str", "data");
        assert_eq!(s, "__cenc_v1_str:data");
        assert!(is_encrypted_str(&s));
        assert!(is_client_encrypted_str(&s));
    }

    #[test]
    fn test_format_client_v2() {
        let s = format_client_v2("k2", "bool", "data");
        assert_eq!(s, "__cenc_v2_k2.bool:data");
        assert!(is_encrypted_str(&s));
        assert!(is_client_encrypted_str(&s));
    }

    #[test]
    fn test_parse_key_version_v1() {
        let s = format_v1("str", "abc");
        assert_eq!(parse_key_version(&s), Some("k1".to_string()));
    }

    #[test]
    fn test_parse_key_version_v2_k1() {
        let s = format_v2("k1", "str", "abc");
        assert_eq!(parse_key_version(&s), Some("k1".to_string()));
    }

    #[test]
    fn test_parse_key_version_v2_k2() {
        let s = format_v2("k2", "str", "abc");
        assert_eq!(parse_key_version(&s), Some("k2".to_string()));
    }

    #[test]
    fn test_parse_key_version_legacy() {
        let s = format!("{ENC_PREFIX_LEGACY}str:abc");
        assert_eq!(parse_key_version(&s), Some("k1".to_string()));
    }

    #[test]
    fn test_parse_key_version_client_v1() {
        let s = format_client_v1("str", "abc");
        assert_eq!(parse_key_version(&s), Some("k1".to_string()));
    }

    #[test]
    fn test_parse_key_version_client_v2() {
        let s = format_client_v2("k3", "str", "abc");
        assert_eq!(parse_key_version(&s), Some("k3".to_string()));
    }

    #[test]
    fn test_parse_key_version_plaintext() {
        assert_eq!(parse_key_version("hello world"), None);
        assert_eq!(parse_key_version(""), None);
        // Note: "__enc_" IS the legacy prefix, so any string starting with it returns Some("k1").
        // Strings that don't match any known prefix return None.
        assert_eq!(parse_key_version("plaintext_value"), None);
        assert_eq!(parse_key_version("not_encrypted"), None);
    }

    #[test]
    fn test_is_encrypted_str_plaintext() {
        assert!(!is_encrypted_str("hello"));
        assert!(!is_encrypted_str(""));
        assert!(!is_encrypted_str("__not_enc_prefix"));
    }

    #[test]
    fn test_parse_server_encrypted_v1() {
        let s = format_v1("str", "payload123");
        let parsed = parse_server_encrypted(&s);
        assert_eq!(parsed, Some(("str", "payload123")));
    }

    #[test]
    fn test_parse_server_encrypted_v2() {
        let s = format_v2("k1", "int", "payload456");
        let parsed = parse_server_encrypted(&s);
        assert_eq!(parsed, Some(("int", "payload456")));
    }

    #[test]
    fn test_parse_server_encrypted_legacy() {
        let s = format!("{ENC_PREFIX_LEGACY}bool:data789");
        let parsed = parse_server_encrypted(&s);
        assert_eq!(parsed, Some(("bool", "data789")));
    }

    #[test]
    fn test_parse_server_encrypted_client_returns_none() {
        let s = format_client_v1("str", "data");
        assert_eq!(parse_server_encrypted(&s), None);
    }

    #[test]
    fn test_type_tag_constants() {
        assert_eq!(TYPE_STR, "str");
        assert_eq!(TYPE_INT, "int");
        assert_eq!(TYPE_FLOAT, "float");
        assert_eq!(TYPE_BOOL, "bool");
        assert_eq!(TYPE_VEC, "vec");
        assert_eq!(TYPE_ARR, "arr");
        assert_eq!(TYPE_OBJ, "obj");
        assert_eq!(TYPE_NULL, "null");
    }
}
