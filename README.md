# kfdb-security-kernel

Public, auditable security kernel for [KnowledgeFlowDB](https://knowledgeflowdb.org).

This crate contains the cryptographic primitives that power KFDB's zero-knowledge
graph encryption. It is published publicly so users can verify that the TEE
(Trusted Execution Environment) running KnowledgeFlowDB uses exactly this code —
nothing more, nothing hidden.

## What This Crate Is

A standalone Rust library with **zero dependency on private KFDB code**. All
operations work on raw `&[u8]` bytes. No HTTP handlers, no database access, no
middleware — pure cryptography.

## Modules

| Module | Purpose |
|--------|---------|
| `encryption` | AES-256-GCM encrypt/decrypt on raw byte slices |
| `wire_format` | Prefix constants + parsing for encrypted storage strings |
| `key_hierarchy` | HKDF-SHA256 domain-separated key derivation |
| `key_registry` | Versioned key metadata (no secrets stored) |
| `sign_to_derive` | SHA-256(r\|\|s\|\|v) key derivation from ECDSA signatures |
| `trust_state` | TEE trust posture and release decision types |

## Dependencies

```
aes-gcm   0.10   — AES-256-GCM authenticated encryption
sha2      0.10   — SHA-256 for key derivation
hkdf      0.12   — HKDF-SHA256 for sub-key expansion
hmac      0.12   — HMAC-SHA256
zeroize   1.7    — Zero key memory on drop
base64    0.21   — Wire format encoding
serde     1.0    — Serialization (registry types)
serde_json 1.0   — JSON for registry endpoints
```

No `kfdb-*` crates. No networking. No I/O.

## Verification

Anyone can verify that the KFDB TEE runs this exact code:

**Step 1 — Clone and test:**
```bash
git clone https://github.com/rickycambrian/kfdb_security_kernel.git
cd kfdb_security_kernel
cargo test
# Expected: 64 tests pass, 0 failures
```

**Step 2 — Compute source fingerprint:**
```bash
find src -name '*.rs' | sort | xargs cat | sha256sum
```

**Step 3 — Compare with live TEE attestation:**
```bash
curl https://knowledgeflowdb.org/api/v1/security/verify | jq .kernel_sha256
```

The SHA-256 output from Step 2 must match the `kernel_sha256` field from Step 3.
If they match, the TEE is running exactly the code you audited.

**Step 4 — Visit the verification page:**

https://knowledgeflowdb.org/security

## Usage

```rust
use kfdb_security_kernel::{encrypt_bytes, decrypt_bytes, KeyHierarchy, derive_key_from_signature};

// Derive key hierarchy from a root key
let root_key = [0u8; 32]; // use a real key in production
let hierarchy = KeyHierarchy::from_root_key(&root_key);

// Encrypt arbitrary bytes
let ciphertext = encrypt_bytes(&hierarchy.graph_key, b"hello world").unwrap();

// Decrypt
let plaintext = decrypt_bytes(&hierarchy.graph_key, &ciphertext).unwrap();
assert_eq!(plaintext, b"hello world");

// Sign-to-derive: derive key from wallet signature
let sig_bytes = [0u8; 65]; // 65-byte Ethereum signature
let user_key = derive_key_from_signature(&sig_bytes);
```

## License

Confluent Software License 1.0. See [LICENSE](LICENSE).

Audit and verification use is explicitly permitted. See Section 2(c).
