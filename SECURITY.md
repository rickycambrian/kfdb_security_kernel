# Security Model

This document describes the cryptographic model implemented in `kfdb-security-kernel`.

## Cryptographic Primitives

| Primitive | Algorithm | Purpose |
|-----------|-----------|---------|
| Symmetric encryption | AES-256-GCM | Property-level encryption |
| Key derivation | HKDF-SHA256 | Domain-separated sub-keys |
| Signature hashing | SHA-256 | Sign-to-derive root key |
| Authentication | GCM tag (128-bit) | Ciphertext integrity |
| Nonce | 12 bytes, random (OsRng) | Per-encryption uniqueness |

## Key Hierarchy

```
Root Key (32 bytes)
  |
  +-- HKDF("kfdb-graph-key-v1")    --> Graph Key    [node/edge properties]
  +-- HKDF("kfdb-vector-key-v1")   --> Vector Key   [embedding vectors]
  +-- HKDF("kfdb-fts-key-v1")      --> FTS Key      [full-text search tokens]
  +-- HKDF("kfdb-property-key-v1:{name}") --> Property Key [per-property]
```

Each sub-key is cryptographically independent via HKDF domain separation. Compromise
of one sub-key does not reveal any other sub-key or the root key.

## Sign-to-Derive

For wallet-based (user-controlled) encryption:

```
Ethereum ECDSA Signature (65 bytes: r[32] || s[32] || v[1])
  |
  +-- SHA-256(r || s || v) --> Root Key (32 bytes)
  |
  +-- KeyHierarchy::from_root_key(root_key) --> full hierarchy
```

The server **never receives the derived key**. The user's wallet signs a
deterministic challenge; the key is derived client-side. Different challenges
produce different keys; different `v` values produce different keys.

## Wire Format

Encrypted values are stored as strings with type-tagged prefixes:

| Format | Pattern | Notes |
|--------|---------|-------|
| Server v1 | `__enc_v1_{type}:{base64}` | Implicit key version k1 |
| Server v2 | `__enc_v2_k{N}.{type}:{base64}` | Explicit key version for rotation |
| Legacy | `__enc_{type}:{base64}` | Pre-versioning, read-only |
| Client v1 | `__cenc_v1_{type}:{base64}` | SDK-encrypted, implicit k1 |
| Client v2 | `__cenc_v2_k{N}.{type}:{base64}` | SDK-encrypted, explicit version |

**Type tags:** `str`, `int`, `float`, `bool`, `vec`, `arr`, `obj`, `null`

**Payload layout (base64-decoded):**
```
nonce (12 bytes) || ciphertext (variable) || GCM tag (16 bytes)
```

Total overhead per encrypted value: 12 (nonce) + 16 (tag) + base64 expansion (~33%).

## Trust State Model

| State | Meaning |
|-------|---------|
| `Trusted` | Encryption key sourced from TPM/PCR — hardware-rooted trust |
| `Degraded` | Key present but from non-TPM source (env var fallback) |
| `Unavailable` | No encryption key — cannot serve encrypted data |

Trust posture controls enforcement:

| Posture | Behavior |
|---------|----------|
| `Permissive` | No TEE checks, any environment allowed |
| `Audit` | Allow release, log when it would block in Enforced mode |
| `Enforced` | Refuse to serve without verified TEE platform |

## What This Kernel Does NOT Include

- No HTTP handlers or API routes
- No database access (ScyllaDB, ClickHouse)
- No middleware or request processing
- No authentication or session management
- No key storage or secret management
- No network I/O of any kind

The kernel is a pure function library. The KFDB server wires these primitives
into its storage and API layers.

## Key Management Notes

- Keys are zeroized on drop (`KeyHierarchy` implements `Drop` with `fill(0)`)
- The `KeyRegistry` stores ONLY public metadata (no key material)
- Server keys are derived at runtime via HKDF from a master secret (K8s Secret / TPM)
- User keys are never sent to or stored by the server
- Key rotation is safe via v2 wire format (explicit key version tag per ciphertext)

## Reporting Security Issues

Contact: https://x.com/rickydata42
