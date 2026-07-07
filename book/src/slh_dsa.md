# SLH-DSA-SHA2-128s (FIPS 205)

SLH-DSA is a Stateless Hash-Based Digital Signature Algorithm standard (formerly SPHINCS+). This implementation uses the **SLH-DSA-SHA2-128s** parameter set.

## Parameters
- Security parameter \\(n\\) = 16 bytes (128-bit security)
- Hypertree height \\(h\\) = 63
- Hypertree layers \\(d\\) = 7
- XMSS tree height \\(h'\\) = 9
- FORS trees \\(a\\) = 12
- FORS leaves per tree \\(k\\) = 14
- Winternitz parameter \\(w\\) = 16
- Public Key Size: 32 bytes
- Secret Key Size: 64 bytes
- Signature Size: 7836 bytes

## Key Architectural Features
- **WOTS+ (Winternitz One-Time Signatures)**: One-time signature scheme used as Merkle leaves.
- **FORS (Forest of Random Subsets)**: Keyed hashes representing the message digest tree.
- **Hypertree Structure**: A tree of Merkle trees resolving leaves down to a root.
- **Message-Derived Indices**: Derives hypertree `tree_idx` and `leaf_idx` dynamically from the message hash via `h_msg` to avoid hardcoded fixed indices and maintain stateless integrity.

## Rust Usage
```rust
use pqcrypto_sign::slh_dsa::{keygen, sign, verify};

// 1. Generate key pair
let (public_key, secret_key) = keygen();

// 2. Sign message
let message = b"Critical instruction payload";
let signature = sign(&secret_key, message);

// 3. Verify signature
let is_valid = verify(&public_key, message, &signature);
assert!(is_valid);
```
