# ML-DSA-65 (FIPS 204)

ML-DSA is a Module-Lattice Digital Signature Algorithm standard. This implementation targets the **ML-DSA-65** parameter set, providing excellent speed and signature size balance.

## Parameters
- \\(k\\) = 6 (Module dimension)
- \\(l\\) = 5 (Module dimension)
- \\(q\\) = 8380417 (Prime modulus)
- \\(\eta\\) = 4 (Coefficient bound for secret vectors)
- \\(\\beta\\) = 78 (Challenge weight)
- \\(\\omega\\) = 60 (Hint weight bound)
- Public Key Size: 1952 bytes
- Secret Key Size: 2912 bytes
- Signature Size: 6688 bytes

## Compliance & Security Features
- **Strict Deserialization Verification**: Enforces exact length constraints and bounds checks on deserialized secret keys to prevent malformed key attacks.
- **FIPS 204 MakeHint / UseHint**: Employs the standardized hint mechanisms to reduce signature size without leaking high bits of the key coefficients.
- **Uniform Rejection Sampling**: Implements the standardized rejection sampling loop with 4-bit nibbles for \\(\\eta = 4\\) coefficient generation (`sample_eta`).

## Rust Usage
```rust
use pqcrypto_sign::api::{keygen, sign, verify};

// 1. Generate key pair
let (public_key, secret_key) = keygen();

// 2. Sign message using secret key
let message = b"Transaction data payload";
let signature = sign(&secret_key, message);

// 3. Verify signature using public key
let is_valid = verify(&public_key, message, &signature);
assert!(is_valid);
```
