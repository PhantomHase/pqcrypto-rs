# ML-KEM-768 (FIPS 203)

ML-KEM is a Module-Lattice Key Encapsulation Mechanism standard. This implementation targets the **ML-KEM-768** parameter set, providing 128 bits of post-quantum security (equivalent to AES-128 security levels).

## Parameters
- \\(k\\) = 3 (Module dimension)
- \\(q\\) = 3329 (Prime modulus)
- \\(\eta_1\\) = 2 (Noise parameter)
- \\(\eta_2\\) = 2 (Noise parameter)
- \\(d_u\\) = 10 (Compression parameter)
- \\(d_v\\) = 4 (Compression parameter)
- Public Key Size: 1184 bytes
- Secret Key Size: 2400 bytes
- Ciphertext Size: 1088 bytes
- Shared Secret Size: 32 bytes

## Features
- **Negacyclic NTT**: Employs an \\(O(n \\log n)\\) negacyclic Number Theoretic Transform (NTT) for fast polynomial multiplication.
- **Barrett & Montgomery Reduction**: Provides constant-time modular arithmetic.
- **Centered Binomial Distribution (CBD)**: Uniform binomial noise sampling for lattice secrets.

## Rust Usage
```rust
use pqcrypto_kem::api::{keygen, encapsulate, decapsulate};

// 1. Generate key pair
let (public_key, secret_key) = keygen();

// 2. Encapsulate shared secret using the public key
let (ciphertext, shared_secret_sender) = encapsulate(&public_key).unwrap();

// 3. Decapsulate shared secret using the secret key
let shared_secret_receiver = decapsulate(&secret_key, &ciphertext).unwrap();

assert_eq!(shared_secret_sender, shared_secret_receiver);
```
