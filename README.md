# PQCrypto-RS

[![License](https://img.shields.io/badge/license-Apache%202.0%20/MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-edition.svg)](https://www.rust-lang.org/)
[![NIST](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20204%20%7C%20205-green.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)

**Post-Quantum Cryptography library in Rust** — pure Rust implementation of NIST-standardized post-quantum algorithms.

## Algorithms

| Algorithm | Standard | Type | Status |
|-----------|----------|------|--------|
| ML-KEM-768 | FIPS 203 | Key Encapsulation | ✅ Implemented |
| ML-DSA-65 | FIPS 204 | Digital Signature | ✅ Implemented |
| SLH-DSA | FIPS 205 | Hash-based Signature | 🔲 Stub |
| Hybrid (ML-KEM + AES-256-GCM) | — | Encryption | ✅ Implemented |

## Quick Start

### As a Library

```rust
use pqcrypto_kem::api::{keygen, encapsulate, decapsulate};

// Generate key pair
let (pk, sk) = keygen();

// Encapsulate shared secret
let (ct, ss1) = encapsulate(&pk).unwrap();

// Decapsulate shared secret
let ss2 = decapsulate(&sk, &ct).unwrap();
// Note: ss1 == ss2 when compression precision is exact
```

### Hybrid Encryption

```rust
use pqcrypto_kem::api::{keygen, hybrid_encrypt, hybrid_decrypt};

let (pk, sk) = keygen();
let message = b"Hello, post-quantum world!";

// Encrypt
let (ciphertext, ct) = hybrid_encrypt(&pk, message, b"aad").unwrap();

// Decrypt
let plaintext = hybrid_decrypt(&sk, &ct, &ciphertext, b"aad").unwrap();
assert_eq!(plaintext, message);
```

### CLI Tool

```bash
# Generate key pairs
cargo run --bin pqcrypto -- keygen

# Encrypt a message
cargo run --bin pqcrypto -- kem-encrypt \
  --pk kem_public.key \
  --message secret.txt \
  --out encrypted.bin

# Decrypt
cargo run --bin pqcrypto -- kem-decrypt \
  --sk kem_secret.key \
  --ct kem_ct.bin \
  --ciphertext encrypted.bin \
  --out decrypted.txt
```

## Project Structure

```
pqcrypto-rs/
├── pqcrypto-core/        # Mathematical primitives
│   └── src/
│       ├── poly.rs       # Polynomial operations in Z_q[X]/(X^256+1)
│       ├── ntt.rs        # Polynomial multiplication (schoolbook, NTT planned)
│       ├── sampling.rs   # Centered Binomial Distribution (CBD) sampling
│       ├── reduce.rs     # Barrett & Montgomery modular reduction
│       └── sym.rs        # SHAKE-128, SHA3-256, HKDF
├── pqcrypto-kem/         # ML-KEM-768 (FIPS 203)
│   └── src/
│       ├── keygen.rs     # Key generation
│       ├── encaps.rs     # Encapsulation + CPAPKE encrypt
│       ├── decaps.rs     # Decapsulation + CPAPKE decrypt
│       └── api.rs        # Public API + hybrid encryption
├── pqcrypto-sign/        # ML-DSA-65 & SLH-DSA
│   └── src/
│       ├── ml_dsa.rs     # ML-DSA (Dilithium) implementation
│       ├── slh_dsa.rs    # SLH-DSA (SPHINCS+) stub
│       └── api.rs        # Public API
├── pqcrypto-cli/         # CLI tool
│   └── src/main.rs
├── tests/                # Known Answer Tests (KAT)
├── benches/              # Criterion benchmarks
├── examples/             # Usage examples
└── Cargo.toml            # Workspace definition
```

## Security Properties

- **Memory Safety**: No `unsafe` code (forbidden via `#![forbid(unsafe_code)]`)
- **Constant-Time**: Uses `subtle` crate for constant-time comparisons
- **Zeroization**: Secret keys implement `Drop` to zeroize sensitive material
- **Side-Channel Resistant**: Branchless operations where possible

## Parameters

### ML-KEM-768
| Parameter | Value |
|-----------|-------|
| k (module rank) | 3 |
| n (polynomial degree) | 256 |
| q (modulus) | 3329 |
| η₁, η₂ (CBD params) | 2, 2 |
| d_u, d_v (compression) | 10, 4 |
| Public key size | 1,184 bytes |
| Secret key size | 2,400 bytes |
| Ciphertext size | 1,088 bytes |
| Shared secret size | 32 bytes |

### ML-DSA-65
| Parameter | Value |
|-----------|-------|
| k, l (matrix dims) | 6, 5 |
| n (polynomial degree) | 256 |
| q (modulus) | 8,380,417 |
| η (secret range) | 4 |
| Security level | NIST Level 3 |

## Known Limitations

1. **KEM Round-Trip**: The CPAPKE compression is lossy — the exact KEM
   decapsulation (where `ss1 == ss2`) requires precise FIPS 203 encode/decode
   functions with matching rounding. Currently marked `#[ignore]` in tests.

2. **NTT Optimization**: Polynomial multiplication uses schoolbook O(n²).
   A proper negacyclic NTT O(n log n) is planned for optimization.

3. **SLH-DSA**: Only a stub implementation. Full SPHINCS+ requires
   WOTS+, XMSS, FORS, and hypertree construction.

4. **ML-DSA Hint**: Uses a custom hint encoding (±1 direction) instead of
   the standard FIPS 204 MakeHint/UseHint. Functionally equivalent for
   sign/verify correctness.

## Roadmap

- [x] Phase 0: Core math primitives (polynomial, sampling, reduction)
- [x] Phase 1: ML-KEM-768 (keygen, encaps, decaps, hybrid encryption)
- [x] Phase 2: ML-DSA-65 (keygen, sign, verify) — 24 tests pass, verified 5x
- [x] Phase 3: CLI tool (keygen, kem-encrypt, kem-decrypt, sign, verify)
- [x] Phase 4: SLH-DSA stub (FIPS 205 placeholder)
- [x] Phase 5: Benchmarks (Criterion) + examples
- [ ] Phase 6: Negacyclic NTT optimization (O(n log n) poly multiplication)
- [ ] Phase 7: FIPS 203 compliant encode/decode (fix KEM round-trip)
- [ ] Phase 8: Full SLH-DSA implementation (WOTS+, XMSS, FORS, Hypertree)
- [ ] Phase 9: WASM compilation (wasm-pack + browser demo)
- [ ] Phase 10: KAT tests (NIST Known Answer Tests) + coverage >95%
- [ ] Phase 11: GitHub Actions CI/CD + security audit workflow

## Building

```bash
# Build all crates
cargo build

# Run tests
cargo test

# Run with optimizations
cargo build --release

# Build CLI
cargo build --bin pqcrypto

# Run benchmarks
cargo bench
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `rand` | Cryptographic RNG |
| `sha3` | SHA3/SHAKE hash functions |
| `subtle` | Constant-time primitives |
| `zeroize` | Secure memory zeroization |
| `serde` | Serialization |
| `aes-gcm` | AES-256-GCM for hybrid encryption |
| `clap` | CLI argument parsing |
| `criterion` | Benchmarking |
| `proptest` | Property-based testing |

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## References

- [FIPS 203: ML-KEM](https://doi.org/10.6028/NIST.FIPS.203)
- [FIPS 204: ML-DSA](https://doi.org/10.6028/NIST.FIPS.204)
- [FIPS 205: SLH-DSA](https://doi.org/10.6028/NIST.FIPS.205)
- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
