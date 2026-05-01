# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet

### Changed
- Nothing yet

### Fixed
- Nothing yet

## [0.1.0] - 2026-05-01

### Added

#### pqcrypto-core (Core Primitives)
- Polynomial arithmetic in Z_q[X]/(X^256+1) with q = 3329
- Schoolbook polynomial multiplication O(n²)
- Centered Binomial Distribution (CBD) sampling for ML-KEM
- Barrett and Montgomery modular reduction
- SHAKE-128, SHAKE-256, SHA3-256, SHA3-512 hash functions
- HKDF-SHA256 key derivation
- PRF (Pseudorandom Function) for ML-KEM

#### pqcrypto-kem (ML-KEM-768)
- ML-KEM-768 key generation (FIPS 203)
- ML-KEM-768 encapsulation and decapsulation
- CPAPKE (CPA-secure public-key encryption)
- Fujisaki-Okamoto transform for CCA security
- Hybrid encryption: ML-KEM + AES-256-GCM
- Public key and secret key serialization (12-bit encoding)
- Constant-time ciphertext comparison

#### pqcrypto-sign (ML-DSA-65)
- ML-DSA-65 key generation (FIPS 204)
- ML-DSA-65 polynomial operations with q = 8,380,417
- Power2Round decomposition
- SampleInBall challenge polynomial generation
- Matrix A generation from seed
- SLH-DSA stub implementation (FIPS 205)

#### pqcrypto-cli (CLI Tool)
- `keygen` subcommand for ML-KEM and ML-DSA key generation
- `kem-encrypt` and `kem-decrypt` for hybrid encryption
- `sign` and `verify` for digital signatures
- File-based key and ciphertext I/O

#### Infrastructure
- Cargo workspace with 4 crates
- GitHub Actions CI/CD pipeline
- Security audit workflow (cargo-audit, cargo-deny)
- Benchmark tracking with Criterion
- Code coverage with cargo-tarpaulin
- Dependabot configuration
- Issue and PR templates
- CODEOWNERS file
- SECURITY.md policy

### Security
- `#![forbid(unsafe_code)]` on all crates
- Zeroization of secret keys via Drop trait
- Constant-time comparisons via subtle crate

### Known Issues
- KEM round-trip fails due to lossy compression (test ignored)
- ML-DSA signing incomplete (power2round/sample_in_ball issues)
- Polynomial multiplication is O(n²) (NTT optimization planned)

[0.1.0]: https://github.com/omarf/pqcrypto-rs/releases/tag/v0.1.0
