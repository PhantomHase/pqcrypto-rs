# Introduction

Welcome to **PQCrypto-RS**, a Post-Quantum Cryptography workspace library in Rust implementing the latest FIPS quantum-resistant cryptographic algorithms.

## Standards Supported
This library implements the final draft standards published by NIST:
1. **FIPS 203 (ML-KEM)**: Module-Lattice Key Encapsulation Mechanism. Standardizes ML-KEM-768 for quantum-safe key exchange.
2. **FIPS 204 (ML-DSA)**: Module-Lattice Digital Signature Algorithm. Standardizes ML-DSA-65 for secure, lattice-based digital signatures.
3. **FIPS 205 (SLH-DSA)**: Stateless Hash-Based Digital Signature Algorithm. Standardizes SLH-DSA-SHA2-128s, a highly secure, stateless hash-based signature scheme.

## Design Philosophy
- **Forbid Unsafe**: The workspace is built entirely under `#![forbid(unsafe_code)]` to prevent memory safety issues.
- **Constant-Time Operations**: Uses constant-time math operations and comparisons (via the `subtle` crate) to protect against timing side-channel attacks.
- **Zeroization**: Securely cleans up secret variables and memory structures when they go out of scope using the `zeroize` crate.
- **Cross-Platform & WASM**: Supports standard execution on Unix and Windows, along with WebAssembly target support for browser environments.
