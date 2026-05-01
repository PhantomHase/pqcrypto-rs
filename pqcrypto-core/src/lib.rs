//! # pqcrypto-core
//!
//! Core mathematical primitives for post-quantum cryptography.
//!
//! This crate provides:
//! - Polynomial arithmetic in Z_q[X]/(X^n+1)
//! - Number Theoretic Transform (NTT) for fast polynomial multiplication
//! - Centered Binomial Distribution (CBD) sampling
//! - Modular reduction (Barrett, Montgomery)
//! - Symmetric primitives (SHAKE-128, SHA3-256)

#![forbid(unsafe_code)]

pub mod ntt;
pub mod poly;
pub mod reduce;
pub mod sampling;
pub mod sym;

/// Shared constant: prime modulus q = 3329 (for ML-KEM)
pub const Q: u16 = 3329;

/// Polynomial ring dimension n = 256
pub const N: usize = 256;

/// 256-th root of unity modulo q
pub const ZETA: u16 = 17;

/// Montgomery factor R = 2^16 mod q
pub const MONT_R: i32 = 1353; // 2^16 mod 3329

/// Inverse of Montgomery factor: R^{-1} mod q
pub const MONT_R_INV: i32 = 169; // 2^{-16} mod 3329

/// Barrett reduction constant: floor(2^26 / q)
pub const BARRETT_K: i32 = 20159; // floor(2^26 / 3329)
