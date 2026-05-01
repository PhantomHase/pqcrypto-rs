//! # pqcrypto-kem
//!
//! ML-KEM-768 Key Encapsulation Mechanism (FIPS 203).
//!
//! Provides key generation, encapsulation, and decapsulation
//! for the Module-Lattice-Based Key-Encapsulation Mechanism.
//!
//! ML-KEM-768 parameters:
//! - k = 3 (module rank)
//! - n = 256 (polynomial dimension)
//! - q = 3329 (modulus)
//! - η₁ = 2, η₂ = 2 (CBD parameters)
//! - d_u = 10, d_v = 4 (compression bit widths)

#![forbid(unsafe_code)]

pub mod api;
pub mod decaps;
pub mod encaps;
pub mod keygen;

// Note: cpapke_encrypt is used internally by encaps and decaps modules

/// ML-KEM-768: module rank k = 3
pub const K: usize = 3;

/// CBD parameter for secret vector: η₁ = 2
pub const ETA1: usize = 2;

/// CBD parameter for error/noise: η₂ = 2
pub const ETA2: usize = 2;

/// Compression bits for u: d_u = 10
pub const DU: u32 = 10;

/// Compression bits for v: d_v = 4
pub const DV: u32 = 4;

/// Seed length in bytes (256 bits)
pub const SEED_LEN: usize = 32;

/// Shared secret length in bytes (256 bits)
pub const SS_LEN: usize = 32;

/// Public key length: k * 12 * n/8 + 32 = 3 * 384 + 32 = 1184 bytes
pub const PK_LEN: usize = K * 384 + SEED_LEN; // 1184

/// Secret key length: k * 12 * n/8 = 3 * 384 = 1152 bytes
/// Plus hash of public key (32) and implicit rejection value z (32)
pub const SK_LEN: usize = K * 384 + SEED_LEN + PK_LEN + SS_LEN; // 2400

/// Ciphertext length: k * d_u * n/8 + d_v * n/8
/// = 3 * 10 * 32 + 4 * 32 = 960 + 128 = 1088 bytes
pub const CT_LEN: usize = (K * DU as usize * 256 + DV as usize * 256) / 8; // 1088

/// NIST Security Level 3
pub const SECURITY_LEVEL: u8 = 3;

/// Error type for KEM operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KemError {
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid secret key
    InvalidSecretKey,
    /// Invalid ciphertext
    InvalidCiphertext,
    /// Decapsulation failure (implicit rejection)
    DecapsulationFailure,
    /// Serialization error
    SerializationError(String),
}

impl std::fmt::Display for KemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KemError::InvalidPublicKey => write!(f, "Invalid public key"),
            KemError::InvalidSecretKey => write!(f, "Invalid secret key"),
            KemError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            KemError::DecapsulationFailure => write!(f, "Decapsulation failure"),
            KemError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for KemError {}
