//! # pqcrypto-sign
//!
//! ML-DSA-65 and SLH-DSA digital signature schemes.
//!
//! ML-DSA-65 (formerly Dilithium-3) is a lattice-based signature scheme
//! standardized as FIPS 204. It provides NIST Security Level 3.
//!
//! SLH-DSA (formerly SPHINCS+) is a hash-based signature scheme
//! standardized as FIPS 205.

#![forbid(unsafe_code)]

pub mod api;
pub mod ml_dsa;

/// ML-DSA-65 parameters
pub mod ml_dsa_params {
    /// Module rank k = 6
    pub const K: usize = 6;
    /// Module dimension l = 5
    pub const L: usize = 5;
    /// Polynomial degree n = 256
    pub const N: usize = 256;
    /// Prime modulus q = 8380417
    pub const Q: u32 = 8380417;
    /// Secret key range η = 4
    pub const ETA: usize = 4;
    /// Challenge range γ₁ = 2^19 = 524288
    pub const GAMMA1: u32 = 524288;
    /// Rounding parameter γ₂ = (q-1)/32 = 261888
    pub const GAMMA2: u32 = 261888;
    /// Challenge bound β = τ * η = 49 * 4 = 196... actually β = 78 for ML-DSA-65
    pub const BETA: u32 = 78;
    /// Number of ±1 coefficients in challenge: τ = 49
    pub const TAU: usize = 49;
    /// Seed length (256 bits)
    pub const SEED_LEN: usize = 32;
    /// Private key seed length
    pub const KEY_SEED_LEN: usize = 32;

    /// Public key length: seed (32) + t1 encoded (k * 320 bytes)
    /// t1 uses 10 bits per coefficient: k * 10 * 256 / 8 = k * 320
    pub const PK_LEN: usize = SEED_LEN + super::ml_dsa_params::K * 320;

    /// Secret key length: seed (32) + tr (32) + s1 encoded + s2 encoded + hint
    /// s1, s2 use η bits: k * η * 256 / 8 + l * η * 256 / 8
    pub const SK_LEN: usize = SEED_LEN * 3 + super::ml_dsa_params::K * 128 + super::ml_dsa_params::L * 128;

    /// Maximum signature length (approximate)
    pub const SIG_LEN: usize = 4096;
}

/// Error type for signature operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid secret key
    InvalidSecretKey,
    /// Invalid signature
    InvalidSignature,
    /// Serialization error
    SerializationError(String),
    /// Verification failed
    VerificationFailed,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::InvalidPublicKey => write!(f, "Invalid public key"),
            SignError::InvalidSecretKey => write!(f, "Invalid secret key"),
            SignError::InvalidSignature => write!(f, "Invalid signature"),
            SignError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            SignError::VerificationFailed => write!(f, "Signature verification failed"),
        }
    }
}

impl std::error::Error for SignError {}
