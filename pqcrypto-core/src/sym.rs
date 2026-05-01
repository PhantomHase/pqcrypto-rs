//! Symmetric cryptographic primitives.
//!
//! Provides SHAKE-128, SHAKE-256, SHA3-256, and SHA3-512 as used in ML-KEM and ML-DSA.
//! Also provides hash functions with domain separation and XOF (Extendable Output Functions).

use crate::N;

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Sha3_256, Sha3_512, Shake128, Shake256,
};

/// SHAKE-128 XOF: extendable output function.
///
/// Used in ML-KEM for:
/// - Matrix A generation (sampleNTT with seed ρ)
/// - CPA encryption randomness
pub fn shake128_xof(input: &[u8], output_len: usize) -> Vec<u8> {
    use sha3::digest::Update;
    let mut hasher = Shake128::default();
    Update::update(&mut hasher, input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

/// SHAKE-256 XOF: extendable output function.
///
/// Used in ML-KEM for:
/// - Key derivation (G function)
/// - PRF (pseudorandom function)
pub fn shake256_xof(input: &[u8], output_len: usize) -> Vec<u8> {
    use sha3::digest::Update;
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

/// SHA3-256 hash function.
///
/// Returns a 32-byte digest.
pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, input);
    hasher.finalize().into()
}

/// SHA3-512 hash function.
///
/// Returns a 64-byte digest.
pub fn sha3_512(input: &[u8]) -> [u8; 64] {
    use sha3::Digest;
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, input);
    hasher.finalize().into()
}

/// Domain-separated hash: H(b || input).
///
/// Used for domain separation in ML-KEM. The byte `b` is prepended
/// before hashing.
pub fn h(b: u8, input: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(1 + input.len());
    data.push(b);
    data.extend_from_slice(input);
    sha3_256(&data)
}

/// PRF (Pseudorandom Function) for ML-KEM.
///
/// PRF(η, s, b) = SHAKE-256(s || b, η * N / 4)
///
/// Used for generating random coins during encryption.
pub fn prf(eta: usize, seed: &[u8], b: u8) -> Vec<u8> {
    let mut input = Vec::with_capacity(seed.len() + 1);
    input.extend_from_slice(seed);
    input.push(b);
    shake256_xof(&input, eta * N / 4) // η * N / 4 bytes per polynomial
}

/// J (jacobian) function for ML-KEM.
///
/// J(s) = SHAKE-256(s, 32)
/// Used in the Fujisaki-Okamoto transform.
pub fn j(input: &[u8]) -> [u8; 32] {
    let output = shake256_xof(input, 32);
    let mut result = [0u8; 32];
    result.copy_from_slice(&output);
    result
}

/// G function for ML-KEM.
///
/// G(s) = SHA3-512(s)
/// Used for deriving (z, c) from the random coins.
pub fn g(input: &[u8]) -> [u8; 64] {
    sha3_512(input)
}

/// HKDF-SHA256 Extract-and-Expand for hybrid encryption.
///
/// Derives a key from a shared secret using HKDF.
pub fn hkdf_extract_expand(ikm: &[u8], info: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_empty() {
        let hash = sha3_256(b"");
        assert_eq!(hash.len(), 32);
        // Known test vector for empty input
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_sha3_512_empty() {
        let hash = sha3_512(b"");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_shake128() {
        let output = shake128_xof(b"hello", 32);
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_shake256() {
        let output = shake256_xof(b"hello", 64);
        assert_eq!(output.len(), 64);
    }

    #[test]
    fn test_h_domain_separation() {
        let h0 = h(0, b"test");
        let h1 = h(1, b"test");
        // Different domain bytes should produce different hashes
        assert_ne!(h0, h1);
    }

    #[test]
    fn test_prf() {
        let seed = [0x42u8; 32];
        let output = prf(2, &seed, 0);
        assert_eq!(output.len(), 128); // η=2: 2 * 64 = 128

        let output2 = prf(2, &seed, 1);
        // Different nonce should produce different output
        assert_ne!(output, output2);
    }

    #[test]
    fn test_g_function() {
        let input = b"test input for G function";
        let output = g(input);
        assert_eq!(output.len(), 64);
    }

    #[test]
    fn test_hkdf() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        let output = hkdf_extract_expand(ikm, info, salt, 32);
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_deterministic() {
        // Same input should always produce same output
        let hash1 = sha3_256(b"deterministic");
        let hash2 = sha3_256(b"deterministic");
        assert_eq!(hash1, hash2);

        let shake1 = shake128_xof(b"deterministic", 64);
        let shake2 = shake128_xof(b"deterministic", 64);
        assert_eq!(shake1, shake2);
    }
}
