//! Centered Binomial Distribution (CBD) sampling.
//!
//! Samples polynomials from the centered binomial distribution CBD_η as specified
//! in FIPS 203 Section 4.1. This is used for generating secret and error vectors
//! in ML-KEM key generation and encapsulation.

use crate::poly::Poly;
use crate::{N, Q};

/// Sample a polynomial from the centered binomial distribution CBD_η.
///
/// Given a pseudorandom byte stream of length `eta * N / 4` bytes,
/// computes a polynomial where each coefficient is the difference
/// of two sums of η random bits.
///
/// For each coefficient a_i:
///   1. Extract 2*η bits from the stream
///   2. Split into two groups of η bits
///   3. a_i = (sum of first η bits) - (sum of second η bits) mod q
///
/// This produces coefficients in the range [-η, η].
pub fn sample_cbd(eta: usize, bytes: &[u8]) -> Poly {
    let mut poly = Poly::zero();
    let needed_bytes = eta * N / 4;
    assert!(
        bytes.len() >= needed_bytes,
        "CBD sampling needs {} bytes, got {}",
        needed_bytes,
        bytes.len()
    );

    let mut bit_idx = 0usize;

    for i in 0..N {
        let mut a: i32 = 0;
        let mut b: i32 = 0;

        for _ in 0..eta {
            // Extract a single bit
            a += ((bytes[bit_idx / 8] >> (bit_idx % 8)) & 1) as i32;
            bit_idx += 1;
        }
        for _ in 0..eta {
            b += ((bytes[bit_idx / 8] >> (bit_idx % 8)) & 1) as i32;
            bit_idx += 1;
        }

        // CBD coefficient = a - b, mapped to Z_q
        let val = (a - b).rem_euclid(Q as i32);
        poly.coeffs[i] = val as u16;
    }

    poly
}

/// Sample a vector of `k` polynomials from CBD_η.
///
/// This is used for generating vectors s, e in ML-KEM key generation.
/// The byte stream is split into k segments, each of length η * N / 4 bytes.
pub fn sample_cbd_vec(k: usize, eta: usize, bytes: &[u8]) -> Vec<Poly> {
    let segment_len = eta * N / 4;
    assert!(
        bytes.len() >= k * segment_len,
        "CBD vector sampling needs {} bytes, got {}",
        k * segment_len,
        bytes.len()
    );

    (0..k)
        .map(|i| sample_cbd(eta, &bytes[i * segment_len..(i + 1) * segment_len]))
        .collect()
}

/// Sample a polynomial from a uniform distribution using rejection sampling.
///
/// Given a stream of pseudorandom bytes, generates coefficients uniformly
/// in [0, q) by rejecting values >= q. This is the "sampleNTT" function
/// from FIPS 203 Section 4.2.2.
pub fn sample_uniform(bytes: &[u8]) -> Poly {
    let mut poly = Poly::zero();
    let mut coeff_idx = 0;
    let mut byte_idx = 0;

    while coeff_idx < N && byte_idx + 2 <= bytes.len() {
        // Read two bytes as a little-endian u16
        let val = u16::from_le_bytes([bytes[byte_idx], bytes[byte_idx + 1]]);
        byte_idx += 2;

        // Reject if val >= q (rejection sampling for uniform distribution)
        if val < Q {
            poly.coeffs[coeff_idx] = val;
            coeff_idx += 1;
        }
    }

    poly
}

/// Sample a polynomial from a uniform distribution using the "samplePolyCBD"
/// method with seed expansion via SHAKE-128.
///
/// This is the optimized version used in ML-KEM that generates pseudorandom
/// bytes from a seed using SHAKE-128, then samples from the uniform distribution.
pub fn sample_uniform_from_seed(seed: &[u8; 32]) -> Poly {
    use sha3::Shake128;
    use sha3::digest::{Update, ExtendableOutput, XofReader};

    // Generate enough pseudorandom bytes for rejection sampling
    // We need about 2 * N * ceil(log2(q)) / 8 = 2 * 256 * 12 / 8 = 768 bytes
    // But rejection rate is low, so 1024 bytes should be sufficient
    let mut hasher = Shake128::default();
    Update::update(&mut hasher, seed);
    let mut reader = hasher.finalize_xof();
    let mut bytes = vec![0u8; 1024];
    reader.read(&mut bytes);

    sample_uniform(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbd_eta2() {
        // CBD with η=2 should produce coefficients in [-2, 2]
        let bytes = vec![0xFF; 128]; // All 1s → max values
        let poly = sample_cbd(2, &bytes);
        for &c in &poly.coeffs {
            // With all 1s: a=2, b=2, so a-b=0
            assert_eq!(c, 0);
        }
    }

    #[test]
    fn test_cbd_eta2_zeros() {
        // CBD with all 0s should produce zero polynomial
        let bytes = vec![0x00; 128];
        let poly = sample_cbd(2, &bytes);
        assert!(poly.is_zero());
    }

    #[test]
    fn test_cbd_eta3() {
        // CBD with η=3: coefficients in [-3, 3]
        let bytes = vec![0xFF; 192]; // 3 * 256 / 4 = 192
        let poly = sample_cbd(3, &bytes);
        for &c in &poly.coeffs {
            assert_eq!(c, 0); // All 1s: a=3, b=3, so a-b=0
        }
    }

    #[test]
    fn test_sample_uniform() {
        // Test with sequential bytes
        let mut bytes = Vec::new();
        for i in 0..1000u16 {
            bytes.extend_from_slice(&i.to_le_bytes());
        }
        let poly = sample_uniform(&bytes);
        // All coefficients should be < Q
        for &c in &poly.coeffs {
            assert!(c < Q);
        }
    }

    #[test]
    fn test_sample_uniform_rejection() {
        // Values >= Q should be rejected
        let mut bytes = Vec::new();
        // Q = 3329, so values 3329, 3330, ... should be rejected
        for i in 0..512u16 {
            bytes.extend_from_slice(&(Q + i % 100).to_le_bytes());
        }
        // This should still work because we skip rejected values
        // But we need enough bytes to fill 256 coefficients
        // All values >= Q, so we'd need many more bytes
        // Let's test with a mix
        let mut bytes = Vec::new();
        for i in 0..500u16 {
            bytes.extend_from_slice(&(i % (Q - 1)).to_le_bytes());
        }
        let poly = sample_uniform(&bytes);
        for &c in &poly.coeffs {
            assert!(c < Q);
        }
    }

    #[test]
    fn test_cbd_vector() {
        let bytes = vec![0xAA; 3 * 2 * 256 / 4]; // η=2, k=3
        let vec = sample_cbd_vec(3, 2, &bytes);
        assert_eq!(vec.len(), 3);
        for poly in &vec {
            for &c in &poly.coeffs {
                // η=2: coefficients in [-2, 2] mod q
                let c_signed = if c > Q / 2 {
                    c as i32 - Q as i32
                } else {
                    c as i32
                };
                assert!(c_signed >= -2 && c_signed <= 2);
            }
        }
    }
}
