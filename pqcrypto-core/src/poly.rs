//! Polynomial operations in the ring R_q = Z_q[X]/(X^256+1).
//!
//! This module defines the `Poly` type representing polynomials with 256 coefficients
//! in Z_q (q = 3329), and operations on them including addition, subtraction,
//! NTT-based multiplication, and serialization.

use crate::{N, Q};

/// A polynomial in R_q = Z_q[X]/(X^256+1).
///
/// Coefficients are stored in standard (non-NTT) form.
/// Use `ntt::ntt_forward()` to convert to NTT domain for fast multiplication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly {
    /// Coefficients a_0, a_1, ..., a_{255} in Z_q
    pub coeffs: [u16; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}

impl Poly {
    /// Create a zero polynomial.
    pub const fn zero() -> Self {
        Self { coeffs: [0u16; N] }
    }

    /// Create a polynomial from a slice of coefficients.
    /// Panics if the slice has fewer than 256 elements.
    pub fn from_coeffs(coeffs: &[u16]) -> Self {
        assert!(coeffs.len() >= N, "Need at least {} coefficients", N);
        let mut c = [0u16; N];
        c.copy_from_slice(&coeffs[..N]);
        Self { coeffs: c }
    }

    /// Reduce all coefficients modulo q.
    pub fn reduce(&mut self) {
        for c in &mut self.coeffs {
            *c %= Q;
        }
    }

    /// Add two polynomials coefficient-wise (mod q).
    ///
    /// Result[i] = (self[i] + rhs[i]) mod q
    pub fn add(&self, rhs: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..N {
            let sum = self.coeffs[i] as u32 + rhs.coeffs[i] as u32;
            result.coeffs[i] = (sum % Q as u32) as u16;
        }
        result
    }

    /// Subtract two polynomials coefficient-wise (mod q).
    ///
    /// Result[i] = (self[i] - rhs[i]) mod q
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..N {
            // Compute (self[i] - rhs[i]) mod q
            let diff = (self.coeffs[i] as u32 + Q as u32 - rhs.coeffs[i] as u32) % Q as u32;
            result.coeffs[i] = diff as u16;
        }
        result
    }

    /// Multiply a polynomial by a scalar (mod q).
    pub fn scalar_mul(&self, scalar: u16) -> Self {
        let mut result = Self::zero();
        for i in 0..N {
            let prod = (self.coeffs[i] as u32 * scalar as u32) % Q as u32;
            result.coeffs[i] = prod as u16;
        }
        result
    }

    /// Check if this is the zero polynomial.
    pub fn is_zero(&self) -> bool {
        self.coeffs.iter().all(|&c| c == 0)
    }

    /// Serialize coefficients to bytes (little-endian, 2 bytes per coefficient).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(N * 2);
        for &c in &self.coeffs {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes
    }

    /// Deserialize coefficients from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= N * 2, "Not enough bytes for a polynomial");
        let mut coeffs = [0u16; N];
        for (i, chunk) in bytes.chunks_exact(2).enumerate().take(N) {
            coeffs[i] = u16::from_le_bytes([chunk[0], chunk[1]]);
        }
        Self { coeffs }
    }

    /// Compress the polynomial for use in ciphertext (lossy).
    ///
    /// Maps coefficients from [0, q) to [0, 2^d) by rounding.
    /// For ML-KEM-768, d = 10 for ciphertext compression.
    pub fn compress(&self, d: u32) -> Vec<u8> {
        let mut result = Vec::with_capacity(d as usize * N / 8);
        let half_q = (Q as u32 + 1) / 2;

        // Pack d-bit values
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for &coeff in &self.coeffs {
            // Compress: round(coeff * 2^d / q)
            let compressed = ((coeff as u32 * (1 << d) + half_q) / Q as u32) & ((1 << d) - 1);
            acc |= compressed << bits;
            bits += d;
            while bits >= 8 {
                result.push((acc & 0xFF) as u8);
                acc >>= 8;
                bits -= 8;
            }
        }
        if bits > 0 {
            result.push((acc & 0xFF) as u8);
        }
        result
    }

    /// Decompress the polynomial from compressed bytes.
    ///
    /// Reverses the lossy compression. The result is an approximation
    /// of the original polynomial.
    pub fn decompress(bytes: &[u8], d: u32) -> Self {
        let mut poly = Self::zero();
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut byte_idx = 0;
        let mask = (1u32 << d) - 1;
        let half_q = (Q as u32 + 1) / 2;

        for i in 0..N {
            while bits < d {
                if byte_idx < bytes.len() {
                    acc |= (bytes[byte_idx] as u32) << bits;
                    byte_idx += 1;
                }
                bits += 8;
            }
            let compressed = acc & mask;
            acc >>= d;
            bits -= d;
            // Decompress: round(compressed * q / 2^d)
            poly.coeffs[i] =
                ((compressed as u64 * Q as u64 + (1u64 << (d - 1))) >> d) as u16 % Q;
        }
        poly
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_zero() {
        let a = Poly::from_coeffs(&[1; N]);
        let zero = Poly::zero();
        assert_eq!(a.add(&zero), a);
    }

    #[test]
    fn test_sub_self() {
        let a = Poly::from_coeffs(&[42; N]);
        let result = a.sub(&a);
        assert!(result.is_zero());
    }

    #[test]
    fn test_add_sub_round_trip() {
        let a = Poly::from_coeffs(&[100; N]);
        let b = Poly::from_coeffs(&[200; N]);
        let sum = a.add(&b);
        let diff = sum.sub(&b);
        assert_eq!(diff, a);
    }

    #[test]
    fn test_scalar_mul() {
        let a = Poly::from_coeffs(&[1; N]);
        let result = a.scalar_mul(Q - 1);
        // 1 * (Q-1) = Q-1
        assert!(result.coeffs.iter().all(|&c| c == Q - 1));
    }

    #[test]
    fn test_serialization_round_trip() {
        let mut poly = Poly::zero();
        for i in 0..N {
            poly.coeffs[i] = (i as u16 * 13) % Q;
        }
        let bytes = poly.to_bytes();
        let recovered = Poly::from_bytes(&bytes);
        assert_eq!(poly, recovered);
    }

    #[test]
    fn test_compress_decompress_round_trip() {
        let mut poly = Poly::zero();
        for i in 0..N {
            poly.coeffs[i] = (i as u16 * 7) % Q;
        }
        let compressed = poly.compress(10);
        let decompressed = Poly::decompress(&compressed, 10);
        // Decompression is lossy, but should be close
        for i in 0..N {
            let diff = (poly.coeffs[i] as i32 - decompressed.coeffs[i] as i32).abs();
            assert!(
                diff <= (Q as i32 / (1 << 10) + 1),
                "Coefficient {} too far off: {} vs {}",
                i,
                poly.coeffs[i],
                decompressed.coeffs[i]
            );
        }
    }
}
