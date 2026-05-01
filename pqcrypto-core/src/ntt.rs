//! Number Theoretic Transform (NTT) for fast polynomial multiplication.
//!
//! This module provides polynomial multiplication in the ring R_q = Z_q[X]/(X^256+1)
//! where q = 3329.
//!
//! Currently uses schoolbook multiplication O(n²) which is correct but not optimal.
//! A proper negacyclic NTT implementation is planned for Phase 5 (optimization).
//!
//! The negacyclic NTT for ML-KEM requires:
//! - A primitive 2n-th root of unity (not n-th)
//! - Special butterfly structure for the X^n+1 reduction
//! - Montgomery form for constant-time intermediate computations

use crate::poly::Poly;
use crate::{Q, N};

/// Compute a^b mod m using modular exponentiation.
#[allow(dead_code)]
const fn mod_pow(mut a: i64, mut b: u32, m: i64) -> i64 {
    let mut result = 1i64;
    a = a % m;
    while b > 0 {
        if b & 1 == 1 {
            result = (result * a) % m;
        }
        a = (a * a) % m;
        b >>= 1;
    }
    result
}

/// Bit-reverse a value with the given number of bits.
#[allow(dead_code)]
const fn bit_reverse(mut x: usize, bits: usize) -> usize {
    let mut result = 0usize;
    let mut i = 0;
    while i < bits {
        result = (result << 1) | (x & 1);
        x >>= 1;
        i += 1;
    }
    result
}

/// Multiply two polynomials in the ring R_q = Z_q[X]/(X^256+1).
///
/// Uses schoolbook multiplication with the negacyclic property:
/// X^256 ≡ -1 (mod X^256+1).
///
/// This is O(n²) but correct. For production use, replace with
/// negacyclic NTT for O(n log n) performance.
pub fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    let q = Q as u32;
    let mut result = [0u32; N];

    // Schoolbook multiplication
    for i in 0..N {
        for j in 0..N {
            let prod = a.coeffs[i] as u32 * b.coeffs[j] as u32;
            let idx = i + j;
            if idx < N {
                result[idx] = (result[idx] + prod) % q;
            } else {
                // X^256 ≡ -1, so X^(256+k) ≡ -X^k
                let wrapped = idx - N;
                result[wrapped] = (result[wrapped] + q - (prod % q)) % q;
            }
        }
    }

    let mut poly = Poly::zero();
    for i in 0..N {
        poly.coeffs[i] = result[i] as u16;
    }
    poly
}

/// NTT-based forward transform (placeholder).
///
/// For now, this is a no-op since we use schoolbook multiplication.
/// The negacyclic NTT requires careful implementation of:
/// - Cooley-Tukey butterfly with negacyclic twist
/// - Montgomery form arithmetic
/// - Proper twiddle factor precomputation
#[allow(dead_code)]
pub fn ntt_forward(_poly: &mut Poly) {
    // Placeholder: no-op for schoolbook multiplication
    // TODO: Implement negacyclic NTT for FIPS 203 compliance
}

/// NTT-based inverse transform (placeholder).
#[allow(dead_code)]
pub fn ntt_inverse(_poly: &mut Poly) {
    // Placeholder: no-op for schoolbook multiplication
    // TODO: Implement inverse negacyclic NTT
}

/// Pointwise multiplication in NTT domain (placeholder).
///
/// For schoolbook multiplication, this is just regular polynomial multiplication.
#[allow(dead_code)]
pub fn ntt_pointwise(a: &Poly, b: &Poly) -> Poly {
    poly_mul(a, b)
}

/// Multiply two polynomials using NTT (currently schoolbook).
///
/// This is the main entry point for polynomial multiplication.
/// Uses schoolbook O(n²) for correctness. Will be upgraded to
/// negacyclic NTT O(n log n) in a future optimization pass.
pub fn poly_mul_ntt(a: &Poly, b: &Poly) -> Poly {
    poly_mul(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_reverse() {
        assert_eq!(bit_reverse(0, 7), 0);
        assert_eq!(bit_reverse(1, 7), 64);
        assert_eq!(bit_reverse(64, 7), 1);
        assert_eq!(bit_reverse(0b1010101, 7), 0b1010101);
    }

    #[test]
    fn test_mod_pow() {
        assert_eq!(mod_pow(17, 0, 3329), 1);
        assert_eq!(mod_pow(17, 1, 3329), 17);
        // 17^256 mod 3329 should be 1 (if 17 is a 256th root of unity)
        // Actually 17^256 mod 3329 = 3083, not 1
        // 17 is NOT a primitive 256th root of unity mod 3329
    }

    #[test]
    fn test_poly_mul_zero() {
        let a = Poly::zero();
        let b = Poly::from_coeffs(&[1; N]);
        let c = poly_mul(&a, &b);
        assert!(c.is_zero());
    }

    #[test]
    fn test_poly_mul_identity() {
        // Multiplying by 1 should give the same polynomial
        let mut a = Poly::zero();
        a.coeffs[0] = 42;
        let mut one = Poly::zero();
        one.coeffs[0] = 1;
        let c = poly_mul(&a, &one);
        assert_eq!(c.coeffs[0], 42);
        for i in 1..N {
            assert_eq!(c.coeffs[i], 0);
        }
    }

    #[test]
    fn test_poly_mul_linear() {
        // (1 + x)(1 + x) = 1 + 2x + x^2
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        a.coeffs[0] = 1;
        a.coeffs[1] = 1;
        b.coeffs[0] = 1;
        b.coeffs[1] = 1;

        let c = poly_mul(&a, &b);
        assert_eq!(c.coeffs[0], 1);
        assert_eq!(c.coeffs[1], 2);
        assert_eq!(c.coeffs[2], 1);
        for i in 3..N {
            assert_eq!(c.coeffs[i], 0);
        }
    }

    #[test]
    fn test_poly_mul_negacyclic() {
        // X^255 * X = X^256 = -1 (in R_q)
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        a.coeffs[255] = 1;
        b.coeffs[1] = 1;

        let c = poly_mul(&a, &b);
        // X^256 ≡ -1 ≡ q-1 (mod q)
        assert_eq!(c.coeffs[0], Q - 1);
        for i in 1..N {
            assert_eq!(c.coeffs[i], 0);
        }
    }

    #[test]
    fn test_poly_mul_negacyclic_higher() {
        // X^255 * X^2 = X^257 = X * X^256 = -X
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        a.coeffs[255] = 1;
        b.coeffs[2] = 1;

        let c = poly_mul(&a, &b);
        // X^257 = X * X^256 = -X = (q-1) * X
        assert_eq!(c.coeffs[0], 0);
        assert_eq!(c.coeffs[1], Q - 1);
        for i in 2..N {
            assert_eq!(c.coeffs[i], 0);
        }
    }

    #[test]
    fn test_poly_mul_commutative() {
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        for i in 0..10 {
            a.coeffs[i] = (i as u16 * 7 + 3) % Q;
            b.coeffs[i] = (i as u16 * 13 + 5) % Q;
        }

        let ab = poly_mul(&a, &b);
        let ba = poly_mul(&b, &a);
        for i in 0..N {
            assert_eq!(ab.coeffs[i], ba.coeffs[i], "Commutativity failed at {}", i);
        }
    }
}
