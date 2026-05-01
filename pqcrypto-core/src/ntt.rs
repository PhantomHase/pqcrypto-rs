//! Polynomial multiplication for ML-KEM.
//!
//! Currently uses schoolbook O(n²) multiplication.
//! A negacyclic NTT O(n log n) optimization is planned for Phase 5.

use crate::poly::Poly;
use crate::{Q, N};

/// Multiply two polynomials in R_q = Z_q[X]/(X^256+1).
///
/// Uses schoolbook multiplication with the negacyclic property:
/// X^256 ≡ -1 (mod X^256+1).
///
/// This is O(n²) but correct. For production use, replace with
/// negacyclic NTT for O(n log n) performance.
pub fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    let q = Q as u32;
    let mut result = [0u32; N];

    for i in 0..N {
        for j in 0..N {
            let prod = a.coeffs[i] as u32 * b.coeffs[j] as u32;
            let idx = i + j;
            if idx < N {
                result[idx] = (result[idx] + prod) % q;
            } else {
                // X^256 ≡ -1
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

/// Forward NTT (no-op for schoolbook multiplication).
/// In a future optimization, this will transform to NTT domain.
pub fn ntt_forward(_poly: &mut Poly) {
    // No-op: schoolbook multiplication doesn't need NTT transform
}

/// Inverse NTT (no-op for schoolbook multiplication).
pub fn ntt_inverse(_poly: &mut Poly) {
    // No-op: schoolbook multiplication doesn't need NTT transform
}

/// Pointwise multiplication in NTT domain.
/// For schoolbook, this is just regular multiplication.
pub fn ntt_pointwise(a: &Poly, b: &Poly) -> Poly {
    poly_mul(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_mul_zero() {
        let a = Poly::zero();
        let b = Poly::from_coeffs(&[1; N]);
        let c = poly_mul(&a, &b);
        assert!(c.is_zero());
    }

    #[test]
    fn test_poly_mul_identity() {
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
        // x^255 * x = x^256 = -1 in R_q
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        a.coeffs[255] = 1;
        b.coeffs[1] = 1;

        let c = poly_mul(&a, &b);
        assert_eq!(c.coeffs[0], Q - 1); // -1 mod q
        for i in 1..N {
            assert_eq!(c.coeffs[i], 0);
        }
    }

    #[test]
    fn test_poly_mul_commutative() {
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        for i in 0..10 {
            a.coeffs[i] = (i as u16 * 13 + 7) % Q;
            b.coeffs[i] = (i as u16 * 17 + 11) % Q;
        }

        let ab = poly_mul(&a, &b);
        let ba = poly_mul(&b, &a);
        for i in 0..N {
            assert_eq!(ab.coeffs[i], ba.coeffs[i], "Commutativity failed at {}", i);
        }
    }

    #[test]
    fn test_poly_mul_negacyclic_higher() {
        // x^255 * x^2 = x^257 = -x
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        a.coeffs[255] = 1;
        b.coeffs[2] = 1;

        let c = poly_mul(&a, &b);
        assert_eq!(c.coeffs[0], 0);
        assert_eq!(c.coeffs[1], Q - 1);
        for i in 2..N {
            assert_eq!(c.coeffs[i], 0);
        }
    }
}
