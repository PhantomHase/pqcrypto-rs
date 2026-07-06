//! ML-KEM Number Theoretic Transform.
//!
//! Implements the FIPS 203 NTT for q = 3329. ML-KEM does not have a
//! primitive 512th root of unity, so multiplication in the NTT domain is
//! performed as 128 independent degree-one products modulo X^2 - gamma.

use crate::poly::Poly;
use crate::{N, Q};

const INV_128: u16 = 3303;

const ZETAS: [u16; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296,
    2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331,
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435,
    807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583,
    2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789,
    1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037,
    3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403,
    1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

const BASE_CASE_GAMMAS: [i16; 128] = [
    17, -17, 2761, -2761, 583, -583, 2649, -2649, 1637, -1637, 723, -723, 2288, -2288, 1100, -1100,
    1409, -1409, 2662, -2662, 3281, -3281, 233, -233, 756, -756, 2156, -2156, 3015, -3015, 3050,
    -3050, 1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789, 1847, -1847, 952, -952, 1461, -1461,
    2687, -2687, 939, -939, 2308, -2308, 2437, -2437, 2388, -2388, 733, -733, 2337, -2337, 268,
    -268, 641, -641, 1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220, 375, -375, 2549, -2549,
    2090, -2090, 1645, -1645, 1063, -1063, 319, -319, 2773, -2773, 757, -757, 2099, -2099, 561,
    -561, 2466, -2466, 2594, -2594, 2804, -2804, 1092, -1092, 403, -403, 1026, -1026, 1143, -1143,
    2150, -2150, 2775, -2775, 886, -886, 1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029, 2110,
    -2110, 2935, -2935, 885, -885, 2154, -2154,
];

#[inline]
fn add_mod(a: u16, b: u16) -> u16 {
    ((a as u32 + b as u32) % Q as u32) as u16
}

#[inline]
fn sub_mod(a: u16, b: u16) -> u16 {
    ((a as u32 + Q as u32 - b as u32) % Q as u32) as u16
}

#[inline]
fn mul_mod(a: u16, b: u16) -> u16 {
    ((a as u32 * b as u32) % Q as u32) as u16
}

#[inline]
fn signed_mod_q(value: i16) -> u16 {
    (value as i32).rem_euclid(Q as i32) as u16
}

/// Multiply two polynomials in R_q = Z_q[X]/(X^256+1).
pub fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    let mut a_hat = *a;
    let mut b_hat = *b;

    ntt_forward(&mut a_hat);
    ntt_forward(&mut b_hat);
    let mut product = ntt_pointwise(&a_hat, &b_hat);
    ntt_inverse(&mut product);

    product
}

/// Forward ML-KEM NTT, transforming a polynomial from R_q into T_q.
pub fn ntt_forward(poly: &mut Poly) {
    let mut zeta_idx = 1usize;
    let mut len = N / 2;

    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[zeta_idx];
            zeta_idx += 1;

            for j in start..start + len {
                let t = mul_mod(zeta, poly.coeffs[j + len]);
                let u = poly.coeffs[j];
                poly.coeffs[j + len] = sub_mod(u, t);
                poly.coeffs[j] = add_mod(u, t);
            }

            start += 2 * len;
        }
        len /= 2;
    }
}

/// Inverse ML-KEM NTT, transforming an element of T_q back into R_q.
pub fn ntt_inverse(poly: &mut Poly) {
    let mut zeta_idx = 127usize;
    let mut len = 2usize;

    while len <= N / 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[zeta_idx];
            zeta_idx -= 1;

            for j in start..start + len {
                let t = poly.coeffs[j];
                let u = poly.coeffs[j + len];
                poly.coeffs[j] = add_mod(t, u);
                poly.coeffs[j + len] = mul_mod(zeta, sub_mod(u, t));
            }

            start += 2 * len;
        }
        len *= 2;
    }

    for coeff in &mut poly.coeffs {
        *coeff = mul_mod(*coeff, INV_128);
    }
}

/// Multiply two ML-KEM NTT-domain polynomials.
pub fn ntt_pointwise(a: &Poly, b: &Poly) -> Poly {
    let mut result = Poly::zero();

    for i in 0..N / 2 {
        let gamma = signed_mod_q(BASE_CASE_GAMMAS[i]);
        let a0 = a.coeffs[2 * i];
        let a1 = a.coeffs[2 * i + 1];
        let b0 = b.coeffs[2 * i];
        let b1 = b.coeffs[2 * i + 1];

        result.coeffs[2 * i] = add_mod(mul_mod(a0, b0), mul_mod(mul_mod(a1, b1), gamma));
        result.coeffs[2 * i + 1] = add_mod(mul_mod(a0, b1), mul_mod(a1, b0));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schoolbook_mul(a: &Poly, b: &Poly) -> Poly {
        let q = Q as u32;
        let mut result = [0u32; N];

        for i in 0..N {
            for j in 0..N {
                let prod = a.coeffs[i] as u32 * b.coeffs[j] as u32;
                let idx = i + j;
                if idx < N {
                    result[idx] = (result[idx] + prod) % q;
                } else {
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

    #[test]
    fn test_ntt_round_trip() {
        let mut a = Poly::zero();
        for i in 0..N {
            a.coeffs[i] = (i as u16 * 17 + 23) % Q;
        }

        let original = a;
        ntt_forward(&mut a);
        ntt_inverse(&mut a);
        assert_eq!(a, original);
    }

    #[test]
    fn test_ntt_pointwise_matches_schoolbook() {
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        for i in 0..N {
            a.coeffs[i] = (i as u16 * 13 + 7) % Q;
            b.coeffs[i] = (i as u16 * 19 + 11) % Q;
        }

        assert_eq!(poly_mul(&a, &b), schoolbook_mul(&a, &b));
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
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        a.coeffs[255] = 1;
        b.coeffs[1] = 1;

        let c = poly_mul(&a, &b);
        assert_eq!(c.coeffs[0], Q - 1);
        for i in 1..N {
            assert_eq!(c.coeffs[i], 0);
        }
    }

    #[test]
    fn test_poly_mul_commutative() {
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        for i in 0..N {
            a.coeffs[i] = (i as u16 * 13 + 7) % Q;
            b.coeffs[i] = (i as u16 * 17 + 11) % Q;
        }

        let ab = poly_mul(&a, &b);
        let ba = poly_mul(&b, &a);
        assert_eq!(ab, ba);
    }

    #[test]
    fn test_poly_mul_negacyclic_higher() {
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
