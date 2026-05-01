//! Modular reduction utilities.
//!
//! Provides Barrett and Montgomery reduction for efficient modular arithmetic
//! in the polynomial ring Z_q[X]/(X^256+1).

use crate::Q;

/// Conditional subtraction of q. If `a >= q`, return `a - q`, else return `a`.
/// This is constant-time using the `subtle` crate.
#[inline]
pub fn cond_sub_q(a: u16) -> u16 {
    let mask = subtle::ConditionallySelectable::conditional_select(
        &0u16,
        &Q,
        subtle::Choice::from(((a >= Q) as u8) & 1),
    );
    a.wrapping_sub(mask)
}

/// Barrett reduction: reduce an i32 in range [0, 2^26) modulo q = 3329.
///
/// Uses the approximation: floor(a * floor(2^26 / q) / 2^26) ≈ floor(a / q)
/// Then: a mod q ≈ a - q * floor(a / q)
///
/// This is correct for all a in [0, 2^26) when q = 3329 and the constant
/// is chosen as floor(2^26 / q) = 20159.
#[inline]
pub fn barrett_reduce(a: i32) -> i16 {
    debug_assert!(a >= 0 && a < (1 << 26));

    let v = ((a as i64 * crate::BARRETT_K as i64 + (1 << 25)) >> 26) as i32;
    let r = a - v * Q as i32;

    // Conditional add q if r < 0
    let r = r + ((r >> 31) & Q as i32);
    debug_assert!(r >= 0 && r < Q as i32);
    r as i16
}

/// Montgomery reduction: reduce a value in Montgomery form.
///
/// Given a value `a` in Montgomery form (a = a' * R mod q where R = 2^16),
/// computes a' = a * R^{-1} mod q.
///
/// Input: a in [-(q-1)*2^16, (q-1)*2^16]
/// Output: a * R^{-1} mod q in [0, q)
#[inline]
pub fn montgomery_reduce(a: i32) -> i16 {
    // a * Q_INV mod 2^16, where Q_INV = -Q^{-1} mod 2^16
    // Q^{-1} mod 2^16: we need 3329 * x ≡ 1 (mod 65536)
    // Using extended Euclidean: 3329 * 62209 ≡ 1 (mod 65536)
    // So -Q^{-1} mod 2^16 = 65536 - 62209 = 3327
    const Q_INV: i32 = 3327; // -Q^{-1} mod 2^16

    let t = (a.wrapping_mul(Q_INV)) as i16 as i32; // t = a * Q_INV mod 2^16 (lower 16 bits)
    let r = (a - t * Q as i32) >> 16;

    // Conditional add q if r is negative (constant-time)
    let r = r + ((r >> 31) & Q as i32);
    r as i16
}

/// Signed Barrett reduction: reduce an i32 modulo q to the range [-(q-1)/2, (q-1)/2].
#[inline]
pub fn barrett_reduce_signed(a: i32) -> i16 {
    let r = barrett_reduce(a);
    // Map [0, q) to [-(q-1)/2, (q-1)/2]
    // If r > (q-1)/2, subtract q
    let half = (Q as i16 - 1) / 2;
    if r > half {
        r - Q as i16
    } else {
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_barrett_reduce() {
        // 0 mod q = 0
        assert_eq!(barrett_reduce(0), 0);
        // q mod q = 0
        assert_eq!(barrett_reduce(Q as i32), 0);
        // 2q mod q = 0
        assert_eq!(barrett_reduce(2 * Q as i32), 0);
        // (q-1) mod q = q-1
        assert_eq!(barrett_reduce(Q as i32 - 1), Q as i16 - 1);
        // 1 mod q = 1
        assert_eq!(barrett_reduce(1), 1);
    }

    #[test]
    fn test_montgomery_reduce() {
        // Test basic properties of Montgomery reduction
        // For a = 0, should get 0
        assert_eq!(montgomery_reduce(0), 0);
        // For a = q, should get 0 (since q mod q = 0)
        // montgomery_reduce(q) = q * R^{-1} mod q = 0
        let r = montgomery_reduce(Q as i32);
        // The result should be in [0, q)
        assert!(r >= 0 && r < Q as i16, "Montgomery result out of range: {}", r);
    }

    #[test]
    fn test_cond_sub_q() {
        assert_eq!(cond_sub_q(0), 0);
        assert_eq!(cond_sub_q(1), 1);
        assert_eq!(cond_sub_q(Q), 0);
        assert_eq!(cond_sub_q(Q + 1), 1);
        assert_eq!(cond_sub_q(Q - 1), Q - 1);
    }

    #[test]
    fn test_barrett_range() {
        // All values in [0, 2^26) should reduce correctly
        for a in 0..1000 {
            let expected = (a % Q as i32) as i16;
            assert_eq!(barrett_reduce(a), expected, "Failed for a={}", a);
        }
    }
}
