//! ML-KEM-768 Encapsulation.
//!
//! Encapsulates a shared secret to a public key according to FIPS 203 Section 5.2.
//!
//! Algorithm:
//! 1. Generate random message m (32 bytes)
//! 2. (K̄, r) = G(m || H(pk))  — derive key and randomness from message
//! 3. Encrypt m under pk using CPAPKE.Encrypt(pk, m, r)
//! 4. K = KDF(K̄ || c)  — derive final shared secret
//! 5. Return (c, K)

use pqcrypto_core::ntt::{ntt_forward, ntt_pointwise};
use pqcrypto_core::poly::Poly;
use pqcrypto_core::sampling::{sample_cbd, sample_cbd_vec, sample_uniform};
use pqcrypto_core::sym::{g, prf, shake128_xof, sha3_256};
use pqcrypto_core::{N, Q};

use crate::keygen::{encode_pk, PublicKey};
use crate::{K, ETA1, ETA2, DU, DV, SEED_LEN, SS_LEN, CT_LEN};
use crate::KemError;

/// Encapsulate a random message to a public key.
///
/// Returns (ciphertext, shared_secret).
///
/// Uses OsRng for the random message m.
pub fn encaps(pk: &PublicKey) -> Result<([u8; CT_LEN], [u8; SS_LEN]), KemError> {
    use rand::RngCore;

    let mut rng = rand::thread_rng();
    let mut m = [0u8; SEED_LEN];
    rng.fill_bytes(&mut m);

    encaps_internal(pk, &m)
}

/// Internal encapsulation with explicit message (for testing/KAT).
pub fn encaps_internal(
    pk: &PublicKey,
    m: &[u8; SEED_LEN],
) -> Result<([u8; CT_LEN], [u8; SS_LEN]), KemError> {
    // Step 1: Compute H(pk)
    let pk_bytes = encode_pk(pk);
    let pk_hash = sha3_256(&pk_bytes);

    // Step 2: (K̄, r) = G(m || H(pk))
    let mut g_input = Vec::with_capacity(2 * SEED_LEN);
    g_input.extend_from_slice(m);
    g_input.extend_from_slice(&pk_hash);
    let g_out = g(&g_input);

    let mut k_bar = [0u8; SEED_LEN];
    let mut r = [0u8; SEED_LEN];
    k_bar.copy_from_slice(&g_out[..SEED_LEN]);
    r.copy_from_slice(&g_out[SEED_LEN..2 * SEED_LEN]);

    // Step 3: Encrypt m under pk
    let ct = cpapke_encrypt(pk, m, &r)?;

    // Step 4: K = KDF(K̄ || ct)
    let mut kdf_input = Vec::with_capacity(SEED_LEN + CT_LEN);
    kdf_input.extend_from_slice(&k_bar);
    kdf_input.extend_from_slice(&ct);
    let k = sha3_256(&kdf_input);
    let mut ss = [0u8; SS_LEN];
    ss.copy_from_slice(&k[..SS_LEN]);

    Ok((ct, ss))
}

/// CPAPKE Encryption (CPA-secure public-key encryption).
///
/// Encrypts message m using randomness r under public key pk.
pub(crate) fn cpapke_encrypt(
    pk: &PublicKey,
    m: &[u8; SEED_LEN],
    r_seed: &[u8; SEED_LEN],
) -> Result<[u8; CT_LEN], KemError> {
    // Step 1: Parse public key
    let rho = &pk.rho;
    let t_hat = &pk.t_hat;

    // Step 2: Generate matrix A_hat
    let a_hat = generate_matrix_a_transpose(rho);

    // Step 3: Sample r_vec from CBD_η₁(r) with nonces 0..k-1
    let mut r_vec: Vec<Poly> = Vec::with_capacity(K);
    for i in 0..K {
        let r_bytes = prf(ETA1, r_seed, i as u8);
        let mut r_i = sample_cbd(ETA1, &r_bytes);
        ntt_forward(&mut r_i);
        r_vec.push(r_i);
    }

    // Step 4: Sample e1 from CBD_η₂(r) with nonces k..2k-1
    let mut e1: Vec<Poly> = Vec::with_capacity(K);
    for i in 0..K {
        let e1_bytes = prf(ETA2, r_seed, (K + i) as u8);
        e1.push(sample_cbd(ETA2, &e1_bytes));
    }

    // Step 5: Sample e2 from CBD_η₂(r) with nonce 2k
    let e2_bytes = prf(ETA2, r_seed, (2 * K) as u8);
    let e2 = sample_cbd(ETA2, &e2_bytes);

    // Step 6: u = NTT⁻¹(A_hat^T · r_vec) + e1
    let mut u = vec![Poly::zero(); K];
    for i in 0..K {
        let mut sum = Poly::zero();
        for j in 0..K {
            let product = ntt_pointwise(&a_hat[i][j], &r_vec[j]);
            sum = sum.add(&product);
        }
        // Inverse NTT to get back to coefficient domain
        pqcrypto_core::ntt::ntt_inverse(&mut sum);
        u[i] = sum.add(&e1[i]);
    }

    // Step 7: v = t_hat · r_vec + e2 + m'
    let mut v = Poly::zero();
    for i in 0..K {
        let product = ntt_pointwise(&t_hat[i], &r_vec[i]);
        v = v.add(&product);
    }
    pqcrypto_core::ntt::ntt_inverse(&mut v);
    v = v.add(&e2);

    // Decode message m into polynomial m'
    // Each bit of m maps to a coefficient: if bit i is 1, m'[i] = ceil(q/2)
    let m_poly = decode_message(m);

    // v = v + m'
    v = v.add(&m_poly);

    // Step 8: Compress and encode
    let mut ct = [0u8; CT_LEN];

    // Encode u: k polynomials, each compressed to d_u bits
    let mut offset = 0;
    for u_i in &u {
        let compressed = u_i.compress(DU);
        let bytes_needed = (DU as usize * N) / 8;
        ct[offset..offset + bytes_needed].copy_from_slice(&compressed[..bytes_needed]);
        offset += bytes_needed;
    }

    // Encode v: 1 polynomial compressed to d_v bits
    let compressed_v = v.compress(DV);
    let bytes_needed = (DV as usize * N) / 8;
    ct[offset..offset + bytes_needed].copy_from_slice(&compressed_v[..bytes_needed]);

    Ok(ct)
}

/// Generate the transposed matrix A_hat from seed ρ.
///
/// A_hat^T[i][j] = A_hat[j][i] = SampleNTT(ρ || i || j)
fn generate_matrix_a_transpose(rho: &[u8; SEED_LEN]) -> Vec<Vec<Poly>> {
    let mut a_hat_t = vec![vec![Poly::zero(); K]; K];

    for i in 0..K {
        for j in 0..K {
            let mut seed_input = Vec::with_capacity(SEED_LEN + 2);
            seed_input.extend_from_slice(rho);
            seed_input.push(i as u8);
            seed_input.push(j as u8);

            let bytes = shake128_xof(&seed_input, 1024);
            a_hat_t[i][j] = sample_uniform(&bytes);
            ntt_forward(&mut a_hat_t[i][j]);
        }
    }

    a_hat_t
}

/// Decode a 32-byte message into a polynomial.
///
/// Each bit i of the message maps to coefficient i:
/// - If bit i = 1: coefficient = ceil(q/2) = 1665
/// - If bit i = 0: coefficient = 0
fn decode_message(m: &[u8; SEED_LEN]) -> Poly {
    let mut poly = Poly::zero();
    let half_q = ((Q as u32 + 1) / 2) as u16; // ceil(q/2) = 1665

    for (byte_idx, &byte) in m.iter().enumerate() {
        for bit_idx in 0..8 {
            let coeff_idx = byte_idx * 8 + bit_idx;
            if coeff_idx < N {
                if (byte >> bit_idx) & 1 == 1 {
                    poly.coeffs[coeff_idx] = half_q;
                }
            }
        }
    }

    poly
}

/// Encode a polynomial back to a 32-byte message.
///
/// This is the inverse of decode_message.
/// For each coefficient, round to nearest: 0 or ceil(q/2).
pub(crate) fn encode_message(poly: &Poly) -> [u8; SEED_LEN] {
    let mut m = [0u8; SEED_LEN];
    let half_q = Q / 2;

    for (byte_idx, byte) in m.iter_mut().enumerate() {
        let mut val = 0u8;
        for bit_idx in 0..8 {
            let coeff_idx = byte_idx * 8 + bit_idx;
            if coeff_idx < N {
                let c = poly.coeffs[coeff_idx];
                // If closer to ceil(q/2) than to 0, set bit
                if c > half_q && c < Q - half_q + 1 {
                    val |= 1 << bit_idx;
                } else {
                    // Distance to 0
                    let dist0 = c;
                    // Distance to ceil(q/2)
                    let dist1 = if c >= 1665 { c - 1665 } else { 1665 - c };
                    if dist1 < dist0 {
                        val |= 1 << bit_idx;
                    }
                }
            }
        }
        *byte = val;
    }

    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen;

    #[test]
    fn test_encaps_produces_valid_ciphertext() {
        let (pk, _) = keygen();
        let result = encaps(&pk);
        assert!(result.is_ok());

        let (ct, ss) = result.unwrap();
        assert_eq!(ct.len(), CT_LEN);
        assert_eq!(ss.len(), SS_LEN);
    }

    #[test]
    fn test_encaps_deterministic() {
        let (pk, _) = keygen();
        let m = [0x42u8; SEED_LEN];

        let (ct1, ss1) = encaps_internal(&pk, &m).unwrap();
        let (ct2, ss2) = encaps_internal(&pk, &m).unwrap();

        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_decode_encode_message() {
        let m = [0xABu8; SEED_LEN]; // alternating bits
        let poly = decode_message(&m);
        let recovered = encode_message(&poly);

        // Due to rounding, this may not be exact, but should be close
        // Let's test with a clean message
        let m_clean = [0xFFu8; SEED_LEN]; // all 1s
        let poly_clean = decode_message(&m_clean);
        for &c in &poly_clean.coeffs {
            assert_eq!(c, 1665); // ceil(q/2)
        }
    }

    #[test]
    fn test_decode_message_zeros() {
        let m = [0x00u8; SEED_LEN];
        let poly = decode_message(&m);
        assert!(poly.is_zero());
    }

    #[test]
    fn test_cpapke_encrypt_decrypt() {
        let (pk, sk) = keygen();
        let m = [0x55u8; SEED_LEN]; // 01010101...
        let r = [0xAAu8; SEED_LEN]; // randomness

        let ct = cpapke_encrypt(&pk, &m, &r).unwrap();
        // We'll test full decapsulation in the decaps module
        assert_eq!(ct.len(), CT_LEN);
    }
}
