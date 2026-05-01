//! ML-KEM-768 Key Generation.
//!
//! Generates a public key and secret key pair according to FIPS 203 Section 5.1.
//!
//! Algorithm:
//! 1. Generate random seed d (32 bytes) and z (32 bytes)
//! 2. (ρ, σ) = G(d || k) — expand seed into matrix seed ρ and noise seed σ
//! 3. Generate matrix A_hat from ρ using sampleNTT
//! 4. Sample secret vector s from CBD_η₁(σ)
//! 5. Sample error vector e from CBD_η₁(σ)
//! 6. t = NTT⁻¹(A_hat · NTT(s)) + e  (in NTT domain: t_hat = A_hat · s_hat + e_hat)
//! 7. pk = (t_hat, ρ), sk = s_hat
//! 8. Return (pk, sk)

use pqcrypto_core::ntt::{ntt_forward, ntt_inverse, ntt_pointwise};
use pqcrypto_core::poly::Poly;
use pqcrypto_core::sampling::{sample_cbd, sample_cbd_vec, sample_uniform};
use pqcrypto_core::sym::g;
use pqcrypto_core::N;

use crate::{K, ETA1, SEED_LEN, PK_LEN, SK_LEN};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A public key for ML-KEM-768.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// t_hat: NTT representation of t (k polynomials)
    pub t_hat: Vec<Poly>,
    /// ρ: matrix seed (32 bytes)
    pub rho: [u8; SEED_LEN],
}

/// A secret key for ML-KEM-768.
#[derive(Clone, Debug)]
pub struct SecretKey {
    /// s_hat: NTT representation of secret vector
    pub s_hat: Vec<Poly>,
    /// Hash of public key (for FO transform)
    pub pk_hash: [u8; SEED_LEN],
    /// Implicit rejection value z
    pub z: [u8; SEED_LEN],
    /// Full public key (needed for decapsulation re-encryption)
    pub pk: PublicKey,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Zeroize all sensitive key material
        for p in &mut self.s_hat {
            p.coeffs.iter_mut().for_each(|c| *c = 0);
        }
        self.pk_hash.iter_mut().for_each(|b| *b = 0);
        self.z.iter_mut().for_each(|b| *b = 0);
    }
}

/// Generate the matrix A_hat from seed ρ.
///
/// A_hat[i][j] = SampleNTT(ρ || j || i) for i, j in [0, k)
///
/// Each element is a polynomial in NTT form.
fn generate_matrix_a(rho: &[u8; SEED_LEN]) -> Vec<Vec<Poly>> {
    let mut a_hat = vec![vec![Poly::zero(); K]; K];

    for i in 0..K {
        for j in 0..K {
            // Seed for this matrix element: ρ || j || i
            let mut seed_input = Vec::with_capacity(SEED_LEN + 2);
            seed_input.extend_from_slice(rho);
            seed_input.push(j as u8);
            seed_input.push(i as u8);

            // Sample polynomial from uniform distribution using SHAKE-128
            let bytes = pqcrypto_core::sym::shake128_xof(&seed_input, 1024);
            a_hat[i][j] = sample_uniform(&bytes);
            ntt_forward(&mut a_hat[i][j]);
        }
    }

    a_hat
}

/// Generate a key pair for ML-KEM-768.
///
/// Returns (public_key, secret_key).
///
/// Uses OsRng for secure random number generation.
pub fn keygen() -> (PublicKey, SecretKey) {
    use rand::RngCore;

    let mut rng = rand::thread_rng();

    // Step 1: Generate random seeds
    let mut d = [0u8; SEED_LEN];
    let mut z = [0u8; SEED_LEN];
    rng.fill_bytes(&mut d);
    rng.fill_bytes(&mut z);

    keygen_internal(&d, &z)
}

/// Internal key generation with explicit seeds (for testing/KAT).
pub fn keygen_internal(d: &[u8; SEED_LEN], z: &[u8; SEED_LEN]) -> (PublicKey, SecretKey) {
    use pqcrypto_core::sym::{g, prf};

    // Step 2: (ρ, σ) = G(d || k)
    let mut g_input = Vec::with_capacity(SEED_LEN + 1);
    g_input.extend_from_slice(d);
    g_input.push(K as u8);
    let g_out = g(&g_input);

    let mut rho = [0u8; SEED_LEN];
    let mut sigma = [0u8; SEED_LEN];
    rho.copy_from_slice(&g_out[..SEED_LEN]);
    sigma.copy_from_slice(&g_out[SEED_LEN..2 * SEED_LEN]);

    // Step 3: Generate matrix A_hat
    let a_hat = generate_matrix_a(&rho);

    // Step 4: Sample secret vector s from CBD_η₁(σ)
    // Each polynomial uses a different nonce: 0, 1, ..., k-1
    let mut s_hat: Vec<Poly> = Vec::with_capacity(K);
    for i in 0..K {
        let s_bytes = prf(ETA1, &sigma, i as u8);
        let mut s_i = sample_cbd(ETA1, &s_bytes);
        ntt_forward(&mut s_i);
        s_hat.push(s_i);
    }

    // Step 5: Sample error vector e from CBD_η₁(σ)
    // Nonces continue from k to 2k-1
    let mut e_hat: Vec<Poly> = Vec::with_capacity(K);
    for i in 0..K {
        let e_bytes = prf(ETA1, &sigma, (K + i) as u8);
        let mut e_i = sample_cbd(ETA1, &e_bytes);
        ntt_forward(&mut e_i);
        e_hat.push(e_i);
    }

    // Step 6: t_hat = A_hat · s_hat + e_hat (in NTT domain)
    let mut t_hat = vec![Poly::zero(); K];
    for i in 0..K {
        let mut sum = Poly::zero();
        for j in 0..K {
            let product = ntt_pointwise(&a_hat[i][j], &s_hat[j]);
            sum = sum.add(&product);
        }
        t_hat[i] = sum.add(&e_hat[i]);
    }

    // Step 7: Create public key and secret key
    let pk = PublicKey {
        t_hat: t_hat.clone(),
        rho,
    };

    // Compute hash of public key for FO transform
    let pk_bytes = encode_pk(&pk);
    let pk_hash = pqcrypto_core::sym::sha3_256(&pk_bytes);

    let sk = SecretKey {
        s_hat,
        pk_hash,
        z: *z,
        pk: pk.clone(),
    };

    (pk, sk)
}

/// Encode public key to bytes: (t_hat compressed || ρ)
pub fn encode_pk(pk: &PublicKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PK_LEN);

    // Encode t_hat: each polynomial as 12*n/8 = 384 bytes (12 bits per coefficient)
    for poly in &pk.t_hat {
        // Encode coefficients as 12-bit little-endian
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for &c in &poly.coeffs {
            acc |= (c as u32) << bits;
            bits += 12;
            while bits >= 8 {
                bytes.push((acc & 0xFF) as u8);
                acc >>= 8;
                bits -= 8;
            }
        }
        if bits > 0 {
            bytes.push((acc & 0xFF) as u8);
        }
    }

    // Append ρ
    bytes.extend_from_slice(&pk.rho);
    bytes
}

/// Decode public key from bytes.
pub fn decode_pk(bytes: &[u8]) -> Result<PublicKey, crate::KemError> {
    if bytes.len() < PK_LEN {
        return Err(crate::KemError::SerializationError(
            "Public key too short".into(),
        ));
    }

    let mut t_hat = Vec::with_capacity(K);
    let mut offset = 0;

    for _ in 0..K {
        let mut coeffs = [0u16; N];
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut coeff_idx = 0;

        while coeff_idx < N && offset < bytes.len() {
            acc |= (bytes[offset] as u32) << bits;
            offset += 1;
            bits += 8;
            while bits >= 12 && coeff_idx < N {
                coeffs[coeff_idx] = (acc & 0xFFF) as u16;
                acc >>= 12;
                bits -= 12;
                coeff_idx += 1;
            }
        }
        t_hat.push(Poly::from_coeffs(&coeffs));
    }

    let mut rho = [0u8; SEED_LEN];
    rho.copy_from_slice(&bytes[offset..offset + SEED_LEN]);

    Ok(PublicKey { t_hat, rho })
}

/// Encode secret key to bytes.
pub fn encode_sk(sk: &SecretKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SK_LEN);

    // Encode s_hat
    for poly in &sk.s_hat {
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for &c in &poly.coeffs {
            acc |= (c as u32) << bits;
            bits += 12;
            while bits >= 8 {
                bytes.push((acc & 0xFF) as u8);
                acc >>= 8;
                bits -= 8;
            }
        }
        if bits > 0 {
            bytes.push((acc & 0xFF) as u8);
        }
    }

    // Append pk_hash, z, and encoded pk
    bytes.extend_from_slice(&sk.pk_hash);
    bytes.extend_from_slice(&sk.z);
    bytes.extend_from_slice(&encode_pk(&sk.pk));
    bytes
}

/// Decode secret key from bytes.
pub fn decode_sk(bytes: &[u8]) -> Result<SecretKey, crate::KemError> {
    if bytes.len() < SK_LEN {
        return Err(crate::KemError::SerializationError(
            "Secret key too short".into(),
        ));
    }

    let mut s_hat = Vec::with_capacity(K);
    let mut offset = 0;

    for _ in 0..K {
        let mut coeffs = [0u16; N];
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut coeff_idx = 0;

        while coeff_idx < N && offset < bytes.len() {
            acc |= (bytes[offset] as u32) << bits;
            offset += 1;
            bits += 8;
            while bits >= 12 && coeff_idx < N {
                coeffs[coeff_idx] = (acc & 0xFFF) as u16;
                acc >>= 12;
                bits -= 12;
                coeff_idx += 1;
            }
        }
        s_hat.push(Poly::from_coeffs(&coeffs));
    }

    let mut pk_hash = [0u8; SEED_LEN];
    let mut z = [0u8; SEED_LEN];

    pk_hash.copy_from_slice(&bytes[offset..offset + SEED_LEN]);
    offset += SEED_LEN;
    z.copy_from_slice(&bytes[offset..offset + SEED_LEN]);
    offset += SEED_LEN;

    // Decode the embedded public key
    let pk = decode_pk(&bytes[offset..])?;

    Ok(SecretKey {
        s_hat,
        pk_hash,
        z,
        pk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_produces_valid_keys() {
        let (pk, sk) = keygen();

        // Public key should have k polynomials
        assert_eq!(pk.t_hat.len(), K);
        // Secret key should have k polynomials
        assert_eq!(sk.s_hat.len(), K);
        // rho should be non-zero (with overwhelming probability)
        assert_ne!(pk.rho, [0u8; SEED_LEN]);
    }

    #[test]
    fn test_keygen_deterministic() {
        let d = [0x42u8; SEED_LEN];
        let z = [0x24u8; SEED_LEN];

        let (pk1, sk1) = keygen_internal(&d, &z);
        let (pk2, sk2) = keygen_internal(&d, &z);

        assert_eq!(pk1.rho, pk2.rho);
        assert_eq!(pk1.t_hat, pk2.t_hat);
        // s_hat should be the same for same seeds
        assert_eq!(sk1.s_hat, sk2.s_hat);
    }

    #[test]
    fn test_pk_encoding_round_trip() {
        let (pk, _) = keygen();
        let encoded = encode_pk(&pk);
        assert_eq!(encoded.len(), PK_LEN);

        let decoded = decode_pk(&encoded).unwrap();
        assert_eq!(decoded.rho, pk.rho);
        for i in 0..K {
            assert_eq!(decoded.t_hat[i], pk.t_hat[i]);
        }
    }

    #[test]
    fn test_sk_encoding_round_trip() {
        let (_, sk) = keygen();
        let encoded = encode_sk(&sk);
        let decoded = decode_sk(&encoded).unwrap();

        assert_eq!(decoded.pk_hash, sk.pk_hash);
        assert_eq!(decoded.z, sk.z);
        for i in 0..K {
            assert_eq!(decoded.s_hat[i], sk.s_hat[i]);
        }
    }

    #[test]
    fn test_keygen_different_seeds() {
        let d1 = [1u8; SEED_LEN];
        let z1 = [2u8; SEED_LEN];
        let d2 = [3u8; SEED_LEN];
        let z2 = [4u8; SEED_LEN];

        let (pk1, _) = keygen_internal(&d1, &z1);
        let (pk2, _) = keygen_internal(&d2, &z2);

        assert_ne!(pk1.rho, pk2.rho);
    }
}
