//! Public API for ML-DSA-65 digital signatures.
//!
//! Provides a high-level interface for key generation, signing, and verification.

use crate::ml_dsa::{self, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
use crate::SignError;
use crate::ml_dsa_params::{SEED_LEN, PK_LEN, SK_LEN, SIG_LEN};

/// Generate a new ML-DSA-65 key pair.
///
/// Returns (public_key, secret_key).
pub fn keygen() -> (MlDsa65PublicKey, MlDsa65SecretKey) {
    let (pk, sk) = ml_dsa::keygen();
    (MlDsa65PublicKey(pk), MlDsa65SecretKey(sk))
}

/// Sign a message using ML-DSA-65.
///
/// Returns the signature.
pub fn sign(
    sk: &MlDsa65SecretKey,
    message: &[u8],
) -> MlDsa65Signature {
    let sig = ml_dsa::sign(&sk.0, message);
    MlDsa65Signature(sig)
}

/// Verify a signature.
///
/// Returns true if the signature is valid.
pub fn verify(
    pk: &MlDsa65PublicKey,
    message: &[u8],
    sig: &MlDsa65Signature,
) -> bool {
    ml_dsa::verify(&pk.0, message, &sig.0)
}

/// ML-DSA-65 public key.
#[derive(Clone, Debug)]
pub struct MlDsa65PublicKey(MlDsaPublicKey);

impl MlDsa65PublicKey {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.0.rho);
        // Encode t1 polynomials (10 bits per coefficient)
        for poly in &self.0.t1.polys {
            let mut acc: u32 = 0;
            let mut bits: u32 = 0;
            for &c in &poly.coeffs {
                acc |= ((c as u32) & 0x3FF) << bits;
                bits += 10;
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
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        if bytes.len() < SEED_LEN {
            return Err(SignError::SerializationError("Public key too short".into()));
        }

        let mut rho = [0u8; SEED_LEN];
        rho.copy_from_slice(&bytes[..SEED_LEN]);

        // Decode t1 polynomials
        let mut t1 = crate::ml_dsa::PolyVec::new(crate::ml_dsa_params::K);
        let mut offset = SEED_LEN;

        for i in 0..crate::ml_dsa_params::K {
            let mut acc: u32 = 0;
            let mut bits: u32 = 0;
            let mut coeff_idx = 0;

            while coeff_idx < crate::ml_dsa_params::N && offset < bytes.len() {
                acc |= (bytes[offset] as u32) << bits;
                offset += 1;
                bits += 8;
                while bits >= 10 && coeff_idx < crate::ml_dsa_params::N {
                    t1.polys[i].coeffs[coeff_idx] = (acc & 0x3FF) as i32;
                    acc >>= 10;
                    bits -= 10;
                    coeff_idx += 1;
                }
            }
        }

        Ok(Self(MlDsaPublicKey { rho, t1 }))
    }
}

/// ML-DSA-65 secret key.
#[derive(Clone, Debug)]
pub struct MlDsa65SecretKey(MlDsaSecretKey);

impl MlDsa65SecretKey {
    /// Serialize to bytes (simplified).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.0.rho);
        bytes.extend_from_slice(&self.0.k);
        bytes.extend_from_slice(&self.0.tr);
        // Encode s1 and s2 (η bits per coefficient)
        for poly in &self.0.s1.polys {
            for &c in &poly.coeffs {
                bytes.push((c + crate::ml_dsa_params::ETA as i32) as u8);
            }
        }
        for poly in &self.0.s2.polys {
            for &c in &poly.coeffs {
                bytes.push((c + crate::ml_dsa_params::ETA as i32) as u8);
            }
        }
        bytes
    }
}

/// ML-DSA-65 signature.
#[derive(Clone, Debug)]
pub struct MlDsa65Signature(MlDsaSignature);

impl MlDsa65Signature {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.0.c_tilde);
        // Encode z polynomials
        for poly in &self.0.z.polys {
            for &c in &poly.coeffs {
                bytes.extend_from_slice(&(c as i32).to_le_bytes());
            }
        }
        // Encode hint
        for poly in &self.0.h.polys {
            for &c in &poly.coeffs {
                bytes.push(c as u8);
            }
        }
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        if bytes.len() < SEED_LEN {
            return Err(SignError::SerializationError("Signature too short".into()));
        }

        let mut c_tilde = [0u8; SEED_LEN];
        c_tilde.copy_from_slice(&bytes[..SEED_LEN]);

        let mut offset = SEED_LEN;

        // Decode z
        let mut z = crate::ml_dsa::PolyVec::new(crate::ml_dsa_params::L);
        for i in 0..crate::ml_dsa_params::L {
            for j in 0..crate::ml_dsa_params::N {
                if offset + 4 <= bytes.len() {
                    z.polys[i].coeffs[j] = i32::from_le_bytes([
                        bytes[offset], bytes[offset + 1],
                        bytes[offset + 2], bytes[offset + 3],
                    ]);
                    offset += 4;
                }
            }
        }

        // Decode hint
        let mut h = crate::ml_dsa::PolyVec::new(crate::ml_dsa_params::K);
        for i in 0..crate::ml_dsa_params::K {
            for j in 0..crate::ml_dsa_params::N {
                if offset < bytes.len() {
                    h.polys[i].coeffs[j] = bytes[offset] as i32;
                    offset += 1;
                }
            }
        }

        Ok(Self(MlDsaSignature { c_tilde, z, h }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_api() {
        let (pk, sk) = keygen();
        let message = b"Hello, ML-DSA!";

        let sig = sign(&sk, message);
        assert!(verify(&pk, message, &sig));
    }

    #[test]
    fn test_signature_serialization() {
        let (_, sk) = keygen();
        let message = b"Serialization test";

        let sig = sign(&sk, message);
        let bytes = sig.to_bytes();
        let recovered = MlDsa65Signature::from_bytes(&bytes).unwrap();

        assert_eq!(sig.0.c_tilde, recovered.0.c_tilde);
    }

    #[test]
    fn test_public_key_serialization() {
        let (pk, _) = keygen();
        let bytes = pk.to_bytes();
        let recovered = MlDsa65PublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk.0.rho, recovered.0.rho);
    }
}
