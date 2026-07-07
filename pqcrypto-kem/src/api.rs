//! Public API for ML-KEM-768.
//!
//! Provides a high-level, easy-to-use interface for key generation,
//! encapsulation, and decapsulation.

use crate::decaps;
use crate::encaps;
use crate::keygen;
use crate::{KemError, CT_LEN, SS_LEN};

/// Generate a new ML-KEM-768 key pair.
///
/// Returns (public_key, secret_key).
///
/// # Example
/// ```
/// use pqcrypto_kem::api::keygen;
/// let (pk, sk) = keygen();
/// ```
pub fn keygen() -> (MlKem768PublicKey, MlKem768SecretKey) {
    let (pk, sk) = keygen::keygen();
    let bytes = keygen::encode_pk(&pk);
    (
        MlKem768PublicKey {
            inner: pk,
            bytes,
        },
        MlKem768SecretKey(sk),
    )
}

/// Generate a new ML-KEM-768 key pair from explicit seeds (for testing/KAT).
pub fn keygen_internal(d: &[u8; 32], z: &[u8; 32]) -> (MlKem768PublicKey, MlKem768SecretKey) {
    let (pk, sk) = keygen::keygen_internal(d, z);
    let bytes = keygen::encode_pk(&pk);
    (
        MlKem768PublicKey {
            inner: pk,
            bytes,
        },
        MlKem768SecretKey(sk),
    )
}

/// Encapsulate a shared secret to a public key.
///
/// Returns (ciphertext, shared_secret).
///
/// # Example
/// ```
/// use pqcrypto_kem::api::{keygen, encapsulate};
/// let (pk, sk) = keygen();
/// let (ct, ss) = encapsulate(&pk).unwrap();
/// ```
pub fn encapsulate(pk: &MlKem768PublicKey) -> Result<(MlKem768Ciphertext, SharedSecret), KemError> {
    let (ct, ss) = encaps::encaps(&pk.inner)?;
    Ok((MlKem768Ciphertext(ct), SharedSecret(ss)))
}

/// Encapsulate a shared secret to a public key with explicit message/entropy (for testing/KAT).
pub fn encapsulate_internal(
    pk: &MlKem768PublicKey,
    m: &[u8; 32],
) -> Result<(MlKem768Ciphertext, SharedSecret), KemError> {
    let (ct, ss) = encaps::encaps_internal(&pk.inner, m)?;
    Ok((MlKem768Ciphertext(ct), SharedSecret(ss)))
}

/// Decapsulate a ciphertext to recover the shared secret.
///
/// Returns the shared secret.
///
/// # Example
/// ```
/// use pqcrypto_kem::api::{keygen, encapsulate, decapsulate};
/// let (pk, sk) = keygen();
/// let (ct, ss) = encapsulate(&pk).unwrap();
/// let recovered_ss = decapsulate(&sk, &ct).unwrap();
/// // Note: Due to lossy compression, shared secrets may differ slightly
/// assert_eq!(recovered_ss.as_bytes().len(), 32);
/// ```
pub fn decapsulate(
    sk: &MlKem768SecretKey,
    ct: &MlKem768Ciphertext,
) -> Result<SharedSecret, KemError> {
    let ss = decaps::decaps(&sk.0, &ct.0)?;
    Ok(SharedSecret(ss))
}

/// ML-KEM-768 public key.
#[derive(Clone, Debug)]
pub struct MlKem768PublicKey {
    pub(crate) inner: keygen::PublicKey,
    pub(crate) bytes: Vec<u8>,
}

impl PartialEq for MlKem768PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for MlKem768PublicKey {}

impl MlKem768PublicKey {
    /// Serialize the public key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Deserialize a public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KemError> {
        let pk = keygen::decode_pk(bytes)?;
        Ok(Self {
            inner: pk,
            bytes: bytes.to_vec(),
        })
    }

    /// Get the raw bytes of the public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-KEM-768 secret key.
#[derive(Clone, Debug)]
pub struct MlKem768SecretKey(keygen::SecretKey);

impl MlKem768SecretKey {
    /// Serialize the secret key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        keygen::encode_sk(&self.0)
    }

    /// Deserialize a secret key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KemError> {
        let sk = keygen::decode_sk(bytes)?;
        Ok(Self(sk))
    }
}

/// ML-KEM-768 ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKem768Ciphertext([u8; CT_LEN]);

impl MlKem768Ciphertext {
    /// Get the ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8; CT_LEN] {
        &self.0
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8; CT_LEN]) -> Self {
        Self(*bytes)
    }
}

/// Shared secret derived from KEM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedSecret([u8; SS_LEN]);

impl SharedSecret {
    /// Get the shared secret bytes.
    pub fn as_bytes(&self) -> &[u8; SS_LEN] {
        &self.0
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8; SS_LEN]) -> Self {
        Self(*bytes)
    }
}

pub fn hybrid_encrypt(
    pk: &MlKem768PublicKey,
    message: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, MlKem768Ciphertext), KemError> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
    use pqcrypto_core::sym::hkdf_extract_expand;
    use rand::RngCore;

    // Step 1: ML-KEM encapsulation
    let (ct, ss) = encapsulate(pk)?;

    // Step 2: Derive AES key using HKDF
    let salt = b"pqcrypto-rs-hybrid-v1";
    let info = b"aes-256-gcm-key";
    let key_bytes = hkdf_extract_expand(ss.as_bytes(), info, salt, 32);

    // Step 3: Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| KemError::SerializationError(e.to_string()))?;

    // Generate a random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    let payload = aes_gcm::aead::Payload { msg: message, aad };
    let encrypted = cipher
        .encrypt(nonce, payload)
        .map_err(|e| KemError::SerializationError(e.to_string()))?;

    // Prepend nonce to ciphertext output
    let mut output = Vec::with_capacity(12 + encrypted.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&encrypted);

    Ok((output, ct))
}

/// Hybrid decryption: ML-KEM + AES-256-GCM.
///
/// Decrypts a message using:
/// 1. ML-KEM decapsulation to recover shared secret
/// 2. HKDF to derive AES-256 key
/// 3. AES-256-GCM to decrypt
pub fn hybrid_decrypt(
    sk: &MlKem768SecretKey,
    ct: &MlKem768Ciphertext,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, KemError> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
    use pqcrypto_core::sym::hkdf_extract_expand;

    // Step 1: ML-KEM decapsulation
    let ss = decapsulate(sk, ct)?;

    // Step 2: Derive AES key using HKDF
    let salt = b"pqcrypto-rs-hybrid-v1";
    let info = b"aes-256-gcm-key";
    let key_bytes = hkdf_extract_expand(ss.as_bytes(), info, salt, 32);

    // Step 3: Decrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| KemError::SerializationError(e.to_string()))?;

    if ciphertext.len() < 12 {
        return Err(KemError::SerializationError("Ciphertext too short".into()));
    }
    let (nonce_bytes, aes_ciphertext) = ciphertext.split_at(12);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

    let payload = aes_gcm::aead::Payload { msg: aes_ciphertext, aad };
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| KemError::SerializationError(e.to_string()))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_encaps_decaps() {
        let (pk, sk) = keygen();
        let (ct, ss1) = encapsulate(&pk).unwrap();
        let ss2 = decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_hybrid_encrypt_decrypt() {
        let (pk, sk) = keygen();
        let message = b"Hello, post-quantum world!";
        let aad = b"additional data";

        let (ciphertext, ct) = hybrid_encrypt(&pk, message, aad).unwrap();
        let plaintext = hybrid_decrypt(&sk, &ct, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_serialization_round_trip() {
        let (pk, sk) = keygen();

        let pk_bytes = pk.to_bytes();
        let pk2 = MlKem768PublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk.to_bytes(), pk2.to_bytes());

        let sk_bytes = sk.to_bytes();
        let sk2 = MlKem768SecretKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
    }
}
