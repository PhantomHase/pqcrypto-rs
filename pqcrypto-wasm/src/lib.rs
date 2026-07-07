use base64::{engine::general_purpose::STANDARD, Engine as _};
use wasm_bindgen::prelude::*;

// ============================================================================
// Encoding/Decoding Helpers
// ============================================================================

fn decode_input(s: &str, expected_len: usize) -> Result<(Vec<u8>, bool), String> {
    let trimmed = s.trim();

    // Check if it has definite base64 characters
    let has_b64_chars = trimmed
        .chars()
        .any(|c| matches!(c, 'g'..='z' | 'G'..='Z' | '+' | '/' | '='));

    if has_b64_chars {
        let decoded = STANDARD
            .decode(trimmed)
            .map_err(|e| format!("Invalid base64 encoding: {}", e))?;
        if decoded.len() != expected_len {
            return Err(format!(
                "Invalid length: expected {} bytes, got {}",
                expected_len,
                decoded.len()
            ));
        }
        return Ok((decoded, true));
    }

    // Check if it's hex by trying to decode it
    if let Ok(decoded) = hex::decode(trimmed) {
        if decoded.len() == expected_len {
            return Ok((decoded, false));
        }
    }

    // Otherwise, try decoding as base64
    if let Ok(decoded) = STANDARD.decode(trimmed) {
        if decoded.len() == expected_len {
            return Ok((decoded, true));
        }
    }

    Err(format!(
        "Input does not match expected length of {} bytes as hex or base64",
        expected_len
    ))
}

fn encode_output(bytes: &[u8], use_b64: bool) -> String {
    if use_b64 {
        STANDARD.encode(bytes)
    } else {
        hex::encode(bytes)
    }
}

// ============================================================================
// ML-KEM-768
// ============================================================================

#[wasm_bindgen]
pub struct MlKemKeyPair {
    pubkey: String,
    seckey: String,
}

#[wasm_bindgen]
impl MlKemKeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> String {
        self.pubkey.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> String {
        self.seckey.clone()
    }
}

#[wasm_bindgen]
pub struct MlKemEncapsResult {
    ciphertext: String,
    shared_secret: String,
}

#[wasm_bindgen]
impl MlKemEncapsResult {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> String {
        self.ciphertext.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> String {
        self.shared_secret.clone()
    }
}

#[wasm_bindgen]
pub fn ml_kem_768_keygen() -> MlKemKeyPair {
    let (pk, sk) = pqcrypto_kem::api::keygen();
    MlKemKeyPair {
        pubkey: hex::encode(pk.to_bytes()),
        seckey: hex::encode(sk.to_bytes()),
    }
}

#[wasm_bindgen]
pub fn ml_kem_768_encapsulate(pk_hex_or_b64: &str) -> Result<MlKemEncapsResult, String> {
    let (pk_bytes, is_b64) = decode_input(pk_hex_or_b64, 1184)?;
    let pk = pqcrypto_kem::api::MlKem768PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    let (ct, ss) =
        pqcrypto_kem::api::encapsulate(&pk).map_err(|e| format!("Encapsulation failed: {}", e))?;
    Ok(MlKemEncapsResult {
        ciphertext: encode_output(ct.as_bytes(), is_b64),
        shared_secret: encode_output(ss.as_bytes(), is_b64),
    })
}

#[wasm_bindgen]
pub fn ml_kem_768_decapsulate(sk_hex_or_b64: &str, ct_hex_or_b64: &str) -> Result<String, String> {
    let (sk_bytes, sk_is_b64) = decode_input(sk_hex_or_b64, 2400)?;
    let (ct_bytes, ct_is_b64) = decode_input(ct_hex_or_b64, 1088)?;
    let is_b64 = sk_is_b64 || ct_is_b64;

    let sk = pqcrypto_kem::api::MlKem768SecretKey::from_bytes(&sk_bytes)
        .map_err(|e| format!("Invalid secret key: {}", e))?;

    let mut ct_arr = [0u8; pqcrypto_kem::CT_LEN];
    ct_arr.copy_from_slice(&ct_bytes);
    let ct = pqcrypto_kem::api::MlKem768Ciphertext::from_bytes(&ct_arr);

    let ss = pqcrypto_kem::api::decapsulate(&sk, &ct)
        .map_err(|e| format!("Decapsulation failed: {}", e))?;
    Ok(encode_output(ss.as_bytes(), is_b64))
}

// ============================================================================
// ML-DSA-65
// ============================================================================

#[wasm_bindgen]
pub struct MlDsaKeyPair {
    pubkey: String,
    seckey: String,
}

#[wasm_bindgen]
impl MlDsaKeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> String {
        self.pubkey.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> String {
        self.seckey.clone()
    }
}

#[wasm_bindgen]
pub fn ml_dsa_65_keygen() -> MlDsaKeyPair {
    let (pk, sk) = pqcrypto_sign::api::keygen();
    MlDsaKeyPair {
        pubkey: hex::encode(pk.to_bytes()),
        seckey: hex::encode(sk.to_bytes()),
    }
}

#[wasm_bindgen]
pub fn ml_dsa_65_sign(sk_hex_or_b64: &str, message: &[u8]) -> Result<String, String> {
    let (sk_bytes, is_b64) = decode_input(sk_hex_or_b64, 2912)?;
    let sk = pqcrypto_sign::api::MlDsa65SecretKey::from_bytes(&sk_bytes)
        .map_err(|e| format!("Invalid secret key: {}", e))?;
    let sig = pqcrypto_sign::api::sign(&sk, message);
    Ok(encode_output(&sig.to_bytes(), is_b64))
}

#[wasm_bindgen]
pub fn ml_dsa_65_verify(
    pk_hex_or_b64: &str,
    message: &[u8],
    sig_hex_or_b64: &str,
) -> Result<bool, String> {
    let (pk_bytes, _pk_is_b64) = decode_input(pk_hex_or_b64, 1952)?;
    let (sig_bytes, _sig_is_b64) = decode_input(sig_hex_or_b64, 6704)?;
    let pk = pqcrypto_sign::api::MlDsa65PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    let sig = pqcrypto_sign::api::MlDsa65Signature::from_bytes(&sig_bytes)
        .map_err(|e| format!("Invalid signature: {}", e))?;
    Ok(pqcrypto_sign::api::verify(&pk, message, &sig))
}

// ============================================================================
// SLH-DSA-SHA2-128s
// ============================================================================

#[wasm_bindgen]
pub struct SlhDsaKeyPair {
    pubkey: String,
    seckey: String,
}

#[wasm_bindgen]
impl SlhDsaKeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> String {
        self.pubkey.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> String {
        self.seckey.clone()
    }
}

#[wasm_bindgen]
pub fn slh_dsa_128s_keygen() -> SlhDsaKeyPair {
    let (pk, sk) = pqcrypto_sign::slh_dsa::keygen();
    SlhDsaKeyPair {
        pubkey: hex::encode(serialize_slh_pk(&pk)),
        seckey: hex::encode(serialize_slh_sk(&sk)),
    }
}

#[wasm_bindgen]
pub fn slh_dsa_128s_sign(sk_hex_or_b64: &str, message: &[u8]) -> Result<String, String> {
    let (sk_bytes, is_b64) = decode_input(sk_hex_or_b64, 64)?;
    let sk = deserialize_slh_sk(&sk_bytes)?;
    let sig = pqcrypto_sign::slh_dsa::sign(&sk, message);
    Ok(encode_output(&serialize_slh_sig(&sig), is_b64))
}

#[wasm_bindgen]
pub fn slh_dsa_128s_verify(
    pk_hex_or_b64: &str,
    message: &[u8],
    sig_hex_or_b64: &str,
) -> Result<bool, String> {
    let (pk_bytes, _pk_is_b64) = decode_input(pk_hex_or_b64, 32)?;
    let (sig_bytes, _sig_is_b64) = decode_input(sig_hex_or_b64, 7836)?;
    let pk = deserialize_slh_pk(&pk_bytes)?;
    let sig = deserialize_slh_sig(&sig_bytes)?;
    Ok(pqcrypto_sign::slh_dsa::verify(&pk, message, &sig))
}

// ============================================================================
// Serialization / Deserialization Helpers for SLH-DSA-SHA2-128s
// ============================================================================

fn serialize_slh_pk(pk: &pqcrypto_sign::slh_dsa::SlhDsaPublicKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(&pk.pk_seed);
    bytes.extend_from_slice(&pk.pk_root);
    bytes
}

fn deserialize_slh_pk(bytes: &[u8]) -> Result<pqcrypto_sign::slh_dsa::SlhDsaPublicKey, String> {
    if bytes.len() != 32 {
        return Err(format!(
            "Invalid public key length: expected 32, got {}",
            bytes.len()
        ));
    }
    let mut pk_seed = [0u8; 16];
    let mut pk_root = [0u8; 16];
    pk_seed.copy_from_slice(&bytes[0..16]);
    pk_root.copy_from_slice(&bytes[16..32]);
    Ok(pqcrypto_sign::slh_dsa::SlhDsaPublicKey { pk_seed, pk_root })
}

fn serialize_slh_sk(sk: &pqcrypto_sign::slh_dsa::SlhDsaSecretKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&sk.sk_seed);
    bytes.extend_from_slice(&sk.prf_key);
    bytes.extend_from_slice(&sk.pk_seed);
    bytes.extend_from_slice(&sk.pk_root);
    bytes
}

fn deserialize_slh_sk(bytes: &[u8]) -> Result<pqcrypto_sign::slh_dsa::SlhDsaSecretKey, String> {
    if bytes.len() != 64 {
        return Err(format!(
            "Invalid secret key length: expected 64, got {}",
            bytes.len()
        ));
    }
    let mut sk_seed = [0u8; 16];
    let mut prf_key = [0u8; 16];
    let mut pk_seed = [0u8; 16];
    let mut pk_root = [0u8; 16];
    sk_seed.copy_from_slice(&bytes[0..16]);
    prf_key.copy_from_slice(&bytes[16..32]);
    pk_seed.copy_from_slice(&bytes[32..48]);
    pk_root.copy_from_slice(&bytes[48..64]);
    Ok(pqcrypto_sign::slh_dsa::SlhDsaSecretKey {
        sk_seed,
        prf_key,
        pk_seed,
        pk_root,
    })
}

fn serialize_slh_sig(sig: &pqcrypto_sign::slh_dsa::SlhDsaSignature) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(7836);
    bytes.extend_from_slice(&sig.r);

    // FORS sig
    let (sk_sig, auth_paths) = &sig.fors_sig;
    for sk in sk_sig {
        bytes.extend_from_slice(sk);
    }
    for path in auth_paths {
        for node in path {
            bytes.extend_from_slice(node);
        }
    }

    // HT sig
    for (auth_path, wots_sig) in &sig.ht_sig {
        for node in auth_path {
            bytes.extend_from_slice(node);
        }
        for wots_node in wots_sig {
            bytes.extend_from_slice(wots_node);
        }
    }

    bytes.extend_from_slice(&sig.tree_idx.to_le_bytes());
    bytes.extend_from_slice(&sig.leaf_idx.to_le_bytes());

    bytes
}

fn deserialize_slh_sig(bytes: &[u8]) -> Result<pqcrypto_sign::slh_dsa::SlhDsaSignature, String> {
    if bytes.len() != 7836 {
        return Err(format!(
            "Invalid signature length: expected 7836, got {}",
            bytes.len()
        ));
    }

    let mut offset = 0;
    let mut r = [0u8; 16];
    r.copy_from_slice(&bytes[offset..offset + 16]);
    offset += 16;

    // FORS sig
    let mut sk_sig = Vec::with_capacity(12);
    for _ in 0..12 {
        let mut node = [0u8; 16];
        node.copy_from_slice(&bytes[offset..offset + 16]);
        sk_sig.push(node);
        offset += 16;
    }

    let mut auth_paths = Vec::with_capacity(12);
    for _ in 0..12 {
        let mut path = Vec::with_capacity(14);
        for _ in 0..14 {
            let mut node = [0u8; 16];
            node.copy_from_slice(&bytes[offset..offset + 16]);
            path.push(node);
            offset += 16;
        }
        auth_paths.push(path);
    }

    // HT sig
    let mut ht_sig = Vec::with_capacity(7);
    for _ in 0..7 {
        let mut auth_path = Vec::with_capacity(9);
        for _ in 0..9 {
            let mut node = [0u8; 16];
            node.copy_from_slice(&bytes[offset..offset + 16]);
            auth_path.push(node);
            offset += 16;
        }

        let mut wots_sig = [[0u8; 16]; 35];
        for i in 0..35 {
            wots_sig[i].copy_from_slice(&bytes[offset..offset + 16]);
            offset += 16;
        }

        ht_sig.push((auth_path, wots_sig));
    }

    let mut tree_idx_bytes = [0u8; 8];
    tree_idx_bytes.copy_from_slice(&bytes[offset..offset + 8]);
    let tree_idx = u64::from_le_bytes(tree_idx_bytes);
    offset += 8;

    let mut leaf_idx_bytes = [0u8; 4];
    leaf_idx_bytes.copy_from_slice(&bytes[offset..offset + 4]);
    let leaf_idx = u32::from_le_bytes(leaf_idx_bytes);

    Ok(pqcrypto_sign::slh_dsa::SlhDsaSignature {
        r,
        fors_sig: (sk_sig, auth_paths),
        ht_sig,
        tree_idx,
        leaf_idx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_ml_kem_768_round_trip() {
        let keypair = ml_kem_768_keygen();
        let pk = keypair.public_key();
        let sk = keypair.secret_key();

        // 1. Hex test
        let enc = ml_kem_768_encapsulate(&pk).unwrap();
        let ct = enc.ciphertext();
        let ss1 = enc.shared_secret();

        let ss2 = ml_kem_768_decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1, ss2);

        // 2. Base64 test
        let pk_bytes = hex::decode(&pk).unwrap();
        let pk_b64 = STANDARD.encode(&pk_bytes);
        let enc_b64 = ml_kem_768_encapsulate(&pk_b64).unwrap();
        assert!(STANDARD.decode(enc_b64.ciphertext()).is_ok());

        let sk_bytes = hex::decode(&sk).unwrap();
        let sk_b64 = STANDARD.encode(&sk_bytes);
        let ss_b64 = ml_kem_768_decapsulate(&sk_b64, &enc_b64.ciphertext()).unwrap();
        assert_eq!(enc_b64.shared_secret(), ss_b64);
    }

    #[test]
    fn test_wasm_ml_dsa_65_round_trip() {
        let keypair = ml_dsa_65_keygen();
        let pk = keypair.public_key();
        let sk = keypair.secret_key();

        let message = b"Hello WASM ML-DSA!";

        // Hex
        let sig = ml_dsa_65_sign(&sk, message).unwrap();
        let valid = ml_dsa_65_verify(&pk, message, &sig).unwrap();
        assert!(valid);

        let invalid = ml_dsa_65_verify(&pk, b"Wrong message", &sig).unwrap();
        assert!(!invalid);

        // Base64
        let sk_bytes = hex::decode(&sk).unwrap();
        let sk_b64 = STANDARD.encode(&sk_bytes);
        let sig_b64 = ml_dsa_65_sign(&sk_b64, message).unwrap();
        let _sig_bytes = STANDARD.decode(&sig_b64).unwrap();

        let pk_bytes = hex::decode(&pk).unwrap();
        let pk_b64 = STANDARD.encode(&pk_bytes);
        let valid_b64 = ml_dsa_65_verify(&pk_b64, message, &sig_b64).unwrap();
        assert!(valid_b64);
    }

    #[test]
    fn test_wasm_slh_dsa_128s_round_trip() {
        let keypair = slh_dsa_128s_keygen();
        let pk = keypair.public_key();
        let sk = keypair.secret_key();

        assert_eq!(pk.len(), 64); // hex representation of 32 bytes
        assert_eq!(sk.len(), 128); // hex representation of 64 bytes

        let message = b"Hello WASM SLH-DSA!";
        let sig = slh_dsa_128s_sign(&sk, message).unwrap();
        assert_eq!(sig.len(), 15672); // hex representation of 7836 bytes

        let valid = slh_dsa_128s_verify(&pk, message, &sig).unwrap();
        assert!(valid);

        let invalid = slh_dsa_128s_verify(&pk, b"Wrong message", &sig).unwrap();
        assert!(!invalid);

        // Base64 test
        let sk_bytes = hex::decode(&sk).unwrap();
        let sk_b64 = STANDARD.encode(&sk_bytes);
        let sig_b64 = slh_dsa_128s_sign(&sk_b64, message).unwrap();

        let pk_bytes = hex::decode(&pk).unwrap();
        let pk_b64 = STANDARD.encode(&pk_bytes);
        let valid_b64 = slh_dsa_128s_verify(&pk_b64, message, &sig_b64).unwrap();
        assert!(valid_b64);
    }

    #[test]
    fn test_wasm_ml_kem_768_boundary_conditions() {
        // Test empty public key
        assert!(ml_kem_768_encapsulate("").is_err());

        // Test too short public key
        assert!(ml_kem_768_encapsulate("0000").is_err());

        // Test empty secret key / ciphertext
        assert!(ml_kem_768_decapsulate("", &hex::encode(vec![0u8; 1088])).is_err());
        assert!(ml_kem_768_decapsulate(&hex::encode(vec![0u8; 2400]), "").is_err());
    }

    #[test]
    fn test_wasm_ml_dsa_65_boundary_conditions() {
        // Test empty secret key / message
        assert!(ml_dsa_65_sign("", b"hello").is_err());

        // Test too short secret key
        assert!(ml_dsa_65_sign("0000", b"hello").is_err());

        // Test empty public key / signature
        assert!(ml_dsa_65_verify("", b"hello", &hex::encode(vec![0u8; 6704])).is_err());
        assert!(ml_dsa_65_verify(&hex::encode(vec![0u8; 1952]), b"hello", "").is_err());

        // Test too short public key / signature
        assert!(ml_dsa_65_verify(
            &hex::encode(vec![0u8; 100]),
            b"hello",
            &hex::encode(vec![0u8; 6704])
        )
        .is_err());
        assert!(ml_dsa_65_verify(
            &hex::encode(vec![0u8; 1952]),
            b"hello",
            &hex::encode(vec![0u8; 100])
        )
        .is_err());
    }

    #[test]
    fn test_wasm_slh_dsa_128s_boundary_conditions() {
        // Test empty secret key
        assert!(slh_dsa_128s_sign("", b"hello").is_err());

        // Test wrong length secret key
        assert!(slh_dsa_128s_sign(&hex::encode(vec![0u8; 63]), b"hello").is_err());
        assert!(slh_dsa_128s_sign(&hex::encode(vec![0u8; 65]), b"hello").is_err());

        // Test empty/wrong length public key / signature
        assert!(slh_dsa_128s_verify("", b"hello", &hex::encode(vec![0u8; 7836])).is_err());
        assert!(slh_dsa_128s_verify(
            &hex::encode(vec![0u8; 31]),
            b"hello",
            &hex::encode(vec![0u8; 7836])
        )
        .is_err());
        assert!(slh_dsa_128s_verify(&hex::encode(vec![0u8; 32]), b"hello", "").is_err());
        assert!(slh_dsa_128s_verify(
            &hex::encode(vec![0u8; 32]),
            b"hello",
            &hex::encode(vec![0u8; 7835])
        )
        .is_err());
    }

    #[test]
    fn test_wasm_deserialized_keys_identity() {
        // 1. ML-KEM-768
        let kem_kp = ml_kem_768_keygen();
        let kem_pk = kem_kp.public_key();
        let kem_sk = kem_kp.secret_key();

        let kem_enc = ml_kem_768_encapsulate(&kem_pk).unwrap();
        let ct = kem_enc.ciphertext();
        let ss = kem_enc.shared_secret();

        // Decapsulate using original secret key bytes
        let ss_dec = ml_kem_768_decapsulate(&kem_sk, &ct).unwrap();
        assert_eq!(ss, ss_dec);

        // 2. ML-DSA-65
        let dsa_kp = ml_dsa_65_keygen();
        let dsa_pk = dsa_kp.public_key();
        let dsa_sk = dsa_kp.secret_key();
        let msg = b"Identity test message";

        let sig = ml_dsa_65_sign(&dsa_sk, msg).unwrap();

        // Verify with original pk
        assert!(ml_dsa_65_verify(&dsa_pk, msg, &sig).unwrap());

        // 3. SLH-DSA-128s
        let slh_kp = slh_dsa_128s_keygen();
        let slh_pk = slh_kp.public_key();
        let slh_sk = slh_kp.secret_key();

        let sig_slh = slh_dsa_128s_sign(&slh_sk, msg).unwrap();
        assert!(slh_dsa_128s_verify(&slh_pk, msg, &sig_slh).unwrap());
    }

    #[test]
    fn test_wasm_extra_boundary_conditions() {
        let kem_kp = ml_kem_768_keygen();
        let kem_pk = kem_kp.public_key();
        let kem_sk = kem_kp.secret_key();

        // 1. ML-KEM-768 key too long
        let mut long_pk = kem_pk.clone();
        long_pk.push_str("00");
        assert!(ml_kem_768_encapsulate(&long_pk).is_err());

        let enc = ml_kem_768_encapsulate(&kem_pk).unwrap();
        let ct = enc.ciphertext();

        let mut long_sk = kem_sk.clone();
        long_sk.push_str("00");
        assert!(ml_kem_768_decapsulate(&long_sk, &ct).is_err());

        // 2. ML-DSA-65 key / signature too long
        let dsa_kp = ml_dsa_65_keygen();
        let dsa_pk = dsa_kp.public_key();
        let dsa_sk = dsa_kp.secret_key();
        let msg = b"test";
        let sig = ml_dsa_65_sign(&dsa_sk, msg).unwrap();

        let mut long_dsa_pk = dsa_pk.clone();
        long_dsa_pk.push_str("00");
        assert!(ml_dsa_65_verify(&long_dsa_pk, msg, &sig).is_err());

        let mut long_sig = sig.clone();
        long_sig.push_str("00");
        assert!(ml_dsa_65_verify(&dsa_pk, msg, &long_sig).is_err());
    }

    #[test]
    fn test_dsa_sk_len_mismatch() {
        let dsa_kp = ml_dsa_65_keygen();
        let dsa_sk = dsa_kp.secret_key();

        // Assert that the actual secret key size is 5824 hex characters
        assert_eq!(dsa_sk.len(), 5824);
    }
}
