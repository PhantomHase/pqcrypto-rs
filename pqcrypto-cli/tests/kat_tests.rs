use pqcrypto_core::sym::sha3_256;

fn assert_hash_eq(name: &str, bytes: &[u8], expected_hex: &str) {
    let hash = sha3_256(bytes);
    let mut hash_hex = String::with_capacity(64);
    for b in hash {
        hash_hex.push_str(&format!("{:02x}", b));
    }
    assert_eq!(
        hash_hex, expected_hex,
        "Hash mismatch for {}: expected {}, got {}",
        name, expected_hex, hash_hex
    );
}

#[test]
fn test_ml_kem_768_kat() {
    let d = [0x01u8; 32];
    let z = [0x02u8; 32];

    // 1. Key generation
    let (pk, sk) = pqcrypto_kem::api::keygen_internal(&d, &z);
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    // Verify deterministic key output matches expected hashes
    assert_hash_eq("ML-KEM-768 PK", &pk_bytes, "e2ea85ac92e61fe28dc0f022f7aca465242c6a9c43a44c15f01862491cbd5e3b");
    assert_hash_eq("ML-KEM-768 SK", &sk_bytes, "19dc6f48c8f5bff40a841c6615750f413d5fb7fa3374a440995fa747db11d8b1");

    // Verify keygen determinism (second run produces identical outputs)
    let (pk2, sk2) = pqcrypto_kem::api::keygen_internal(&d, &z);
    assert_eq!(pk_bytes, pk2.to_bytes());
    assert_eq!(sk_bytes, sk2.to_bytes());

    // 2. Encapsulation
    let m = [0x03u8; 32];
    let (ct, ss) = pqcrypto_kem::api::encapsulate_internal(&pk, &m).unwrap();

    // Verify encapsulation output matches expected hashes
    assert_hash_eq("ML-KEM-768 CT", ct.as_bytes(), "70b6faff65cc74637944186b578bb98b1d089a6dff2200f148ff705035b0f58c");
    assert_hash_eq("ML-KEM-768 SS", ss.as_bytes(), "54d1f1238d890e815112f20b91ad159b8b7f9e3a7557740be53efdc4e428e5ef");

    // Verify encaps determinism
    let (ct2, ss2) = pqcrypto_kem::api::encapsulate_internal(&pk, &m).unwrap();
    assert_eq!(ct.as_bytes(), ct2.as_bytes());
    assert_eq!(ss.as_bytes(), ss2.as_bytes());

    // 3. Decapsulation
    let recovered_ss = pqcrypto_kem::api::decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss.as_bytes(), recovered_ss.as_bytes());
}

#[test]
fn test_ml_dsa_65_kat() {
    let zeta = [0x01u8; 32];

    // 1. Key generation
    let (pk, sk) = pqcrypto_sign::api::keygen_internal(&zeta);
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    // Verify deterministic key output matches expected hashes
    assert_hash_eq("ML-DSA-65 PK", &pk_bytes, "debd41f1daabc054518e6190fdf61ac4b179580201d6317ef0fbf5e71d652482");
    assert_hash_eq("ML-DSA-65 SK", &sk_bytes, "f1ac4a792b15b6d8d100df735f3290c71133a0a7bf6756f1e4b0694aa4e7207c");

    // Verify keygen determinism
    let (pk2, sk2) = pqcrypto_sign::api::keygen_internal(&zeta);
    assert_eq!(pk_bytes, pk2.to_bytes());
    assert_eq!(sk_bytes, sk2.to_bytes());

    // 2. Signing
    let msg = b"ML-DSA KAT test message";
    let rnd = [0x02u8; 32];
    let sig = pqcrypto_sign::api::sign_internal(&sk, msg, &rnd);
    let sig_bytes = sig.to_bytes();

    // Verify signature output matches expected hash
    assert_hash_eq("ML-DSA-65 SIG", &sig_bytes, "101db54bb0e382a683b67ce1e5f0fa656bf158ffe9461649d0fc0eac68e5e065");

    // Verify signing determinism
    let sig2 = pqcrypto_sign::api::sign_internal(&sk, msg, &rnd);
    assert_eq!(sig_bytes, sig2.to_bytes());

    // 3. Verification
    assert!(pqcrypto_sign::api::verify(&pk, msg, &sig));
}

#[test]
fn test_slh_dsa_128s_kat() {
    let sk_seed = [0x01u8; 16];
    let prf_key = [0x02u8; 16];
    let pk_seed = [0x03u8; 16];

    // 1. Key generation
    let (pk, sk) = pqcrypto_sign::slh_dsa::keygen_internal(&sk_seed, &prf_key, &pk_seed);

    // Verify deterministic key output matches expected hashes
    assert_hash_eq("SLH-DSA-128s PK_SEED", &pk.pk_seed, "180f21546ec618e854cd75c469686da6370ab1643e1d52a25f9cac3ecd213532");
    assert_hash_eq("SLH-DSA-128s PK_ROOT", &pk.pk_root, "96dd59b4b6ab40b4f5e7a717e5536aec4d84d4b7ce9d47c45483a6c1c21f393c");

    // Verify keygen determinism
    let (pk2, sk2) = pqcrypto_sign::slh_dsa::keygen_internal(&sk_seed, &prf_key, &pk_seed);
    assert_eq!(pk.pk_seed, pk2.pk_seed);
    assert_eq!(pk.pk_root, pk2.pk_root);
    assert_eq!(sk.sk_seed, sk2.sk_seed);
    assert_eq!(sk.prf_key, sk2.prf_key);

    // 2. Signing (runs in a separate thread with a larger stack size to prevent stack overflow on Windows)
    let slh_msg = b"SLH-DSA KAT test message";
    let opt_rand = [0x04u8; 16];

    let handle = std::thread::Builder::new()
        .name("slh_dsa_sign_thread".to_string())
        .stack_size(8 * 1024 * 1024) // 8 MB stack
        .spawn(move || {
            let sig = pqcrypto_sign::slh_dsa::sign_internal(&sk, slh_msg, &opt_rand);

            // Serialize signature components to compute the hash
            let mut sig_bytes = Vec::new();
            sig_bytes.extend_from_slice(&sig.r);
            for val in &sig.fors_sig.0 {
                sig_bytes.extend_from_slice(val);
            }
            for path in &sig.fors_sig.1 {
                for val in path {
                    sig_bytes.extend_from_slice(val);
                }
            }
            for (auth_path, siblings) in &sig.ht_sig {
                for val in auth_path {
                    sig_bytes.extend_from_slice(val);
                }
                for val in siblings {
                    sig_bytes.extend_from_slice(val);
                }
            }

            // Verify signature output matches expected hash
            assert_hash_eq("SLH-DSA-128s SIG", &sig_bytes, "0263cf540a52711f8710dbda152b60235916de0ba8fed46262c494e1f8f492b4");

            // 3. Verification
            assert!(pqcrypto_sign::slh_dsa::verify(&pk, slh_msg, &sig));
        })
        .unwrap();

    handle.join().unwrap();
}
