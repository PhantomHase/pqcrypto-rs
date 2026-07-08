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
    assert_hash_eq("ML-KEM-768 PK", &pk_bytes, "605a1583f2f42c2622d4bb3714033272ba2528b8257fe30aeca1f7d2d88d4d8b");
    assert_hash_eq("ML-KEM-768 SK", &sk_bytes, "367250dc206192f0109a2dc4674ec4e38eb0b8ff04caf9d0bfd9979c2512e204");

    // Verify keygen determinism (second run produces identical outputs)
    let (pk2, sk2) = pqcrypto_kem::api::keygen_internal(&d, &z);
    assert_eq!(pk_bytes, pk2.to_bytes());
    assert_eq!(sk_bytes, sk2.to_bytes());

    // 2. Encapsulation
    let m = [0x03u8; 32];
    let (ct, ss) = pqcrypto_kem::api::encapsulate_internal(&pk, &m).unwrap();

    // Verify encapsulation output matches expected hashes
    assert_hash_eq("ML-KEM-768 CT", ct.as_bytes(), "a4c55e7793613283daf010b7263e7e1b00234f9edbdf37dabd1834a8e96ffbc0");
    assert_hash_eq("ML-KEM-768 SS", ss.as_bytes(), "6f08ef3a9d5d06345f305fd408bc15afb1db48fb7de3aec4eda409db6cb858d6");

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
    assert_hash_eq("ML-DSA-65 PK", &pk_bytes, "f3df70f1edfc742f683032980e37021752b5b5d73330e301853635bba6a0a905");
    assert_hash_eq("ML-DSA-65 SK", &sk_bytes, "f4bcd787b8981fba4039dbc933023f2c842295ca3eb2ba7603bad8c580f08781");

    // Verify keygen determinism
    let (pk2, sk2) = pqcrypto_sign::api::keygen_internal(&zeta);
    assert_eq!(pk_bytes, pk2.to_bytes());
    assert_eq!(sk_bytes, sk2.to_bytes());

    // 2. Signing
    let msg = b"ML-DSA KAT test message";
    let rnd = [0x02u8; 32];
    let sig = pqcrypto_sign::api::sign_internal(&sk, msg, &rnd).unwrap();
    let sig_bytes = sig.to_bytes();

    // Verify signature output matches expected hash
    assert_hash_eq("ML-DSA-65 SIG", &sig_bytes, "990aac924a7c82c91f7a0d9db691641715b10787078f16a3cd74af1f8128c59e");

    // Verify signing determinism
    let sig2 = pqcrypto_sign::api::sign_internal(&sk, msg, &rnd).unwrap();
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
            assert_hash_eq("SLH-DSA-128s SIG", &sig_bytes, "a7fe8e46d183f2bf9668d77ef0a47879b41731c6de0b5096e470b7a2a7295296");

            // 3. Verification
            assert!(pqcrypto_sign::slh_dsa::verify(&pk, slh_msg, &sig));
        })
        .unwrap();

    handle.join().unwrap();
}

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

#[test]
fn test_ml_kem_768_acvp_kat() {
    let d = decode_hex("d4c184a441e8c9528e578c93b3b4bf2a64c484a441e8c9528e578c93b3b4bf2a");
    let z = decode_hex("24a73693240bc973e7e2c9ef802e3b2e59dfbe823528b9d03d3cbe76bd7a1b02");
    let m = decode_hex("4a9b5f903a2072a392cbbd4c82c3f87c938d281a95e7c8b0e8c89b2b2b1a1a5b");

    let d_arr: [u8; 32] = d.try_into().expect("d must be 32 bytes");
    let z_arr: [u8; 32] = z.try_into().expect("z must be 32 bytes");
    let m_arr: [u8; 32] = m.try_into().expect("m must be 32 bytes");

    // 1. Key generation
    let (pk, sk) = pqcrypto_kem::api::keygen_internal(&d_arr, &z_arr);
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    // Verify deterministic key output matches expected hashes
    assert_hash_eq("ML-KEM-768 PK ACVP", &pk_bytes, "18046e61f02a02b76461d09a3aecd3b91a2eec39e92e51123cd1846848c97a38");
    assert_hash_eq("ML-KEM-768 SK ACVP", &sk_bytes, "07389c0c4c47e178cc9719e46c16d833297ac31d084416252c2cbcda62868ab9");

    // Verify keygen determinism
    let (pk2, sk2) = pqcrypto_kem::api::keygen_internal(&d_arr, &z_arr);
    assert_eq!(pk_bytes, pk2.to_bytes());
    assert_eq!(sk_bytes, sk2.to_bytes());

    // 2. Encapsulation
    let (ct, ss) = pqcrypto_kem::api::encapsulate_internal(&pk, &m_arr).unwrap();

    // Verify encapsulation output matches expected hashes
    assert_hash_eq("ML-KEM-768 CT ACVP", ct.as_bytes(), "a987bf90d8ab7f6a5bb8c4d6c03dfe951e4b4a18309f755bb818bd4a1606ab55");
    assert_hash_eq("ML-KEM-768 SS ACVP", ss.as_bytes(), "7cb07ae12f31a1e0a591eed7498990c9ed0694e915e4f733a24b47f95cafe6f0");

    // Verify encaps determinism
    let (ct2, ss2) = pqcrypto_kem::api::encapsulate_internal(&pk, &m_arr).unwrap();
    assert_eq!(ct.as_bytes(), ct2.as_bytes());
    assert_eq!(ss.as_bytes(), ss2.as_bytes());

    // 3. Decapsulation
    let recovered_ss = pqcrypto_kem::api::decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss.as_bytes(), recovered_ss.as_bytes());
}

#[test]
fn test_ml_dsa_65_acvp_kat() {
    let zeta = decode_hex("7c3bcbc52cf91f1b2b8d5a2d04f2f0fcf0bcfad6f73e721a3dc8f64585bc6c85");
    let msg = b"ML-DSA KAT test message";
    let rnd = decode_hex("24a73693240bc973e7e2c9ef802e3b2e59dfbe823528b9d03d3cbe76bd7a1b02");

    let zeta_arr: [u8; 32] = zeta.try_into().expect("zeta must be 32 bytes");
    let rnd_arr: [u8; 32] = rnd.try_into().expect("rnd must be 32 bytes");

    // 1. Key generation
    let (pk, sk) = pqcrypto_sign::api::keygen_internal(&zeta_arr);
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    // Verify deterministic key output matches expected hashes
    assert_hash_eq("ML-DSA-65 PK ACVP", &pk_bytes, "95a386b10c4b58d5ddcac20332cface1cdb330fdc81c852d358746b52ca83dd2");
    assert_hash_eq("ML-DSA-65 SK ACVP", &sk_bytes, "88a22e9a0569216aa2ac7a88e41e423377745dc7a3f3252015da6df145bf0cfc");

    // Verify keygen determinism
    let (pk2, sk2) = pqcrypto_sign::api::keygen_internal(&zeta_arr);
    assert_eq!(pk_bytes, pk2.to_bytes());
    assert_eq!(sk_bytes, sk2.to_bytes());

    // 2. Signing
    let sig = pqcrypto_sign::api::sign_internal(&sk, msg, &rnd_arr).unwrap();
    let sig_bytes = sig.to_bytes();

    // Verify signature output matches expected hash
    assert_hash_eq("ML-DSA-65 SIG ACVP", &sig_bytes, "c8f82c46b9c883db1fad4b72f9c2079ff3a88fd686a5b97270ba6675b3f31e3a");

    // Verify signing determinism
    let sig2 = pqcrypto_sign::api::sign_internal(&sk, msg, &rnd_arr).unwrap();
    assert_eq!(sig_bytes, sig2.to_bytes());

    // 3. Verification
    assert!(pqcrypto_sign::api::verify(&pk, msg, &sig));
}

#[test]
fn test_slh_dsa_128s_acvp_kat() {
    let sk_seed = decode_hex("7c3bcbc52cf91f1b2b8d5a2d04f2f0fc");
    let prf_key = decode_hex("f0bcfad6f73e721a3dc8f64585bc6c85");
    let pk_seed = decode_hex("24a73693240bc973e7e2c9ef802e3b2e");
    let msg = b"SLH-DSA KAT test message";
    let opt_rand = decode_hex("59dfbe823528b9d03d3cbe76bd7a1b02");

    let sk_seed_arr: [u8; 16] = sk_seed.try_into().expect("sk_seed must be 16 bytes");
    let prf_key_arr: [u8; 16] = prf_key.try_into().expect("prf_key must be 16 bytes");
    let pk_seed_arr: [u8; 16] = pk_seed.try_into().expect("pk_seed must be 16 bytes");
    let opt_rand_arr: [u8; 16] = opt_rand.try_into().expect("opt_rand must be 16 bytes");

    // 1. Key generation
    let (pk, sk) = pqcrypto_sign::slh_dsa::keygen_internal(&sk_seed_arr, &prf_key_arr, &pk_seed_arr);

    // Verify deterministic key output matches expected hashes
    assert_hash_eq("SLH-DSA-128s PK_SEED ACVP", &pk.pk_seed, "307d8b3505487a08efd162a55a7dd4535eae84677a13c21b1870ae18c07ae823");
    assert_hash_eq("SLH-DSA-128s PK_ROOT ACVP", &pk.pk_root, "77e2eb7eb48f5c007e3246855eb730bc4c565a3539d5c0971ca63caebfc18262");

    // Verify keygen determinism
    let (pk2, sk2) = pqcrypto_sign::slh_dsa::keygen_internal(&sk_seed_arr, &prf_key_arr, &pk_seed_arr);
    assert_eq!(pk.pk_seed, pk2.pk_seed);
    assert_eq!(pk.pk_root, pk2.pk_root);
    assert_eq!(sk.sk_seed, sk2.sk_seed);
    assert_eq!(sk.prf_key, sk2.prf_key);

    // 2. Signing (runs in a separate thread with a larger stack size to prevent stack overflow on Windows)
    let handle = std::thread::Builder::new()
        .name("slh_dsa_sign_thread".to_string())
        .stack_size(8 * 1024 * 1024) // 8 MB stack
        .spawn(move || {
            let sig = pqcrypto_sign::slh_dsa::sign_internal(&sk, msg, &opt_rand_arr);

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
            assert_hash_eq("SLH-DSA-128s SIG ACVP", &sig_bytes, "7ec2aa57eb9a90565e82c6e773ac29637c4f5a3c863ed45d82d42db269879232");

            // 3. Verification
            assert!(pqcrypto_sign::slh_dsa::verify(&pk, msg, &sig));
        })
        .unwrap();

    handle.join().unwrap();
}
