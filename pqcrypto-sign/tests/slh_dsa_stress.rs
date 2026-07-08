use pqcrypto_sign::slh_dsa::{keygen, sign, verify};

#[test]
fn test_slh_dsa_large_and_empty_messages() {
    let (pk, sk) = keygen();

    // 1. Empty message
    let empty_msg = b"";
    let sig_empty = sign(&sk, empty_msg);
    assert!(verify(&pk, empty_msg, &sig_empty), "Empty message signature verification failed");

    // 2. Large message (1 MB)
    let large_msg = vec![0x5a; 1_000_000];
    let sig_large = sign(&sk, &large_msg);
    assert!(verify(&pk, &large_msg, &sig_large), "Large message signature verification failed");
}

#[test]
fn test_slh_dsa_adversarial_mutations() {
    let (pk, sk) = keygen();
    let message = b"Adversarial mutation test message for SLH-DSA FORS Domain Separation";
    let sig_orig = sign(&sk, message);

    // Ensure original signature verifies
    assert!(verify(&pk, message, &sig_orig), "Original signature verification failed");

    // 1. Mutate Message
    let mut mutated_message = message.to_vec();
    for i in 0..mutated_message.len() {
        mutated_message[i] ^= 0xff;
        assert!(!verify(&pk, &mutated_message, &sig_orig), "Verification succeeded on mutated message at byte {}", i);
        mutated_message[i] ^= 0xff; // restore
    }

    // 2. Mutate Signature randomizer R
    let mut sig = sig_orig.clone();
    for i in 0..sig.r.len() {
        let orig_val = sig.r[i];
        sig.r[i] ^= 1;
        assert!(!verify(&pk, message, &sig), "Verification succeeded on mutated randomizer R at byte {}", i);
        sig.r[i] = orig_val; // restore
    }

    // 3. Mutate tree_idx
    let mut sig = sig_orig.clone();
    sig.tree_idx ^= 1;
    assert!(!verify(&pk, message, &sig), "Verification succeeded on mutated tree_idx");
    sig.tree_idx ^= 1; // restore

    // 4. Mutate leaf_idx
    let mut sig = sig_orig.clone();
    sig.leaf_idx ^= 1;
    assert!(!verify(&pk, message, &sig), "Verification succeeded on mutated leaf_idx");
    sig.leaf_idx ^= 1; // restore

    // 5. Mutate FORS signature components
    // Mutate individual secret key elements in fors_sig.0
    let mut sig = sig_orig.clone();
    for i in 0..sig.fors_sig.0.len() {
        for j in 0..sig.fors_sig.0[i].len() {
            let orig_val = sig.fors_sig.0[i][j];
            sig.fors_sig.0[i][j] ^= 1;
            assert!(!verify(&pk, message, &sig), "Verification succeeded on mutated FORS sk element {}, byte {}", i, j);
            sig.fors_sig.0[i][j] = orig_val; // restore
        }
    }

    // Mutate authentication path elements in fors_sig.1
    let mut sig = sig_orig.clone();
    for i in 0..sig.fors_sig.1.len() {
        for j in 0..sig.fors_sig.1[i].len() {
            for k in 0..sig.fors_sig.1[i][j].len() {
                let orig_val = sig.fors_sig.1[i][j][k];
                sig.fors_sig.1[i][j][k] ^= 1;
                assert!(!verify(&pk, message, &sig), "Verification succeeded on mutated FORS auth element {}/{}, byte {}", i, j, k);
                sig.fors_sig.1[i][j][k] = orig_val; // restore
            }
        }
    }

    // 6. Mutate Hypertree signature components
    let mut sig = sig_orig.clone();
    for i in 0..sig.ht_sig.len() {
        // Mutate XMSS authentication path elements in ht_sig[i].0
        for j in 0..sig.ht_sig[i].0.len() {
            for k in 0..sig.ht_sig[i].0[j].len() {
                let orig_val = sig.ht_sig[i].0[j][k];
                sig.ht_sig[i].0[j][k] ^= 1;
                assert!(!verify(&pk, message, &sig), "Verification succeeded on mutated HT auth element {}/{}, byte {}", i, j, k);
                sig.ht_sig[i].0[j][k] = orig_val; // restore
            }
        }

        // Mutate WOTS signature elements in ht_sig[i].1
        for j in 0..sig.ht_sig[i].1.len() {
            for k in 0..sig.ht_sig[i].1[j].len() {
                let orig_val = sig.ht_sig[i].1[j][k];
                sig.ht_sig[i].1[j][k] ^= 1;
                assert!(!verify(&pk, message, &sig), "Verification succeeded on mutated HT WOTS element {}/{}, byte {}", i, j, k);
                sig.ht_sig[i].1[j][k] = orig_val; // restore
            }
        }
    }

    // 7. Mutate Public Key
    let mut pk_mut = pk.clone();
    for i in 0..pk_mut.pk_seed.len() {
        let orig_val = pk_mut.pk_seed[i];
        pk_mut.pk_seed[i] ^= 1;
        assert!(!verify(&pk_mut, message, &sig_orig), "Verification succeeded on mutated pk_seed at byte {}", i);
        pk_mut.pk_seed[i] = orig_val; // restore
    }

    for i in 0..pk_mut.pk_root.len() {
        let orig_val = pk_mut.pk_root[i];
        pk_mut.pk_root[i] ^= 1;
        assert!(!verify(&pk_mut, message, &sig_orig), "Verification succeeded on mutated pk_root at byte {}", i);
        pk_mut.pk_root[i] = orig_val; // restore
    }
}
