//! Example: ML-KEM-768 key generation, encapsulation, and decapsulation.

fn main() {
    println!("=== PQCrypto-RS: ML-KEM-768 Example ===\n");

    // Key generation
    println!("1. Generating ML-KEM-768 key pair...");
    let (pk, sk) = pqcrypto_kem::api::keygen();
    println!("   Public key: {} bytes", pk.to_bytes().len());
    println!("   Secret key: {} bytes\n", sk.to_bytes().len());

    // Encapsulation
    println!("2. Encapsulating shared secret...");
    let (ct, ss1) = pqcrypto_kem::api::encapsulate(&pk).unwrap();
    println!("   Ciphertext: {} bytes", ct.as_bytes().len());
    println!("   Shared secret: {:?}\n", &ss1.as_bytes()[..8]);

    // Decapsulation
    println!("3. Decapsulating...");
    let ss2 = pqcrypto_kem::api::decapsulate(&sk, &ct).unwrap();
    println!("   Shared secret: {:?}\n", &ss2.as_bytes()[..8]);

    // ML-DSA-65 signing
    println!("4. ML-DSA-65 key generation...");
    let (dpk, dsk) = pqcrypto_sign::api::keygen();
    println!("   Public key: {} bytes", dpk.to_bytes().len());

    println!("5. Signing message...");
    let message = b"Hello, post-quantum world!";
    let sig = pqcrypto_sign::api::sign(&dsk, message);
    println!("   Signature: {} bytes", sig.to_bytes().len());

    println!("6. Verifying signature...");
    let valid = pqcrypto_sign::api::verify(&dpk, message, &sig);
    println!("   Valid: {}\n", valid);

    println!("=== Done! ===");
}
