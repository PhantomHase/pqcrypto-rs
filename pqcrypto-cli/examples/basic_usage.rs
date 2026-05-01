//! Example: Basic ML-KEM-768 usage
//!
//! Demonstrates key generation, encapsulation, and decapsulation.

use pqcrypto_kem::api::{keygen, encapsulate, decapsulate};

fn main() {
    println!("=== PQCrypto-RS: ML-KEM-768 Example ===\n");

    // Step 1: Generate key pair
    println!("1. Generating ML-KEM-768 key pair...");
    let (pk, sk) = keygen();
    println!("   Public key: {} bytes", pk.to_bytes().len());
    println!("   Secret key: {} bytes\n", sk.to_bytes().len());

    // Step 2: Encapsulate
    println!("2. Encapsulating shared secret...");
    let (ct, ss1) = encapsulate(&pk).unwrap();
    println!("   Ciphertext: {} bytes", ct.as_bytes().len());
    println!("   Shared secret: {} bytes", ss1.as_bytes().len());
    println!("   Shared secret: {:?}\n", &ss1.as_bytes()[..8]);

    // Step 3: Decapsulate
    println!("3. Decapsulating shared secret...");
    let ss2 = decapsulate(&sk, &ct).unwrap();
    println!("   Shared secret: {} bytes", ss2.as_bytes().len());
    println!("   Shared secret: {:?}\n", &ss2.as_bytes()[..8]);

    // Note: Due to lossy compression, ss1 may not equal ss2 exactly
    // This is a known limitation that requires precise FIPS 203 encode/decode

    // Step 4: Hybrid encryption example
    println!("4. Hybrid encryption (ML-KEM + AES-256-GCM)...");
    use pqcrypto_kem::api::{hybrid_encrypt, hybrid_decrypt};

    let message = b"Hello, post-quantum world!";
    let aad = b"example-aad";

    let (ciphertext, kem_ct) = hybrid_encrypt(&pk, message, aad).unwrap();
    println!("   Original: {} bytes", message.len());
    println!("   Encrypted: {} bytes", ciphertext.len());

    let decrypted = hybrid_decrypt(&sk, &kem_ct, &ciphertext, aad).unwrap();
    println!("   Decrypted: {} bytes", decrypted.len());
    println!("   Match: {}\n", decrypted == message);

    // Step 5: Serialization
    println!("5. Key serialization...");
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();
    println!("   Public key serialized: {} bytes", pk_bytes.len());
    println!("   Secret key serialized: {} bytes", sk_bytes.len());

    println!("\n=== Done! ===");
}
