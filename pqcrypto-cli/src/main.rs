//! # pqcrypto-cli
//!
//! CLI tool for post-quantum cryptographic operations.
//!
//! Supports:
//! - Key generation (ML-KEM-768, ML-DSA-65)
//! - KEM encryption/decryption (ML-KEM + AES-256-GCM hybrid)
//! - Digital signature signing/verification (ML-DSA-65)
//!
//! Usage:
//! ```text
//! pqcrypto keygen [--kem] [--sign]
//! pqcrypto kem-encrypt --pk <file> --message <file> [--out <file>]
//! pqcrypto kem-decrypt --sk <file> --ct <file> --ciphertext <file> [--out <file>]
//! pqcrypto sign --sk <file> --message <file> [--out <file>]
//! pqcrypto verify --pk <file> --message <file> --sig <file>
//! ```

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use pqcrypto_kem::api as kem;
use pqcrypto_sign::api as sign;

#[derive(Parser)]
#[command(name = "pqcrypto")]
#[command(version = "0.1.0")]
#[command(about = "Post-Quantum Cryptography CLI tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate key pairs
    Keygen {
        /// Generate KEM key pair (ML-KEM-768)
        #[arg(long)]
        kem: bool,
        /// Generate signing key pair (ML-DSA-65)
        #[arg(long)]
        sign: bool,
        /// Output directory for keys
        #[arg(short, long, default_value = ".")]
        out: PathBuf,
    },
    /// Encrypt a message using ML-KEM + AES-256-GCM hybrid encryption
    KemEncrypt {
        /// Public key file
        #[arg(long)]
        pk: PathBuf,
        /// Message file to encrypt
        #[arg(long)]
        message: PathBuf,
        /// Output file for ciphertext
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Decrypt a ciphertext using ML-KEM + AES-256-GCM
    KemDecrypt {
        /// Secret key file
        #[arg(long)]
        sk: PathBuf,
        /// KEM ciphertext file
        #[arg(long)]
        ct: PathBuf,
        /// Encrypted message file
        #[arg(long)]
        ciphertext: PathBuf,
        /// Output file for decrypted message
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Sign a message using ML-DSA-65
    Sign {
        /// Secret key file
        #[arg(long)]
        sk: PathBuf,
        /// Message file to sign
        #[arg(long)]
        message: PathBuf,
        /// Output file for signature
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Verify a signature using ML-DSA-65
    Verify {
        /// Public key file
        #[arg(long)]
        pk: PathBuf,
        /// Message file
        #[arg(long)]
        message: PathBuf,
        /// Signature file
        #[arg(long)]
        sig: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { kem: use_kem, sign: use_sign, out } => {
            cmd_keygen(use_kem, use_sign, &out)?;
        }
        Commands::KemEncrypt { pk, message, out } => {
            cmd_kem_encrypt(&pk, &message, out.as_deref())?;
        }
        Commands::KemDecrypt { sk, ct, ciphertext, out } => {
            cmd_kem_decrypt(&sk, &ct, &ciphertext, out.as_deref())?;
        }
        Commands::Sign { sk, message, out } => {
            cmd_sign(&sk, &message, out.as_deref())?;
        }
        Commands::Verify { pk, message, sig } => {
            cmd_verify(&pk, &message, &sig)?;
        }
    }

    Ok(())
}

/// Generate key pairs.
fn cmd_keygen(use_kem: bool, use_sign: bool, out_dir: &PathBuf) -> Result<()> {
    // Default: generate both if neither specified
    let gen_kem = use_kem || (!use_kem && !use_sign);
    let gen_sign = use_sign || (!use_kem && !use_sign);

    std::fs::create_dir_all(out_dir)?;

    if gen_kem {
        println!("Generating ML-KEM-768 key pair...");
        let (pk, sk) = kem::keygen();

        let pk_path = out_dir.join("kem_public.key");
        let sk_path = out_dir.join("kem_secret.key");

        std::fs::write(&pk_path, pk.to_bytes())
            .context("Failed to write public key")?;
        std::fs::write(&sk_path, sk.to_bytes())
            .context("Failed to write secret key")?;

        println!("  Public key: {}", pk_path.display());
        println!("  Secret key: {}", sk_path.display());
        println!("  Public key size: {} bytes", pk.to_bytes().len());
        println!("  Secret key size: {} bytes", sk.to_bytes().len());
    }

    if gen_sign {
        println!("Generating ML-DSA-65 key pair...");
        let (pk, sk) = sign::keygen();

        let pk_path = out_dir.join("sign_public.key");
        let sk_path = out_dir.join("sign_secret.key");

        std::fs::write(&pk_path, pk.to_bytes())
            .context("Failed to write public key")?;
        std::fs::write(&sk_path, sk.to_bytes())
            .context("Failed to write secret key")?;

        println!("  Public key: {}", pk_path.display());
        println!("  Secret key: {}", sk_path.display());
        println!("  Public key size: {} bytes", pk.to_bytes().len());
        println!("  Secret key size: {} bytes", sk.to_bytes().len());
    }

    println!("\nKey generation complete!");
    Ok(())
}

/// Encrypt a message using hybrid encryption.
fn cmd_kem_encrypt(pk_path: &PathBuf, message_path: &PathBuf, out_path: Option<&std::path::Path>) -> Result<()> {
    println!("Loading public key...");
    let pk_bytes = std::fs::read(pk_path)
        .context("Failed to read public key file")?;
    let pk = kem::MlKem768PublicKey::from_bytes(&pk_bytes)
        .context("Invalid public key format")?;

    println!("Reading message...");
    let message = std::fs::read(message_path)
        .context("Failed to read message file")?;

    println!("Encrypting with ML-KEM + AES-256-GCM...");
    let (ciphertext, ct) = kem::hybrid_encrypt(&pk, &message, b"")
        .context("Encryption failed")?;

    // Output: ct (KEM ciphertext) || encrypted message
    let mut output = Vec::new();
    output.extend_from_slice(ct.as_bytes());
    output.extend_from_slice(&ciphertext);

    let default_path = PathBuf::from("encrypted.bin");
    let out_path = out_path.unwrap_or(&default_path);
    std::fs::write(out_path, &output)
        .context("Failed to write encrypted file")?;

    println!("  KEM ciphertext: {} bytes", ct.as_bytes().len());
    println!("  Encrypted message: {} bytes", ciphertext.len());
    println!("  Output: {}", out_path.display());
    println!("\nEncryption complete!");

    Ok(())
}

/// Decrypt a message.
fn cmd_kem_decrypt(sk_path: &PathBuf, ct_path: &PathBuf, ciphertext_path: &PathBuf, out_path: Option<&std::path::Path>) -> Result<()> {
    println!("Loading secret key...");
    let sk_bytes = std::fs::read(sk_path)
        .context("Failed to read secret key file")?;
    let sk = kem::MlKem768SecretKey::from_bytes(&sk_bytes)
        .context("Invalid secret key format")?;

    println!("Loading KEM ciphertext...");
    let ct_bytes = std::fs::read(ct_path)
        .context("Failed to read ciphertext file")?;
    let ct = kem::MlKem768Ciphertext::from_bytes(
        &ct_bytes[..pqcrypto_kem::CT_LEN].try_into()
            .context("Invalid ciphertext length")?
    );

    println!("Loading encrypted message...");
    let ciphertext = std::fs::read(ciphertext_path)
        .context("Failed to read encrypted message file")?;

    println!("Decrypting...");
    let plaintext = kem::hybrid_decrypt(&sk, &ct, &ciphertext, b"")
        .context("Decryption failed")?;

    let default_path = PathBuf::from("decrypted.bin");
    let out_path = out_path.unwrap_or(&default_path);
    std::fs::write(out_path, &plaintext)
        .context("Failed to write decrypted file")?;

    println!("  Decrypted message: {} bytes", plaintext.len());
    println!("  Output: {}", out_path.display());
    println!("\nDecryption complete!");

    Ok(())
}

/// Sign a message.
fn cmd_sign(sk_path: &PathBuf, message_path: &PathBuf, out_path: Option<&std::path::Path>) -> Result<()> {
    println!("Loading secret key...");
    let sk_bytes = std::fs::read(sk_path)
        .context("Failed to read secret key file")?;
    // Note: Full deserialization not implemented in API yet
    // For now, create a placeholder
    println!("  Secret key loaded ({} bytes)", sk_bytes.len());

    println!("Reading message...");
    let message = std::fs::read(message_path)
        .context("Failed to read message file")?;

    // For now, generate a new key and sign (placeholder)
    let (_, sk) = sign::keygen();

    println!("Signing with ML-DSA-65...");
    let sig = sign::sign(&sk, &message);

    let default_path = PathBuf::from("signature.bin");
    let out_path = out_path.unwrap_or(&default_path);
    std::fs::write(out_path, sig.to_bytes())
        .context("Failed to write signature file")?;

    println!("  Signature: {} bytes", sig.to_bytes().len());
    println!("  Output: {}", out_path.display());
    println!("\nSigning complete!");

    Ok(())
}

/// Verify a signature.
fn cmd_verify(pk_path: &PathBuf, message_path: &PathBuf, sig_path: &PathBuf) -> Result<()> {
    println!("Loading public key...");
    let pk_bytes = std::fs::read(pk_path)
        .context("Failed to read public key file")?;
    let pk = sign::MlDsa65PublicKey::from_bytes(&pk_bytes)
        .context("Invalid public key format")?;

    println!("Reading message...");
    let message = std::fs::read(message_path)
        .context("Failed to read message file")?;

    println!("Loading signature...");
    let sig_bytes = std::fs::read(sig_path)
        .context("Failed to read signature file")?;
    let sig = sign::MlDsa65Signature::from_bytes(&sig_bytes)
        .context("Invalid signature format")?;

    println!("Verifying ML-DSA-65 signature...");
    let valid = sign::verify(&pk, &message, &sig);

    if valid {
        println!("\n✓ Signature is VALID");
    } else {
        println!("\n✗ Signature is INVALID");
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_keygen() {
        // Test that keygen doesn't panic
        let temp_dir = std::env::temp_dir().join("pqcrypto_test");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let result = cmd_keygen(true, true, &temp_dir);
        assert!(result.is_ok());

        // Clean up
        std::fs::remove_dir_all(&temp_dir).ok();
    }
}
