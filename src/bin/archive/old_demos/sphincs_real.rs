// src/bin/sphincs_real.rs
use qkd_client::quantum_auth::pq::{SphincsAuth, SphincsVariant};
use std::time::Instant;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() {
    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("🌟 SPHINCS+ Quantum-Resistant Signature Demo (Real Implementation)");
    info!("=================================================================");
    info!("This demo uses the real SPHINCS+ implementation from pqcrypto-sphincsplus");
    info!("(NIST post-quantum cryptography submission)");
    info!("");

    // Create a new SPHINCS+ instance
    info!("Generating SPHINCS+ keypair... (this may take a moment)");
    let start = Instant::now();
    match SphincsAuth::new() {
        Ok(sphincs) => {
            info!("✅ Key generation successful in {:?}", start.elapsed());

            // Create test messages of different sizes
            let message_sizes = [32, 64, 256, 1024];

            for size in message_sizes {
                // Create test message of this size
                let message: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
                info!("\nTesting with message size: {} bytes", size);

                // Sign the message
                let start = Instant::now();
                match sphincs.sign(&message) {
                    Ok(signature) => {
                        let sign_time = start.elapsed();
                        info!("✅ Signature generated in {:?}", sign_time);
                        info!("   Signature size: {} bytes", signature.len());

                        // Verify the signature
                        let start = Instant::now();
                        match sphincs.verify(&message, &signature) {
                            Ok(true) => {
                                let verify_time = start.elapsed();
                                info!("✅ Signature verified in {:?}", verify_time);
                            }
                            Ok(false) => {
                                info!("❌ Signature verification failed");
                            }
                            Err(e) => {
                                info!("❌ Error during verification: {}", e);
                            }
                        }

                        // Try with tampered message (flip one bit)
                        let mut tampered = message.clone();
                        if !tampered.is_empty() {
                            tampered[0] ^= 0x01;
                        }

                        let start = Instant::now();
                        match sphincs.verify(&tampered, &signature) {
                            Ok(true) => {
                                info!(
                                    "❌ SECURITY ISSUE: Signature verified with tampered message!"
                                );
                            }
                            Ok(false) => {
                                info!(
                                    "✅ Security check passed: Tampered message rejected in {:?}",
                                    start.elapsed()
                                );
                            }
                            Err(e) => {
                                info!("❓ Verification of tampered message error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        info!("❌ Error generating signature: {}", e);
                    }
                }
            }

            // Provide a summary
            info!("\n📊 SPHINCS+ Implementation Summary:");
            info!("--------------------------------");
            info!("✅ Implementation: Real SPHINCS+ (pqcrypto-sphincsplus)");
            info!("✅ Security level: NIST Level 1 (128-bit post-quantum security)");
            info!("✅ Signature scheme: Stateless hash-based signatures");
            info!("✅ Pros: Provable security, minimal security assumptions");
            info!("⚠️ Cons: Larger signatures compared to classical schemes");

            info!("\n📋 Recommendation for QKD application:");
            info!("Use SPHINCS+ for authenticating critical control messages");
            info!("Pre-compute signatures for time-sensitive operations");
            info!("Cache verification results where appropriate");
        }
        Err(e) => {
            info!("❌ Error creating SPHINCS+ instance: {}", e);
        }
    }
}
