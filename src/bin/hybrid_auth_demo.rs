// src/bin/hybrid_auth_demo.rs
use qkd_client::quantum_auth::hybrid::HybridAuth;
use std::time::Instant;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("🌟 Hybrid Authentication Demo (Classical + Post-Quantum)");
    info!("======================================================");
    info!("This demo combines classical Ed25519 signatures with quantum-resistant SPHINCS+");
    info!("");

    // Initialize hybrid authentication
    info!("Initializing hybrid authentication system...");
    let start = Instant::now();
    match HybridAuth::new() {
        Ok(auth) => {
            info!("✅ Hybrid authentication initialized in {:?}", start.elapsed());
            
            // Display key info
            info!("Classical public key size: {} bytes", auth.get_classical_public_key().len());
            info!("Quantum public key size: {} bytes", auth.get_quantum_public_key().len());
            
            // Test with different message sizes
            let message_sizes = [32, 256, 1024, 4096];
            
            for size in message_sizes {
                // Create test message of this size
                let message: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
                info!("\nTesting with message size: {} bytes", size);
                
                // Sign the message
                let start = Instant::now();
                match auth.sign(&message) {
                    Ok(signature) => {
                        let sign_time = start.elapsed();
                        info!("✅ Hybrid signature generated in {:?}", sign_time);
                        info!("   Classical signature: {} bytes", signature.classical.len());
                        info!("   Quantum signature: {} bytes", signature.quantum.len());
                        info!("   Total size: {} bytes", signature.classical.len() + signature.quantum.len());
                        
                        // Verify the signature
                        let start = Instant::now();
                        match auth.verify(&message, &signature) {
                            Ok(true) => {
                                let verify_time = start.elapsed();
                                info!("✅ Hybrid signature verified in {:?}", verify_time);
                            }
                            Ok(false) => {
                                info!("❌ Hybrid signature verification failed");
                            }
                            Err(e) => {
                                info!("❌ Error during verification: {}", e);
                            }
                        }
                        
                        // Test serialization
                        match HybridAuth::serialize_signature(&signature) {
                            Ok(serialized) => {
                                info!("   Serialized signature size: {} bytes", serialized.len());
                                
                                // Test deserialization
                                match HybridAuth::deserialize_signature(&serialized) {
                                    Ok(deserialized) => {
                                        let start = Instant::now();
                                        match auth.verify(&message, &deserialized) {
                                            Ok(true) => {
                                                info!("✅ Deserialized signature verified in {:?}", start.elapsed());
                                            }
                                            Ok(false) => {
                                                info!("❌ Deserialized signature verification failed");
                                            }
                                            Err(e) => {
                                                info!("❌ Error during verification: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        info!("❌ Error during deserialization: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                info!("❌ Error during serialization: {}", e);
                            }
                        }
                        
                        // Try with tampered message (flip one bit)
                        let mut tampered = message.clone();
                        if !tampered.is_empty() {
                            tampered[0] ^= 0x01;
                        }
                        
                        let start = Instant::now();
                        match auth.verify(&tampered, &signature) {
                            Ok(true) => {
                                info!("❌ SECURITY ISSUE: Signature verified with tampered message!");
                            }
                            Ok(false) => {
                                info!("✅ Security check passed: Tampered message rejected in {:?}", start.elapsed());
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
            info!("\n📊 Hybrid Authentication Summary:");
            info!("--------------------------------");
            info!("✅ Classical: Ed25519 signatures (fast, compact)");
            info!("✅ Quantum: SPHINCS+ signatures (quantum-resistant)");
            info!("✅ Combined security: Protected against both classical and quantum attacks");
            info!("✅ Pros: Full security during transition to post-quantum cryptography");
            info!("⚠️ Cons: Larger total signature size compared to classical-only");
            
            info!("\n📋 Recommendation for QKD application:");
            info!("Use hybrid authentication for critical API requests");
            info!("Store signatures efficiently using binary format rather than Base64");
            info!("Consider pre-computing signatures for known messages");
        }
        Err(e) => {
            info!("❌ Error initializing hybrid authentication: {}", e);
        }
    }
    
    Ok(())
}
