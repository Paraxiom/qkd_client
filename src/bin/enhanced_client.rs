// src/bin/enhanced_client.rs
use qkd_client::reporter::ReporterNode;
use qkd_client::quantum_auth::hybrid::HybridAuth;
use tracing_subscriber::FmtSubscriber;
use std::time::Instant;

#[tokio::main]
async fn main() {
    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    println!("🌟 Starting Enhanced Quantum-Resistant Reporter Node...");

    // Initialize hybrid authentication
    let start = Instant::now();
    let hybrid_auth = match HybridAuth::new() {
        Ok(auth) => {
            println!("✅ Hybrid authentication initialized in {:?}", start.elapsed());
            auth
        },
        Err(e) => {
            println!("❌ Failed to initialize hybrid auth: {}", e);
            return;
        }
    };

    // Generate authentication proof
    let start = Instant::now();
    let auth_proof = match hybrid_auth.authenticate() {
        Ok(proof) => {
            println!("✅ Generated hybrid proof in {:?}", start.elapsed());
            println!("  Classical proof: {} bytes", proof.classical.len());
            println!("  Quantum proof: {} bytes", proof.quantum.len());
            proof
        },
        Err(e) => {
            println!("❌ Failed to generate hybrid proof: {}", e);
            return;
        }
    };

    // Create and run reporter node
    match ReporterNode::new() {
        Ok(reporter) => {
            // Run the reporter and collect metrics
            match reporter.report().await {
                Ok(metrics) => {
                    println!("\n📊 Reporter Node Metrics with Quantum-Resistant Auth:");
                    println!("Key Retrieval Time: {:?}", metrics.key_retrieval_time);
                    println!("Proof Generation Time: {:?}", metrics.proof_generation_time);
                    println!("Verification Time: {:?}", metrics.verification_time);
                    
                    // Calculate total with hybrid auth
                    let hybrid_auth_time = auth_proof.quantum.len() as f64 / 1024.0;
                    println!("Hybrid Auth Size: {:.2} KB", hybrid_auth_time);
                    
                    // Compare with classical-only
                    println!("\n🔄 Comparison with Classical-Only Auth:");
                    println!("Classical Auth Size: {:.2} KB", auth_proof.classical.len() as f64 / 1024.0);
                    println!("Quantum Overhead: {:.2}x", auth_proof.quantum.len() as f64 / auth_proof.classical.len() as f64);
                },
                Err(e) => println!("❌ Reporting failed: {}", e),
            }
        },
        Err(e) => println!("❌ Failed to create Reporter Node: {}", e),
    }
}
