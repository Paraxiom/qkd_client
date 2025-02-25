// src/bin/hybrid_example.rs
use qkd_client::quantum_auth::pq::SphincsAuth;
use qkd_client::quantum_auth::hybrid::HybridAuth;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() {
    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    println!("🌟 Testing Hybrid Authentication...");

    // Initialize hybrid auth
    match HybridAuth::new() {
        Ok(auth) => {
            // Generate hybrid proof
            match auth.authenticate() {
                Ok(proof) => {
                    println!("✅ Generated hybrid proof:");
                    println!("  Classical proof size: {} bytes", proof.classical.len());
                    println!("  Quantum-resistant proof size: {} bytes", proof.quantum.len());

                    // Verify hybrid proof
                    match auth.verify(&proof) {
                        Ok(true) => println!("✅ Hybrid proof verified successfully!"),
                        Ok(false) => println!("❌ Hybrid proof verification failed"),
                        Err(e) => println!("❌ Error verifying proof: {}", e),
                    }
                }
                Err(e) => println!("❌ Error generating hybrid proof: {}", e),
            }
        }
        Err(e) => println!("❌ Failed to initialize hybrid auth: {}", e),
    }
}
