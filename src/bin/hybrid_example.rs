// src/bin/hybrid_example.rs
use qkd_client::quantum_auth::hybrid::HybridAuth;
use std::time::Instant;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("🌟 Hybrid Authentication Example");
    info!("===============================");

    // Create hybrid authentication
    info!("Initializing hybrid authentication...");
    let start = Instant::now();
    let auth = HybridAuth::new()?;
    info!("✅ Initialization completed in {:?}", start.elapsed());

    // Sign a message
    let message = b"This is a test message for hybrid authentication";
    info!("Signing message: \"{}\"", String::from_utf8_lossy(message));

    let start = Instant::now();
    let signature = auth.sign(message)?;
    info!("✅ Signature generated in {:?}", start.elapsed());
    info!("  Classical signature: {} bytes", signature.classical.len());
    info!("  Quantum signature: {} bytes", signature.quantum.len());

    // Verify the signature
    let start = Instant::now();
    let valid = auth.verify(message, &signature)?;
    info!(
        "✅ Verification completed in {:?}: {}",
        start.elapsed(),
        valid
    );

    // Serialize for transport
    let start = Instant::now();
    let serialized = HybridAuth::serialize_signature(&signature)?;
    info!(
        "✅ Serialized in {:?}: {} bytes",
        start.elapsed(),
        serialized.len()
    );

    // Deserialize
    let start = Instant::now();
    match HybridAuth::deserialize_signature(&serialized) {
        Ok(deserialized) => {
            info!("✅ Deserialized in {:?}", start.elapsed());

            // Verify deserialized signature
            let start = Instant::now();
            let valid = auth.verify(message, &deserialized)?;
            info!("✅ Verification of deserialized signature: {}", valid);
        }
        Err(e) => {
            warn!("❌ Deserialization error: {}", e);
        }
    }

    // Try with tampered message
    let tampered_message = b"This is a tampered message";
    let start = Instant::now();
    let valid = auth.verify(tampered_message, &signature)?;
    info!(
        "✅ Security check: Tampered message verification: {} (should be false)",
        valid
    );

    Ok(())
}
