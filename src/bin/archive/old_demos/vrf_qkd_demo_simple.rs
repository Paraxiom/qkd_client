// src/bin/vrf_qkd_demo_simple.rs
use std::error::Error;
use std::path::Path;
use std::env;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use qkd_client::qkd::etsi_api::{DeviceType, ETSIClient};
use qkd_client::vrf::core::QuantumVRF;
use qkd_client::vrf::qkd_vrf::QKDVerifiableRandomFunction;
use qkd_client::quantum_auth::hybrid::HybridAuth;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let role = if args.len() > 1 { &args[1] } else { "alice" };
    
    // Input data for VRF
    let input_data = b"default-input";
    let dest_id = "bob";
    
    // Create HybridAuth for VRF
    info!("Initializing hybrid authentication system...");
    let auth = HybridAuth::new()?;
    
    // Create QuantumVRF
    let vrf = QuantumVRF::new(auth);
    
    // Create QKD VRF with simulated device for testing
    let qkd_vrf = QKDVerifiableRandomFunction::new(
        vrf,
        DeviceType::Simulated,
        Path::new("dummy-path.pem"), // Path doesn't matter for simulation
    )?;
    
    match role {
        "alice" => {
            // Alice generates VRF output using QKD
            info!("🔑 Generating VRF output using quantum key...");
            info!("- Input: {:?}", input_data);
            info!("- Destination: {}", dest_id);
            
            // Check available key material
            let available = qkd_vrf.get_available_key_size().await?;
            info!("Available quantum key material: {} bytes", available);
            
            // Generate VRF output
            let (output, proof, key_id) = qkd_vrf.generate_with_qkd(input_data, dest_id).await?;
            
            // Display results
            info!("✅ VRF output generated successfully!");
            info!("Key ID: {}", key_id);
            info!("VRF Output: {}", hex::encode(&output));
            info!("VRF Proof: {}", hex::encode(&proof));
            info!("");
            info!("For Bob to verify this output, run:");
            info!("./vrf_qkd_demo_simple bob {} {} {}", 
                  key_id, hex::encode(&output), hex::encode(&proof));
        },
        "bob" => {
            // Bob verifies VRF output using QKD
            if args.len() < 5 {
                return Err("Bob needs key_id, output, and proof arguments".into());
            }
            
            let key_id = &args[2];
            let output_hex = &args[3];
            let proof_hex = &args[4];
            
            // Decode hex strings
            let output = hex::decode(output_hex)?;
            let proof = hex::decode(proof_hex)?;
            
            info!("🔍 Verifying VRF output using quantum key...");
            info!("- Input: {:?}", input_data);
            info!("- Key ID: {}", key_id);
            
            // Verify VRF output
            let valid = qkd_vrf.verify_with_qkd(input_data, &output, &proof, key_id).await?;
            
            if valid {
                info!("✅ VRF output verified successfully!");
            } else {
                info!("❌ VRF verification failed!");
            }
        },
        _ => {
            return Err(format!("Unknown role: {}", role).into());
        }
    }
    
    Ok(())
}