// src/bin/test_qkd_vrf.rs
use qkd_client::quantum_auth::hybrid::HybridAuth;
use qkd_client::vrf::core::QuantumVRF;
use qkd_client::vrf::qkd_vrf::QKDVerifiableRandomFunction;
use qkd_client::qkd::etsi_api::DeviceType;
use std::error::Error;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("🔐 QKD-Enhanced VRF Test");
    println!("========================");
    
    // Initialize authentication system
    let hybrid_auth = HybridAuth::new()?;
    
    // Create VRF
    let vrf = QuantumVRF::new(hybrid_auth);
    
    // Create QKD-VRF using simulated device
    let cert_path = Path::new("certificate/Toshiba/certs/client_alice_crt.pem");
    let qkd_vrf = QKDVerifiableRandomFunction::new(vrf, DeviceType::Simulated, cert_path)?;
    
    // Test input
    let input = b"Byzantine leader selection for round 1";
    println!("\n📡 Generating VRF output with quantum key...");
    
    // Generate VRF output with quantum key
    let (output, proof) = qkd_vrf.generate_with_qkd(input, "bob-node-id").await?;
    
    println!("✅ VRF output generated successfully!");
    println!("  📏 Output size: {} bytes", output.len());
    println!("  🔢 First 8 bytes: {:?}", &output[0..8.min(output.len())]);
    println!("  📋 Proof size: {} bytes", proof.len());
    
    // Verify VRF output
    println!("\n🔍 Verifying VRF output...");
    let is_valid = qkd_vrf.verify_with_qkd(input, &output, &proof, "test-key-id").await?;
    
    println!("✅ Verification result: {}", if is_valid { "Valid" } else { "Invalid" });
    
    println!("\n🎉 QKD-Enhanced VRF test completed!");
    Ok(())
}
