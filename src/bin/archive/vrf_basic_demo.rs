// src/bin/vrf_basic_demo.rs
use hex;
use qkd_client::quantum_auth::hybrid::HybridAuth;
use qkd_client::vrf::core::QuantumVRF;
use std::error::Error;
use std::time::Instant;

fn main() -> Result<(), Box<dyn Error>> {
    println!("🔐 Basic VRF Demo");
    println!("================");

    // Initialize the hybrid auth system
    let hybrid_auth = HybridAuth::new()?;

    // Create the VRF
    let vrf = QuantumVRF::new(hybrid_auth);

    // Generate a quantum key (in a real system, this would come from your QKD source)
    let quantum_key = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    // Generate VRF output
    let input = b"Some public input";
    println!("Generating VRF output for input: {:?}", input);

    let start = Instant::now();
    let (output, proof) = vrf.generate(input, &quantum_key)?;
    let elapsed = start.elapsed();

    println!("VRF Output: {}", hex::encode(&output[0..16]));
    println!("VRF Proof Size: {} bytes", proof.len());
    println!("Generation Time: {:?}", elapsed);

    // Verify the output
    let start = Instant::now();
    let is_valid = vrf.verify(input, &output, &proof, &quantum_key)?;
    let elapsed = start.elapsed();

    println!(
        "Verification Result: {}",
        if is_valid { "✅ Valid" } else { "❌ Invalid" }
    );
    println!("Verification Time: {:?}", elapsed);

    Ok(())
}
