// src/bin/stark_examples/vrf_seed_example.rs
use qkd_client::zk::stark::vrf_seed_proof::VrfSeedProofStark;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Create test inputs
    let quantum_key = b"example_quantum_key_123";
    let input_data = b"example_input_data_456";
    
    // Create the VRF proof
    let mut vrf_proof = VrfSeedProofStark::new(quantum_key, input_data, None)?;
    
    // The proof is already generated in the constructor, but for compatibility:
    vrf_proof.generate_proof()?;
    
    // Verify the proof
    let is_valid = vrf_proof.verify()?;
    println!("VRF proof verified: {}", is_valid);
    
    // Display the VRF seed
    println!("VRF seed: {:?}", vrf_proof.seed);
    
    Ok(())
}