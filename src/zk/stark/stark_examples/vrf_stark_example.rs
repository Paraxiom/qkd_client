use qkd_client::zk::stark::{VrfStarkProof, VrfStarkProver, VrfStarkVerifier};
use std::error::Error;
use std::time::Instant;

fn main() -> Result<(), Box<dyn Error>> {
    println!("QKD Client - VRF-STARK Example");
    println!("==============================");
    
    // Create test inputs
    let quantum_key = b"quantum_key_for_vrf_stark_example_123456789";
    let input_data = b"input_data_for_vrf_stark_example_987654321";
    
    println!("Input data: {:?}", String::from_utf8_lossy(input_data));
    
    // Create the VRF STARK prover
    println!("\nCreating VRF-STARK prover...");
    let prover = VrfStarkProver::new(quantum_key, 128)?;
    
    // Generate the proof
    println!("Generating VRF-STARK proof...");
    let start = Instant::now();
    let proof = prover.prove(input_data)?;
    let duration = start.elapsed();
    
    println!("Proof generation took {:?}", duration);
    println!("VRF seed: {:?}", hex::encode(&proof.vrf_seed));
    
    // Serialize the proof
    let proof_bytes = proof.to_bytes();
    println!("\nProof size: {} bytes", proof_bytes.len());
    
    // Create the verifier
    println!("\nCreating VRF-STARK verifier...");
    let verifier = VrfStarkVerifier::new(128)?;
    
    // Verify the proof
    println!("Verifying VRF-STARK proof...");
    let start = Instant::now();
    let is_valid = verifier.verify(&proof)?;
    let duration = start.elapsed();
    
    println!("Proof verification took {:?}", duration);
    println!("\nVerification result: {}", if is_valid { "VALID ✓" } else { "INVALID ✗" });
    
    // Deserialize and verify again
    println!("\nDeserializing proof...");
    let deserialized_proof = VrfStarkProof::from_bytes(&proof_bytes)?;
    
    println!("Verifying deserialized proof...");
    let is_valid = verifier.verify(&deserialized_proof)?;
    
    println!("Verification result: {}", if is_valid { "VALID ✓" } else { "INVALID ✗" });
    
    Ok(())
}