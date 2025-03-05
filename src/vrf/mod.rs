// src/vrf/mod.rs
pub mod core;
pub mod integrated;
pub mod integrated_vrf;
pub mod qkd_vrf;
use crate::quantum_auth::hybrid::HybridAuth;
use crate::quantum_auth::pq::SphincsAuth;
use sha3::{Digest, Sha3_512};
use std::error::Error;
use tracing::{debug, info};

pub struct QuantumVRF {
    // Use the HybridAuth which contains SPHINCS+
    hybrid_auth: HybridAuth,
    // Direct access to SPHINCS+ for purely quantum operations
    sphincs_auth: SphincsAuth,
}

impl QuantumVRF {
    pub fn new(hybrid_auth: HybridAuth) -> Result<Self, Box<dyn Error>> {
        // Initialize the SPHINCS+ component
        let sphincs_auth = SphincsAuth::new()?;

        Ok(Self {
            hybrid_auth,
            sphincs_auth,
        })
    }

    // Generate a random value and proof based on quantum key input
    pub fn generate(
        &self,
        input: &[u8],
        quantum_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        debug!(
            "Generating VRF output from quantum key, input length: {}",
            input.len()
        );

        // Combine input with quantum key to create seed
        let mut hasher = Sha3_512::new();
        hasher.update(input);
        hasher.update(quantum_key);
        let seed = hasher.finalize().to_vec();
        debug!("Generated VRF seed from quantum key and input");

        // Use SPHINCS+ for the quantum-resistant signature
        let signature_start = std::time::Instant::now();
        let signature = self.sphincs_auth.sign(&seed)?;
        debug!(
            "Generated SPHINCS+ signature in {:?}",
            signature_start.elapsed()
        );

        // Hash the signature to get the random output
        let mut output_hasher = Sha3_512::new();
        output_hasher.update(&signature);
        let random_output = output_hasher.finalize().to_vec();

        info!(
            "VRF output generated successfully: {} bytes, proof: {} bytes",
            random_output.len(),
            signature.len()
        );

        Ok((random_output, signature))
    }

    // Verify a VRF output with its proof
    pub fn verify(
        &self,
        input: &[u8],
        output: &[u8],
        proof: &[u8],
        quantum_key: &[u8],
    ) -> Result<bool, Box<dyn Error>> {
        debug!("Verifying VRF output, input length: {}", input.len());

        // Recreate the seed
        let mut hasher = Sha3_512::new();
        hasher.update(input);
        hasher.update(quantum_key);
        let seed = hasher.finalize().to_vec();

        // Verify the signature (proof) using SPHINCS+
        let verify_start = std::time::Instant::now();
        let signature_valid = self.sphincs_auth.verify(&seed, proof)?;
        if !signature_valid {
            debug!("SPHINCS+ signature verification failed");
            return Ok(false);
        }
        debug!(
            "SPHINCS+ signature verified in {:?}",
            verify_start.elapsed()
        );

        // Verify the output by hashing the signature
        let mut output_hasher = Sha3_512::new();
        output_hasher.update(proof);
        let expected_output = output_hasher.finalize().to_vec();

        let output_valid = expected_output.as_slice() == output;
        if !output_valid {
            debug!("Output verification failed - hash mismatch");
        }

        info!(
            "VRF verification result: {}",
            if output_valid { "valid" } else { "invalid" }
        );

        Ok(output_valid && signature_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrf_generation_and_verification() -> Result<(), Box<dyn Error>> {
        // Initialize hybrid auth system for testing
        let hybrid_auth = HybridAuth::new()?;

        // Create VRF with quantum-resistant signatures
        let vrf = QuantumVRF::new(hybrid_auth)?;

        // Test values
        let input = b"Test VRF input";
        let quantum_key = b"Quantum key for testing";

        // Generate output and proof
        let (output, proof) = vrf.generate(input, quantum_key)?;

        // Verify the output and proof
        let valid = vrf.verify(input, &output, &proof, quantum_key)?;
        assert!(valid, "VRF verification should succeed");

        // Test with modified input (should fail)
        let modified_input = b"Modified input";
        let valid = vrf.verify(modified_input, &output, &proof, quantum_key)?;
        assert!(!valid, "VRF verification should fail with modified input");

        // Test with modified quantum key (should fail)
        let modified_key = b"Modified quantum key for testing";
        let valid = vrf.verify(input, &output, &proof, modified_key)?;
        assert!(
            !valid,
            "VRF verification should fail with modified quantum key"
        );

        Ok(())
    }
}
