use crate::quantum_auth::hybrid::HybridAuth;
use sha3::{Digest, Sha3_512};
use std::error::Error;
use tracing::{debug, info};

/// Verifiable Random Function implementation using quantum authentication
///
/// This VRF creates unpredictable but verifiable randomness from quantum keys
/// by combining the input with a quantum key and using hybrid authentication
/// as the source of verifiability.
pub struct QuantumVRF {
    signer: HybridAuth,
}

impl QuantumVRF {
    /// Create a new VRF using the provided hybrid auth system
    pub fn new(signer: HybridAuth) -> Self {
        Self { signer }
    }

    /// Generate a random value and proof based on quantum key input
    ///
    /// # Arguments
    /// * `input` - Public input data (e.g., round number, context)
    /// * `quantum_key` - Quantum key from QKD (remains secret)
    ///
    /// # Returns
    /// Tuple of (random_output, proof)
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

        // Use the seed to generate a signature (serves as the proof)
        let signature = self.signer.sign(&seed)?;

        // Serialize the signature for use as proof
        let start = std::time::Instant::now();
        let signature_bytes = HybridAuth::serialize_signature(&signature)?
            .as_bytes()
            .to_vec();
        debug!("Serialized signature in {:?}", start.elapsed());

        // Hash the signature to get the random output
        let mut output_hasher = Sha3_512::new();
        output_hasher.update(&signature_bytes);
        let random_output = output_hasher.finalize().to_vec();

        info!(
            "VRF output generated successfully: {} bytes, proof: {} bytes",
            random_output.len(),
            signature_bytes.len()
        );
        Ok((random_output, signature_bytes))
    }

    /// Verify a VRF output with its proof
    ///
    /// # Arguments
    /// * `input` - The same public input used for generation
    /// * `output` - The random output to verify
    /// * `proof` - The proof of correct generation
    /// * `quantum_key` - The quantum key used for generation
    ///
    /// # Returns
    /// `true` if the output was correctly derived from the input and quantum key
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

        // Deserialize and verify the signature (proof)
        let start = std::time::Instant::now();
        let signature = HybridAuth::deserialize_signature(&String::from_utf8(proof.to_vec())?)?;

        if !self.signer.verify(&seed, &signature)? {
            debug!("VRF verification failed - invalid signature");
            return Ok(false);
        }
        debug!("VRF signature verified in {:?}", start.elapsed());

        // Verify the output by hashing the signature
        let mut output_hasher = Sha3_512::new();
        output_hasher.update(proof);
        let expected_output = output_hasher.finalize().to_vec();

        let valid = &expected_output[..] == output;
        info!(
            "VRF verification result: {}",
            if valid { "valid" } else { "invalid" }
        );
        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrf_generation_and_verification() -> Result<(), Box<dyn Error>> {
        // Initialize auth system for testing
        let auth = HybridAuth::new()?;
        let vrf = QuantumVRF::new(auth);

        // Test values
        let input = b"Test VRF input";
        let quantum_key = b"Quantum key for testing";

        // Generate output and proof
        let (output, proof) = vrf.generate(input, quantum_key)?;

        // Verify the output
        let valid = vrf.verify(input, &output, &proof, quantum_key)?;
        assert!(valid, "VRF verification should succeed");

        // Test with modified input (should fail)
        let modified_input = b"Modified input";
        let valid = vrf.verify(modified_input, &output, &proof, quantum_key)?;
        assert!(!valid, "VRF verification should fail with modified input");

        Ok(())
    }
}
