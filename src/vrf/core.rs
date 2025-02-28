// src/vrf/core.rs
use crate::quantum_auth::hybrid::HybridAuth;
use sha3::{Digest, Sha3_512};
use std::error::Error;

pub struct QuantumVRF {
    signer: HybridAuth,
}

impl QuantumVRF {
    pub fn new(signer: HybridAuth) -> Self {
        Self { signer }
    }

    // Generate a random value and proof based on quantum key input
    pub fn generate(
        &self,
        input: &[u8],
        quantum_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        // Combine input with quantum key to create seed
        let mut hasher = Sha3_512::new();
        hasher.update(input);
        hasher.update(quantum_key);
        let seed = hasher.finalize();

        // Use the seed to generate a signature (serves as the proof)
        let signature = self.signer.sign(&seed.to_vec())?;

        // Serialize the signature for use as proof
        let signature_bytes = HybridAuth::serialize_signature(&signature)?
            .as_bytes()
            .to_vec();

        // Hash the signature to get the random output
        let mut output_hasher = Sha3_512::new();
        output_hasher.update(&signature_bytes);
        let random_output = output_hasher.finalize().to_vec();

        Ok((random_output, signature_bytes))
    }

    // Verify a VRF output with its proof
    pub fn verify(
        &self,
        input: &[u8],
        output: &[u8],
        proof: &[u8],
        quantum_key: &[u8],
    ) -> Result<bool, Box<dyn Error>> {
        // Recreate the seed
        let mut hasher = Sha3_512::new();
        hasher.update(input);
        hasher.update(quantum_key);
        let seed = hasher.finalize();

        // Deserialize and verify the signature (proof)
        let signature = HybridAuth::deserialize_signature(&String::from_utf8(proof.to_vec())?)?;

        if !self.signer.verify(&seed.to_vec(), &signature)? {
            return Ok(false);
        }

        // Verify the output by hashing the signature
        let mut output_hasher = Sha3_512::new();
        output_hasher.update(proof);
        let expected_output = output_hasher.finalize();

        Ok(&expected_output[..] == output)
    }
}
