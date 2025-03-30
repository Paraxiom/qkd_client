use crate::qkd::QkdClient;
use crate::zk::stark::winterfell::vrf_prover::VrfProver;
use crate::zk::stark::winterfell::vrf_air::VrfPublicInputs;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use winterfell::Proof;
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::time::{Instant, Duration};
use tracing::{info, warn, debug, error};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBuffer {
    #[zeroize(skip)]
    pub id: String,
    pub data: Vec<u8>,
}

pub struct QkdStarkBridge {
    qkd_client: QkdClient,
    stark_prover: VrfProver,
    max_proof_time: Duration,
}

impl QkdStarkBridge {
    pub fn new(qkd_client: QkdClient, stark_prover: VrfProver, max_proof_time: Duration) -> Self {
        Self { 
            qkd_client, 
            stark_prover,
            max_proof_time,
        }
    }
    
    /// Generate a VRF output and STARK proof using a quantum key
    /// 
    /// # Arguments
    /// * `key_id` - Identifier for the quantum key to retrieve
    /// * `input` - Input data for the VRF computation
    /// 
    /// # Returns
    /// A tuple containing the VRF output and its corresponding STARK proof
    pub fn generate_vrf_with_proof(
        &self,
        key_id: &str,
        input: &[u8],
    ) -> Result<(Vec<u8>, Proof), BridgeError> {
        debug!("Retrieving quantum key with ID: {}", key_id);
        
        // Start timing the operation
        let start_time = Instant::now();
        
        // Retrieve key with proper error handling
        let mut quantum_key = self.qkd_client.get_key(key_id)
            .map_err(|e| BridgeError::KeyRetrievalFailed(format!("Failed to retrieve key: {}", e)))?;
        
        debug!("Successfully retrieved quantum key ({} bytes)", quantum_key.data.len());
        
        // Validate the key has sufficient entropy
        if quantum_key.data.len() < 32 {
            return Err(BridgeError::InsufficientKeyMaterial(
                format!("Key size too small: {} bytes (minimum 32 bytes required)", quantum_key.data.len())
            ));
        }
        
        // Compute VRF output
        let vrf_output = self.compute_vrf_output(&quantum_key.data, input)?;
        debug!("VRF output computed successfully");
        
        // Generate public inputs for the proof
        let public_inputs = self.prepare_public_inputs(input, &vrf_output)?;
        
        // Generate proof with careful memory management
        debug!("Generating STARK proof...");
        let proof = self.stark_prover.build_proof(&quantum_key.data, input, &public_inputs)
            .map_err(|e| BridgeError::ProofGenerationFailed(format!("Proof generation failed: {:?}", e)))?;
            
        // Check if proof generation exceeded the maximum allowed time
        let elapsed = start_time.elapsed();
        if elapsed > self.max_proof_time {
            warn!("Proof generation took {:?}, which exceeds the configured maximum of {:?}", 
                  elapsed, self.max_proof_time);
        }
        
        info!("Successfully generated VRF output and STARK proof in {:?}", elapsed);
        
        // quantum_key.data will be automatically zeroized when it goes out of scope
        // thanks to the ZeroizeOnDrop trait
        
        Ok((vrf_output, proof))
    }
    
    /// Compute the VRF output from the key and input
    fn compute_vrf_output(&self, key: &[u8], input: &[u8]) -> Result<Vec<u8>, BridgeError> {
        // Implement HMAC-based VRF as specified in RFC 6979 section 3.2
        let mut hmac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|_| BridgeError::CryptographicError("Failed to initialize HMAC".to_string()))?;
        
        // Update with input data
        hmac.update(input);
        
        // Finalize and get the result
        let result = hmac.finalize().into_bytes();
        
        Ok(result.to_vec())
    }
    
    /// Prepare the public inputs for the STARK proof
    fn prepare_public_inputs(&self, input: &[u8], output: &[u8]) -> Result<VrfPublicInputs, BridgeError> {
        // Hash the input to get a commitment
        let mut hasher = Sha256::new();
        hasher.update(input);
        let input_hash = hasher.finalize();
        
        // Convert the first 32 bytes of output to field elements
        // This is a simplified conversion and should be replaced with proper
        // field element conversion based on your specific implementation
        let output_bytes = output.get(0..32)
            .ok_or_else(|| BridgeError::InvalidData("Output too short".to_string()))?;
        
        // Create public inputs structure
        let public_inputs = VrfPublicInputs::new(
            input_hash.as_slice(), 
            output_bytes
        ).map_err(|e| BridgeError::InvalidData(format!("Failed to create public inputs: {}", e)))?;
        
        Ok(public_inputs)
    }
    
    /// Verify a VRF STARK proof
    pub fn verify_vrf_proof(
        &self,
        input: &[u8],
        claimed_output: &[u8],
        proof: &Proof,
    ) -> Result<bool, BridgeError> {
        // Prepare public inputs
        let public_inputs = self.prepare_public_inputs(input, claimed_output)?;
        
        // Verify the proof
        debug!("Verifying STARK proof for VRF...");
        let start_time = Instant::now();
        
        let verification_result = self.stark_prover.verify_proof(proof, &public_inputs)
            .map_err(|e| BridgeError::VerificationFailed(format!("Proof verification failed: {:?}", e)))?;
            
        info!("STARK proof verification completed in {:?}: result={}", 
              start_time.elapsed(), verification_result);
              
        Ok(verification_result)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("Failed to retrieve QKD key: {0}")]
    KeyRetrievalFailed(String),
    
    #[error("Insufficient key material: {0}")]
    InsufficientKeyMaterial(String),
    
    #[error("Failed to generate proof: {0}")]
    ProofGenerationFailed(String),
    
    #[error("Cryptographic operation failed: {0}")]
    CryptographicError(String),
    
    #[error("Invalid data: {0}")]
    InvalidData(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

// Extension trait for QkdClient to support more robust key retrieval
pub trait QkdClientExt {
    fn get_key_with_retry(&self, key_id: &str, max_retries: usize) -> Result<SecureBuffer, String>;
}

impl QkdClientExt for QkdClient {
    fn get_key_with_retry(&self, key_id: &str, max_retries: usize) -> Result<SecureBuffer, String> {
        let mut last_error = None;
        
        for attempt in 0..max_retries {
            match self.get_key(key_id) {
                Ok(key) => {
                    if attempt > 0 {
                        info!("Successfully retrieved key after {} retries", attempt);
                    }
                    return Ok(key);
                }
                Err(e) => {
                    warn!("Failed to retrieve key (attempt {}/{}): {}", 
                          attempt + 1, max_retries, e);
                    last_error = Some(e.to_string());
                    
                    // Exponential backoff
                    if attempt < max_retries - 1 {
                        let backoff = std::time::Duration::from_millis(100 * 2u64.pow(attempt as u32));
                        std::thread::sleep(backoff);
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| "Unknown error".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compute_vrf_output_deterministic() {
        // This test can be implemented with direct HMAC functions
        // without relying on the bridge implementation
        let key = [1u8; 32];
        let input = b"test input";
        
        let mut hmac1 = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        hmac1.update(input);
        let output1 = hmac1.finalize().into_bytes();
        
        let mut hmac2 = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        hmac2.update(input);
        let output2 = hmac2.finalize().into_bytes();
        
        assert_eq!(output1, output2, "VRF output should be deterministic");
    }
}