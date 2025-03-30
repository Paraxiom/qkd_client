use winterfell::Proof;
use winter_verifier::{verify, VerifierError};
use winter_crypto::hashers::sha3::Sha3_256;
use winter_crypto::RandomCoin;
use crate::zk::stark::winterfell::vrf_air::{VrfAir, VrfPublicInputs, Felt};
use thiserror::Error;
use tracing::{debug, info};
use std::time::Instant;

/// Standalone verifier for VRF proofs
pub struct VrfVerifier {
    options: winterfell::ProofOptions,
}

impl VrfVerifier {
    /// Create a new VRF verifier with the given options
    pub fn new(options: winterfell::ProofOptions) -> Self {
        Self { options }
    }
    
    /// Verify a VRF proof
    pub fn verify(
        &self,
        proof: &Proof,
        public_inputs: &VrfPublicInputs,
    ) -> Result<bool, VerifierError> {
        debug!("Verifying VRF proof...");
        let start = Instant::now();
        
        // Create the VRF AIR instance
        let air = VrfAir::new(
            proof.context.trace_info.clone(),
            public_inputs.clone(),
            self.options.clone()
        );
        
        // Use Sha3_256 hasher and RandomCoin for verification
        type DefaultHasher = Sha3_256<Felt>;
        type DefaultRandomCoin = RandomCoin<DefaultHasher>;
        
        // Verify the proof
        let result = match verify::<VrfAir, DefaultHasher, DefaultRandomCoin>(
            proof.clone(),
            &air
        ) {
            Ok(_) => {
                info!("Proof verified successfully in {:?}", start.elapsed());
                Ok(true)
            },
            Err(VerifierError::InvalidProver) => {
                debug!("Proof verification failed in {:?}", start.elapsed());
                Ok(false)
            },
            Err(e) => {
                debug!("Verification error: {:?}", e);
                Err(e)
            }
        };
        
        result
    }
}

/// Simplified verification function for VRF proofs
pub fn verify_vrf_proof(
    proof: &Proof,
    public_inputs: &VrfPublicInputs,
    options: &winterfell::ProofOptions,
) -> Result<bool, VerifierError> {
    let verifier = VrfVerifier::new(options.clone());
    verifier.verify(proof, public_inputs)
}

#[derive(Debug, Error)]
pub enum VrfVerifierError {
    #[error("Failed to verify proof: {0}")]
    VerificationFailed(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use winter_air::{FieldExtension, BatchingMethod};
    
    #[test]
    fn test_verifier_creation() {
        // Create proof options
        let options = winterfell::ProofOptions::new(
            16,   // queries
            4,    // blowup factor
            8,    // grinding factor
            FieldExtension::None, // field extension
            31,   // FRI max remainder size 
            4,    // FRI folding factor
            BatchingMethod::None, // first batching method
            BatchingMethod::None  // second batching method
        );
        
        // Create a verifier
        let _verifier = VrfVerifier::new(options);
        // Just test that it builds without errors
    }
}