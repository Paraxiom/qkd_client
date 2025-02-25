// src/quantum_auth/hybrid.rs
use crate::quantum_auth::SphincsAuth;
use crate::quantum_auth::authenticator::QuantumAuthenticator;

use std::error::Error;
use tracing::{info, debug};

pub struct HybridAuth {
    classical: QuantumAuthenticator,
    quantum: SphincsAuth,
}

pub struct HybridProof {
    pub classical: Vec<u8>,
    pub quantum: Vec<u8>,
}

impl HybridAuth {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        debug!("Initializing hybrid authentication system...");
        
        Ok(Self {
            classical: QuantumAuthenticator::new()?,
            quantum: SphincsAuth::new()?,
        })
    }
    
    pub fn authenticate(&self) -> Result<HybridProof, Box<dyn Error>> {
        debug!("Generating hybrid authentication proof...");
        
        // Generate classical proof first
        let classical_proof = self.classical.authenticate()?;
        
        // Sign it with quantum-resistant signature
        let quantum_proof = self.quantum.sign(&classical_proof)?;
        
        info!("Hybrid proof generated successfully");
        Ok(HybridProof {
            classical: classical_proof,
            quantum: quantum_proof,
        })
    }
    
    pub fn verify(&self, proof: &HybridProof) -> Result<bool, Box<dyn Error>> {
        debug!("Verifying hybrid authentication proof...");
        
        // Verify quantum signature of classical proof
        let quantum_valid = self.quantum.verify(&proof.classical, &proof.quantum)?;
        
        info!("Hybrid proof verification result: {}", quantum_valid);
        Ok(quantum_valid)
    }
}
