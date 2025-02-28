// src/vrf/integrated_vrf.rs
use super::QuantumVRF;
use crate::zk_proof::{ZKProver, ZKVerifier};
use crate::quantum_auth::HybridSignature;

pub struct IntegratedVRF {
    vrf: QuantumVRF,
    zk_prover: ZKProver,
    zk_verifier: ZKVerifier,
}

impl IntegratedVRF {
    pub fn new(signer: HybridSignature, zk_prover: ZKProver, zk_verifier: ZKVerifier) -> Self {
        Self {
            vrf: QuantumVRF::new(signer),
            zk_prover,
            zk_verifier,
        }
    }
    
    pub fn generate_with_proof(&self, input: &[u8], quantum_key: &[u8]) -> Result<VRFResponse, Box<dyn std::error::Error>> {
        // Generate VRF output and proof
        let (random_output, vrf_proof) = self.vrf.generate(input, quantum_key)?;
        
        // Create a ZK proof that the quantum key is authentic
        let zk_inputs = json!({
            "quantumKey": hex::encode(quantum_key),
            "inputData": hex::encode(input),
            "vrfSeed": hex::encode(&vrf_proof[0..32]) // Use part of the proof as the seed
        });
        
        let zk_proof = self.zk_prover.generate_proof("vrf_seed_proof", &zk_inputs)?;
        
        Ok(VRFResponse {
            output: random_output,
            vrf_proof,
            zk_proof,
        })
    }
    
    pub fn verify_with_proof(&self, input: &[u8], response: &VRFResponse, public_quantum_key: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        // Verify the VRF proof
        let vrf_valid = self.vrf.verify(input, &response.output, &response.vrf_proof, public_quantum_key)?;
        if !vrf_valid {
            return Ok(false);
        }
        
        // Verify the ZK proof
        let zk_public_inputs = json!({
            "inputData": hex::encode(input),
            "vrfSeed": hex::encode(&response.vrf_proof[0..32])
        });
        
        let zk_valid = self.zk_verifier.verify_proof("vrf_seed_proof", &response.zk_proof, &zk_public_inputs)?;
        
        Ok(zk_valid)
    }
}

pub struct VRFResponse {
    pub output: Vec<u8>,
    pub vrf_proof: Vec<u8>,
    pub zk_proof: Vec<u8>,
}
