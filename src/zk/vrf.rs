use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::error::Error;
use std::fs;
use std::process::Command;
use tracing::{debug, info, warn};

/// Verifiable Random Function with zero-knowledge capabilities
///
/// This implementation allows generating unpredictable randomness from
/// a seed and proving properties of that randomness without revealing the seed.
pub struct VerifiableRandomFunction {
    seed: Vec<u8>,
}

impl VerifiableRandomFunction {
    /// Create a new VRF with the given seed
    pub fn new(seed: &[u8]) -> Self {
        Self {
            seed: seed.to_vec(),
        }
    }

    /// Generate a deterministic output from the input
    pub fn generate(&self, input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // Simple implementation: hash the input with the seed
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(input);
        hasher.update(&self.seed);
        Ok(hasher.finalize().to_vec())
    }

    /// Verify an output was generated from this input
    pub fn verify(&self, input: &[u8], output: &[u8]) -> Result<bool, Box<dyn Error>> {
        let expected = self.generate(input)?;
        Ok(expected == output)
    }
    pub fn prove(&self, input: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        use sha3::{Digest, Sha3_256};

        let mut hasher = Sha3_256::new();
        hasher.update(input);
        hasher.update(&self.seed);
        let vrf_output = hasher.finalize().to_vec();

        // Generate a zero-knowledge proof (stub, replace with real ZK logic)
        let zk_proof = self.generate_zk_proof(input)?;

        Ok((vrf_output, zk_proof))
    }
    pub fn elect_leader(&self, node_count: u64) -> Result<u64, Box<dyn Error>> {
        use sha3::{Digest, Sha3_256};

        let mut hasher = Sha3_256::new();
        hasher.update(&self.seed);
        let hash_output = hasher.finalize();
        let leader_index = u64::from_le_bytes(hash_output[..8].try_into().unwrap()) % node_count;

        Ok(leader_index)
    }
    pub fn select_committee(&self, count: u64, total_nodes: u64) -> Result<Vec<u64>, Box<dyn Error>> {
        if count > total_nodes {
            return Err("Committee size cannot exceed total nodes".into());
        }

        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.seed);
        let hash_output = hasher.finalize();

        let mut nodes: Vec<u64> = (0..total_nodes).collect();
        let mut committee = Vec::with_capacity(count as usize);

        for i in 0..count {
            let i_usize = i as usize;  // ✅ Convert `i` from u64 to usize
            let index = u64::from_le_bytes(hash_output[i_usize..i_usize + 8].try_into().unwrap()) % (total_nodes - i);


            committee.push(nodes[index as usize]);
            nodes.swap_remove(index as usize);
        }

        Ok(committee)
    }
    pub fn from_multi_source_proof(
        commitment: &str,
        vrf_seed: &str,
    ) -> Result<Self, Box<dyn Error>> {
        // Combine commitment and VRF seed to create a deterministic seed
        let mut combined = Vec::new();
        combined.extend_from_slice(commitment.as_bytes());
        combined.extend_from_slice(vrf_seed.as_bytes());

        // Hash the combined data to create a seed
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&combined);
        let seed = hasher.finalize().to_vec();

        Ok(Self { seed })
    }

    /// Generate a zero-knowledge proof for the VRF
    pub fn generate_zk_proof(&self, input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        debug!("Generating ZK proof for VRF");

        // Generate the VRF output
        let output = self.generate(input)?;
        debug!("Generated VRF output: {} bytes", output.len());

        // In a real implementation, this would create a circuit-based ZK proof
        // For now, we'll create a simplified proof
        let mut proof = Vec::new();
        proof.extend_from_slice(b"zk-proof-"); // Header
        proof.extend_from_slice(&output); // Output

        info!("Generated ZK proof: {} bytes", proof.len());
        Ok(proof)
    }

    /// Verify a zero-knowledge proof for the VRF
    pub fn verify_zk_proof(&self, input: &[u8], proof: &[u8]) -> Result<bool, Box<dyn Error>> {
        debug!("Verifying ZK proof for VRF");

        // Simple verification for the simplified proof format
        if proof.len() < 9 || &proof[0..9] != b"zk-proof-" {
            warn!("Invalid ZK proof format");
            return Ok(false);
        }

        // Extract output from proof
        let output = &proof[9..];

        // Verify the output matches what we'd generate
        let valid = self.verify(input, output)?;

        info!(
            "ZK proof verification result: {}",
            if valid { "valid" } else { "invalid" }
        );
        Ok(valid)
    }
}

/// This creates a deterministic but unpredictable value from a ZK proof seed
pub fn generate_vrf_proof(quantum_key: &[u8], input_data: &[u8]) -> Result<String, Box<dyn Error>> {
    debug!("Generating VRF proof from quantum key");

    // Create VRF instance
    let vrf = VerifiableRandomFunction::new(quantum_key);
    let output = vrf.generate(input_data)?;

    info!(
        "Generated VRF proof from quantum key: {} bytes",
        output.len()
    );
    Ok(hex::encode(output))
}

pub fn verify_vrf_proof(
    proof: &str,
    quantum_key: &[u8],
    input_data: &[u8],
) -> Result<bool, Box<dyn Error>> {
    debug!("Verifying VRF proof");

    let vrf = VerifiableRandomFunction::new(quantum_key);
    let output = hex::decode(proof)?;
    let result = vrf.verify(input_data, &output)?;

    info!(
        "VRF proof verification result: {}",
        if result { "valid" } else { "invalid" }
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrf() -> Result<(), Box<dyn Error>> {
        // Create VRF with test seed
        let seed = b"test-vrf-seed";
        let vrf = VerifiableRandomFunction::new(seed);

        // Generate output for test input
        let input = b"test-input";
        let output = vrf.generate(input)?;

        // Verify the output
        let valid = vrf.verify(input, &output)?;
        assert!(valid, "VRF verification should succeed");

        // Generate and verify ZK proof
        let proof = vrf.generate_zk_proof(input)?;
        let zk_valid = vrf.verify_zk_proof(input, &proof)?;
        assert!(zk_valid, "ZK proof verification should succeed");

        Ok(())
    }
}
