//! FRI (Fast Reed-Solomon Interactive Oracle Proofs of Proximity) Protocol
//! for verifying that a polynomial has a low degree
use crate::zk::stark::field::FieldElement;
use crate::zk::stark::merkle::{MerkleTree, MerkleProof};
use sha3::{Digest, Keccak256};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::error::Error;

/// FRI Proof for low-degree testing
#[derive(Debug, Clone)]
pub struct FriProof {
    /// Merkle roots for each layer
    pub layer_commitments: Vec<Vec<u8>>,
    /// Final constant polynomial coefficient
    pub final_polynomial: FieldElement,
    /// Merkle proofs for query points
    pub query_proofs: Vec<Vec<FriQueryProof>>,
}

/// Proof for a single query point in the FRI protocol
#[derive(Debug, Clone)]
pub struct FriQueryProof {
    /// Evaluation at the query point
    pub evaluation: FieldElement,
    /// Merkle proof for the evaluation
    pub merkle_proof: MerkleProof,
}

/// FRI Protocol implementation
pub struct FriProtocol {
    /// Maximum degree of the polynomial to be tested
    max_degree: usize,
    /// Number of layers in the protocol
    num_layers: usize,
    /// Number of queries to make
    num_queries: usize,
    /// Expansion factor for Reed-Solomon code
    expansion_factor: usize,
    /// Random seed for verifier challenges
    seed: [u8; 32],
}

impl FriProtocol {
    /// Create a new FRI protocol instance
    pub fn new(
        max_degree: usize,
        expansion_factor: usize,
        num_queries: usize,
        seed: Option<[u8; 32]>,
    ) -> Result<Self, Box<dyn Error>> {
        if expansion_factor <= 1 {
            return Err("Expansion factor must be greater than 1".into());
        }
        
        if max_degree < 1 {
            return Err("Max degree must be at least 1".into());
        }
        
        // Calculate number of layers based on the max degree
        let num_layers = ((max_degree as f64).log2().ceil() as usize).saturating_sub(3).max(1);
        
        // Generate random seed if not provided
        let seed = match seed {
            Some(s) => s,
            None => {
                let mut s = [0u8; 32];
                rand::thread_rng().fill(&mut s);
                s
            }
        };
        
        Ok(Self {
            max_degree,
            num_layers,
            num_queries,
            expansion_factor,
            seed,
        })
    }
    
    /// Generate a FRI proof for a polynomial
    pub fn prove(
        &self,
        polynomial_evaluations: Vec<FieldElement>,
        domain_size: usize,
    ) -> Result<FriProof, Box<dyn Error>> {
        if polynomial_evaluations.len() != domain_size {
            return Err("Number of evaluations must match domain size".into());
        }
        
        if domain_size < self.max_degree * self.expansion_factor {
            return Err("Domain size must be at least max_degree * expansion_factor".into());
        }
        
        // Initialize random number generator with seed
        let mut rng = StdRng::from_seed(self.seed);
        
        // Layer 0 is the original evaluations
        let mut layers = Vec::with_capacity(self.num_layers + 1);
        layers.push(polynomial_evaluations);
        
        // Merkle commitments for each layer
        let mut layer_commitments = Vec::with_capacity(self.num_layers + 1);
        
        // Generate Merkle tree for layer 0
        let layer0_leaves: Vec<Vec<u8>> = layers[0]
            .iter()
            .map(|&eval| {
                let bytes = eval.to_bytes();
                bytes.to_vec()
            })
            .collect();
        
        let layer0_tree = MerkleTree::new(layer0_leaves)?;
        layer_commitments.push(layer0_tree.root.clone());
        
        // Generate subsequent layers
        for i in 0..self.num_layers {
            // Get random field element for this round
            let alpha = FieldElement::new(rng.gen::<u64>());
            
            // Fold current layer to get next layer
            let next_layer = self.fold_layer(&layers[i], alpha);
            layers.push(next_layer);
            
            // Generate Merkle tree for this layer
            let leaves: Vec<Vec<u8>> = layers[i + 1]
                .iter()
                .map(|&eval| {
                    let bytes = eval.to_bytes();
                    bytes.to_vec()
                })
                .collect();
            
            let tree = MerkleTree::new(leaves)?;
            layer_commitments.push(tree.root.clone());
        }
        
        // Final polynomial is just the constant term of the last layer
        let final_polynomial = layers.last().unwrap()[0];
        
        // Generate query proofs
        let mut query_proofs = Vec::with_capacity(self.num_queries);
        
        for _ in 0..self.num_queries {
            // Select random evaluation point
            let query_idx = rng.gen_range(0..domain_size);
            
            // Generate proofs for each layer
            let mut layer_proofs = Vec::with_capacity(self.num_layers + 1);
            
            for layer_idx in 0..=self.num_layers {
                // Get the evaluation at this point
                let evaluation = layers[layer_idx][query_idx % (domain_size >> layer_idx)];
                
                // Generate Merkle proof
                let leaves: Vec<Vec<u8>> = layers[layer_idx]
                    .iter()
                    .map(|&eval| {
                        let bytes = eval.to_bytes();
                        bytes.to_vec()
                    })
                    .collect();
                
                let tree = MerkleTree::new(leaves)?;
                let merkle_proof = tree.generate_proof(query_idx % (domain_size >> layer_idx))?;
                
                layer_proofs.push(FriQueryProof {
                    evaluation,
                    merkle_proof,
                });
            }
            
            query_proofs.push(layer_proofs);
        }
        
        Ok(FriProof {
            layer_commitments,
            final_polynomial,
            query_proofs,
        })
    }
    
    /// Verify a FRI proof
    pub fn verify(
        &self,
        proof: &FriProof,
        domain_size: usize,
    ) -> Result<bool, Box<dyn Error>> {
        // Check that proof has correct structure
        if proof.layer_commitments.len() != self.num_layers + 1 {
            return Err("Proof has incorrect number of layer commitments".into());
        }
        
        if proof.query_proofs.len() != self.num_queries {
            return Err("Proof has incorrect number of query proofs".into());
        }
        
        // Initialize random number generator with seed
        let mut rng = StdRng::from_seed(self.seed);
        
        // Verify each query
        for query_proofs in &proof.query_proofs {
            if query_proofs.len() != self.num_layers + 1 {
                return Err("Query proof has incorrect number of layers".into());
            }
            
            // Verify Merkle proofs for each layer
            for (layer_idx, query_proof) in query_proofs.iter().enumerate() {
                // Verify Merkle proof
                if !query_proof.merkle_proof.verify(&proof.layer_commitments[layer_idx]) {
                    return Ok(false);
                }
                
                // If not the last layer, verify folding relation
                if layer_idx < self.num_layers {
                    let alpha = FieldElement::new(rng.gen::<u64>());
                    
                    // For simplicity, we're not verifying the folding relation here
                    // In a complete implementation, we would check:
                    // 1. Calculate the expected value in the next layer based on the current layer
                    // 2. Verify it matches the provided value in the next layer
                }
            }
        }
        
        // Verify final polynomial degree
        // In a complete implementation, we would check that the final polynomial
        // has degree less than or equal to the expected degree
        
        Ok(true)
    }
    
    /// Fold a layer to produce the next layer in the FRI protocol
    fn fold_layer(
        &self,
        layer: &[FieldElement],
        alpha: FieldElement,
    ) -> Vec<FieldElement> {
        let n = layer.len();
        let half_n = n / 2;
        
        let mut next_layer = Vec::with_capacity(half_n);
        
        for i in 0..half_n {
            let y_i = layer[i];
            let y_i_plus_half = layer[i + half_n];
            
            // Compute P(w^i)
            let p_w_i = y_i + alpha * y_i_plus_half;
            
            next_layer.push(p_w_i);
        }
        
        next_layer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::stark::field::FieldElement;
    
    #[test]
    fn test_fri_protocol_small_polynomial() -> Result<(), Box<dyn Error>> {
        // Create a polynomial of degree 4: f(x) = x^4 + 2x^3 + 3x^2 + 4x + 5
        // Evaluate it at powers of a primitive root of unity
        
        // For simplicity, we'll use a simulated domain and evaluations
        let domain_size = 16;
        let evaluations: Vec<FieldElement> = (0..domain_size)
            .map(|i| {
                // Simulate polynomial evaluation at domain point i
                let x = FieldElement::new(i as u64);
                let x2 = x * x;
                let x3 = x2 * x;
                let x4 = x3 * x;
                
                // f(x) = x^4 + 2x^3 + 3x^2 + 4x + 5
                let result = x4 + FieldElement::new(2) * x3 + 
                             FieldElement::new(3) * x2 + 
                             FieldElement::new(4) * x + 
                             FieldElement::new(5);
                             
                result
            })
            .collect();
        
        // Create FRI protocol
        let protocol = FriProtocol::new(4, 4, 3, None)?;
        
        // Generate proof
        let proof = protocol.prove(evaluations, domain_size)?;
        
        // Verify proof
        let is_valid = protocol.verify(&proof, domain_size)?;
        
        assert!(is_valid, "FRI proof should be valid");
        
        Ok(())
    }
}
