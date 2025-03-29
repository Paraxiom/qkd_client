use crate::zk::stark::field::FieldElement;
use sha3::{Digest, Sha3_256};
use std::error::Error;
use std::fmt;
use tracing::{debug, info};

/// A more robust polynomial commitment scheme for ZK-STARKs.
/// This implements a Merkle-tree based commitment scheme, which is a key component
/// of production-grade STARK implementations.
pub struct PolyCommitment {
    /// The field elements representing polynomial evaluations
    evaluations: Vec<FieldElement>,
    
    /// Merkle tree root hash for the commitment
    root: Vec<u8>,
    
    /// The layers of the Merkle tree, from leaves to root
    layers: Vec<Vec<Vec<u8>>>,
    
    /// The domain size - must be a power of 2
    domain_size: usize,
    
    /// Security parameter (affects the number of queries)
    security_parameter: usize,
}

impl PolyCommitment {
    /// Create a new polynomial commitment from evaluations
    pub fn new(evaluations: &[FieldElement], security_parameter: usize) -> Result<Self, Box<dyn Error>> {
        // Domain size must be a power of 2
        let domain_size = evaluations.len();
        if !domain_size.is_power_of_two() {
            return Err("Domain size must be a power of 2".into());
        }
        
        if security_parameter < 80 {
            return Err("Security parameter must be at least 80 bits".into());
        }
        
        // Create leaf nodes of the Merkle tree from evaluations
        let mut layers = Vec::new();
        let mut leaf_layer = Vec::with_capacity(domain_size);
        
        for (i, eval) in evaluations.iter().enumerate() {
            let leaf = Self::hash_leaf(i, eval);
            leaf_layer.push(leaf);
        }
        
        layers.push(leaf_layer);
        
        // Build the Merkle tree
        let mut current_layer = 0;
        while layers[current_layer].len() > 1 {
            let current_nodes = &layers[current_layer];
            let mut next_layer = Vec::new();
            
            for i in 0..current_nodes.len() / 2 {
                let left = &current_nodes[i * 2];
                let right = &current_nodes[i * 2 + 1];
                let parent = Self::hash_node(left, right);
                next_layer.push(parent);
            }
            
            layers.push(next_layer);
            current_layer += 1;
        }
        
        // The root is the last layer's only element
        let root = layers.last().unwrap()[0].clone();
        
        Ok(Self {
            evaluations: evaluations.to_vec(),
            root,
            layers,
            domain_size,
            security_parameter,
        })
    }
    
    /// Get the Merkle root of the commitment
    pub fn root(&self) -> &[u8] {
        &self.root
    }
    
    /// Generate a proof for an evaluation at a specific point
    pub fn prove(&self, index: usize) -> Result<PolyProof, Box<dyn Error>> {
        if index >= self.domain_size {
            return Err(format!("Index {} out of range for domain size {}", index, self.domain_size).into());
        }
        
        let mut path = Vec::new();
        let mut current_index = index;
        
        // Build the Merkle proof by collecting sibling nodes
        for layer in 0..self.layers.len() - 1 {
            let sibling_index = current_index ^ 1; // Flip least significant bit to get sibling
            if sibling_index < self.layers[layer].len() {
                let sibling = self.layers[layer][sibling_index].clone();
                path.push((sibling_index, sibling));
            }
            current_index /= 2;
        }
        
        Ok(PolyProof {
            eval: self.evaluations[index],
            index,
            path,
        })
    }
    
    /// Get multiple proofs for batch verification
    pub fn batch_prove(&self, indices: &[usize]) -> Result<Vec<PolyProof>, Box<dyn Error>> {
        indices.iter().map(|&index| self.prove(index)).collect()
    }
    
    /// Verify a polynomial proof against the commitment
    pub fn verify(&self, proof: &PolyProof) -> Result<bool, Box<dyn Error>> {
        if proof.index >= self.domain_size {
            return Err("Proof index out of range".into());
        }
        
        // Start with the leaf hash
        let mut current_hash = Self::hash_leaf(proof.index, &proof.eval);
        let mut current_index = proof.index;
        
        // Traverse up the Merkle tree
        for (sibling_index, sibling) in &proof.path {
            let (left, right) = if current_index % 2 == 0 {
                // Current node is left child
                (&current_hash, sibling)
            } else {
                // Current node is right child
                (sibling, &current_hash)
            };
            
            // Compute parent hash
            current_hash = Self::hash_node(left, right);
            current_index /= 2;
        }
        
        // Verify computed root matches the commitment root
        Ok(current_hash == self.root)
    }
    
    /// Batch verify multiple proofs
    pub fn batch_verify(&self, proofs: &[PolyProof]) -> Result<bool, Box<dyn Error>> {
        for proof in proofs {
            if !self.verify(proof)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Hash a leaf node
    fn hash_leaf(index: usize, eval: &FieldElement) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        
        // Include "leaf" domain separator
        hasher.update(b"leaf");
        
        // Include index
        hasher.update(&index.to_le_bytes());
        
        // Include field element value
        hasher.update(&eval.to_bytes());
        
        hasher.finalize().to_vec()
    }
    
    /// Hash an internal node from left and right children
    fn hash_node(left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        
        // Include "node" domain separator
        hasher.update(b"node");
        
        // Include both child nodes
        hasher.update(left);
        hasher.update(right);
        
        hasher.finalize().to_vec()
    }
    
    /// Get the security parameter
    pub fn security_parameter(&self) -> usize {
        self.security_parameter
    }
    
    /// Get the domain size
    pub fn domain_size(&self) -> usize {
        self.domain_size
    }
}

/// A proof for a polynomial evaluation at a specific point
#[derive(Debug, Clone)]
pub struct PolyProof {
    /// The field element representing the evaluation
    pub eval: FieldElement,
    
    /// The index in the domain
    pub index: usize,
    
    /// The Merkle authentication path (sibling nodes)
    pub path: Vec<(usize, Vec<u8>)>,
}

impl PolyProof {
    /// Serialize the proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Add index
        bytes.extend_from_slice(&self.index.to_le_bytes());
        
        // Add eval field element
        bytes.extend_from_slice(&self.eval.to_bytes());
        
        // Add path length
        bytes.extend_from_slice(&(self.path.len() as u32).to_le_bytes());
        
        // Add each path element
        for (idx, hash) in &self.path {
            bytes.extend_from_slice(&(*idx as u32).to_le_bytes());
            bytes.extend_from_slice(&(hash.len() as u32).to_le_bytes());
            bytes.extend_from_slice(hash);
        }
        
        bytes
    }

    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        if bytes.len() < 40 { // Minimum size: eval(32) + index(4) + path_len(4)
            return Err("Proof data too short".into());
        }
        
        let mut pos = 0;
        
        // Read evaluation
        let eval = FieldElement::from_bytes(&bytes[pos..pos+32])?;
        pos += 32;
        
        // Read index
        let mut index_bytes = [0u8; 4];
        index_bytes.copy_from_slice(&bytes[pos..pos+4]);
        let index = u32::from_le_bytes(index_bytes) as usize;
        pos += 4;
        
        // Read number of path elements
        let mut path_len_bytes = [0u8; 4];
        path_len_bytes.copy_from_slice(&bytes[pos..pos+4]);
        let path_len = u32::from_le_bytes(path_len_bytes) as usize;
        pos += 4;
        
        // Read path elements
        let mut path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            if pos + 8 > bytes.len() {
                return Err("Proof data truncated".into());
            }
            
            // Read sibling index
            let mut sibling_index_bytes = [0u8; 4];
            sibling_index_bytes.copy_from_slice(&bytes[pos..pos+4]);
            let sibling_index = u32::from_le_bytes(sibling_index_bytes) as usize;
            pos += 4;
            
            // Read hash length
            let mut hash_len_bytes = [0u8; 4];
            hash_len_bytes.copy_from_slice(&bytes[pos..pos+4]);
            let hash_len = u32::from_le_bytes(hash_len_bytes) as usize;
            pos += 4;
            
            if pos + hash_len > bytes.len() {
                return Err("Proof data truncated".into());
            }
            
            // Read hash
            let hash = bytes[pos..pos+hash_len].to_vec();
            pos += hash_len;
            
            path.push((sibling_index, hash));
        }
        
        Ok(Self {
            eval,
            index,
            path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::stark::field::FieldElement;
    
    #[test]
    fn test_poly_commitment_create_verify() -> Result<(), Box<dyn Error>> {
        // Create a polynomial evaluated at a power-of-2 domain
        let domain_size = 16;
        let mut evaluations = Vec::with_capacity(domain_size);
        
        for i in 0..domain_size {
            evaluations.push(FieldElement::from_u64(i as u64 * i as u64));
        }
        
        // Create the commitment
        let commitment = PolyCommitment::new(&evaluations, 128)?;
        
        // Generate and verify a proof for each point
        for i in 0..domain_size {
            let proof = commitment.prove(i)?;
            assert!(commitment.verify(&proof)?, "Proof should verify for index {}", i);
        }
        
        // Try with a batch of indices
        let indices = vec![1, 3, 7, 15];
        let proofs = commitment.batch_prove(&indices)?;
        assert!(commitment.batch_verify(&proofs)?, "Batch proofs should verify");
        
        // Try with a tampered proof
        let mut tampered_proof = commitment.prove(5)?;
        tampered_proof.eval = FieldElement::from_u64(999);
        assert!(!commitment.verify(&tampered_proof)?, "Tampered proof should not verify");
        
        Ok(())
    }
    
    #[test]
    fn test_poly_proof_serialization() -> Result<(), Box<dyn Error>> {
        // Create a polynomial evaluated at a power-of-2 domain
        let domain_size = 8;
        let mut evaluations = Vec::with_capacity(domain_size);
        
        for i in 0..domain_size {
            evaluations.push(FieldElement::from_u64(i as u64));
        }
        
        // Create the commitment
        let commitment = PolyCommitment::new(&evaluations, 128)?;
        
        // Generate a proof
        let proof = commitment.prove(3)?;
        
        // Serialize and deserialize
        let bytes = proof.to_bytes();
        let deserialized_proof = PolyProof::from_bytes(&bytes)?;
        
        // Verify the deserialized proof
        assert_eq!(proof.index, deserialized_proof.index, "Indices should match");
        assert_eq!(proof.eval, deserialized_proof.eval, "Evaluations should match");
        assert_eq!(proof.path.len(), deserialized_proof.path.len(), "Path lengths should match");
        
        // Verify the proof still works
        assert!(commitment.verify(&deserialized_proof)?, "Deserialized proof should verify");
        
        Ok(())
    }
    
    #[test]
    fn test_poly_commitment_security_params() -> Result<(), Box<dyn Error>> {
        // Create evaluations
        let domain_size = 32;
        let mut evaluations = Vec::with_capacity(domain_size);
        
        for i in 0..domain_size {
            evaluations.push(FieldElement::from_u64(i as u64));
        }
        
        // Try creating with invalid security parameter
        let result = PolyCommitment::new(&evaluations, 40);
        assert!(result.is_err(), "Should reject low security parameter");
        
        // Try creating with non-power-of-2 domain
        let mut odd_evaluations = evaluations.clone();
        odd_evaluations.push(FieldElement::from_u64(domain_size as u64));
        
        let result = PolyCommitment::new(&odd_evaluations, 128);
        assert!(result.is_err(), "Should reject non-power-of-2 domain size");
        
        Ok(())
    }
}
