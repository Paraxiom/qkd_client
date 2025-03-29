//! Merkle tree implementation for commitments in STARK proofs
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::error::Error;

/// Merkle tree for STARK proofs
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Root hash of the tree
    pub root: Vec<u8>,
    /// Leaves of the tree (data elements)
    leaves: Vec<Vec<u8>>,
    /// Internal nodes of the tree
    nodes: HashMap<usize, Vec<Vec<u8>>>,
}

impl MerkleTree {
    /// Create a new Merkle tree from leaves
    pub fn new(leaves: Vec<Vec<u8>>) -> Result<Self, Box<dyn Error>> {
        if leaves.is_empty() {
            return Err("Cannot create Merkle tree with empty leaves".into());
        }

        // Ensure leaf count is a power of 2
        let leaf_count = leaves.len();
        let next_power_of_two = leaf_count.next_power_of_two();
        
        let mut padded_leaves = leaves.clone();
        if leaf_count < next_power_of_two {
            // Pad with copies of the last leaf
            let last_leaf = leaves.last().unwrap();
            for _ in 0..(next_power_of_two - leaf_count) {
                padded_leaves.push(last_leaf.clone());
            }
        }

        let mut tree = Self {
            root: Vec::new(),
            leaves: padded_leaves,
            nodes: HashMap::new(),
        };

        tree.build_tree()?;
        Ok(tree)
    }

    /// Build the Merkle tree from leaves
    fn build_tree(&mut self) -> Result<(), Box<dyn Error>> {
        let leaf_count = self.leaves.len();
        
        // Initialize level 0 with leaf hashes
        let mut level_nodes = Vec::with_capacity(leaf_count);
        for leaf in &self.leaves {
            level_nodes.push(Self::hash(leaf));
        }
        
        self.nodes.insert(0, level_nodes);
        
        // Build the tree bottom-up
        let mut current_level = 0;
        let mut current_count = leaf_count;
        
        while current_count > 1 {
            let next_level = current_level + 1;
            let next_count = (current_count + 1) / 2;
            let mut next_nodes = Vec::with_capacity(next_count);
            
            for i in 0..(current_count / 2) {
                let left = &self.nodes[&current_level][2 * i];
                let right = &self.nodes[&current_level][2 * i + 1];
                
                // Concatenate and hash
                let mut combined = left.clone();
                combined.extend_from_slice(right);
                next_nodes.push(Self::hash(&combined));
            }
            
            // Handle odd number of nodes
            if current_count % 2 == 1 {
                let last = &self.nodes[&current_level][current_count - 1];
                next_nodes.push(last.clone());
            }
            
            self.nodes.insert(next_level, next_nodes);
            
            current_level = next_level;
            current_count = next_count;
        }
        
        // Set the root
        self.root = self.nodes[&current_level][0].clone();
        Ok(())
    }

    /// Generate a Merkle proof for a leaf at a given index
    pub fn generate_proof(&self, leaf_index: usize) -> Result<MerkleProof, Box<dyn Error>> {
        if leaf_index >= self.leaves.len() {
            return Err(format!("Leaf index {} out of bounds", leaf_index).into());
        }

        let mut proof = MerkleProof {
            leaf: self.leaves[leaf_index].clone(),
            leaf_index,
            siblings: Vec::new(),
        };

        let mut current_index = leaf_index;
        let mut current_level = 0;
        let mut nodes_at_level = self.leaves.len().next_power_of_two();
        
        while nodes_at_level > 1 {
            let is_right = current_index % 2 == 1;
            let sibling_index = if is_right { current_index - 1 } else { current_index + 1 };
            
            // Don't add sibling if we're at the end with an odd number of nodes
            if sibling_index < nodes_at_level && sibling_index < self.nodes[&current_level].len() {
                proof.siblings.push(self.nodes[&current_level][sibling_index].clone());
            }
            
            // Move to parent
            current_index /= 2;
            current_level += 1;
            nodes_at_level = (nodes_at_level + 1) / 2;
        }

        Ok(proof)
    }

    /// Hash a slice of bytes using Keccak256
    fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

/// Merkle proof for a leaf
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The leaf value
    pub leaf: Vec<u8>,
    /// The index of the leaf in the tree
    pub leaf_index: usize,
    /// Sibling hashes along the path from leaf to root
    pub siblings: Vec<Vec<u8>>,
}

impl MerkleProof {
    /// Verify the Merkle proof against a root hash
    pub fn verify(&self, root: &[u8]) -> bool {
        let leaf_hash = MerkleTree::hash(&self.leaf);
        
        let mut current_hash = leaf_hash;
        let mut current_index = self.leaf_index;
        
        for sibling in &self.siblings {
            let is_right = current_index % 2 == 1;
            
            // Combine with sibling
            let mut combined = Vec::new();
            if is_right {
                combined.extend_from_slice(sibling);
                combined.extend_from_slice(&current_hash);
            } else {
                combined.extend_from_slice(&current_hash);
                combined.extend_from_slice(sibling);
            }
            
            current_hash = MerkleTree::hash(&combined);
            current_index /= 2;
        }
        
        current_hash == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_creation() -> Result<(), Box<dyn Error>> {
        // Create leaves
        let leaves = vec![
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
            b"leaf3".to_vec(),
            b"leaf4".to_vec(),
        ];
        
        let tree = MerkleTree::new(leaves.clone())?;
        
        // Tree should have a valid root
        assert!(!tree.root.is_empty());
        
        // Tree should store all leaves
        assert_eq!(tree.leaves, leaves);
        
        Ok(())
    }

    #[test]
    fn test_merkle_proof_verification() -> Result<(), Box<dyn Error>> {
        // Create leaves
        let leaves = vec![
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
            b"leaf3".to_vec(),
            b"leaf4".to_vec(),
        ];
        
        let tree = MerkleTree::new(leaves.clone())?;
        
        // Generate proofs for each leaf
        for i in 0..leaves.len() {
            let proof = tree.generate_proof(i)?;
            
            // Verify the proof
            assert!(proof.verify(&tree.root));
            
            // Check leaf value matches
            assert_eq!(proof.leaf, leaves[i]);
        }
        
        Ok(())
    }

    #[test]
    fn test_merkle_proof_tamper_detection() -> Result<(), Box<dyn Error>> {
        // Create leaves
        let leaves = vec![
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
            b"leaf3".to_vec(),
            b"leaf4".to_vec(),
        ];
        
        let tree = MerkleTree::new(leaves.clone())?;
        
        // Generate proof for leaf 0
        let mut proof = tree.generate_proof(0)?;
        
        // Tamper with the leaf value
        proof.leaf = b"tampered".to_vec();
        
        // Verification should fail
        assert!(!proof.verify(&tree.root));
        
        Ok(())
    }
}
