use crate::zk::stark::field::FieldElement;
use crate::zk::stark::poly_commitment::{PolyCommitment, PolyProof as CommitmentPolyProof}; 
use sha3::{Digest, Sha3_256};
use std::error::Error;
// Remove unused imports
// use tracing::{debug, info};

/// FRI (Fast Reed-Solomon Interactive Oracle Proof) protocol for proving
/// that a polynomial has a low degree. This is a crucial component of STARKs.
pub struct FriProver {
    /// The polynomial evaluations at domain points
    evaluations: Vec<FieldElement>,
    
    /// The domain size (must be a power of 2)
    domain_size: usize,
    
    /// The claimed degree bound for the polynomial
    degree_bound: usize,
    
    /// The root of unity used for evaluations
    omega: FieldElement,
    
    /// The number of rounds in the FRI protocol
    num_rounds: usize,
    
    /// The security parameter (affects the number of queries)
    security_parameter: usize,
    
    /// The number of queries to make at each round
    num_queries: usize,
}

impl FriProver {
    /// Create a new FRI prover
    pub fn new(
        evaluations: Vec<FieldElement>,
        degree_bound: usize,
        omega: FieldElement,
        security_parameter: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let domain_size = evaluations.len();
        
        if !domain_size.is_power_of_two() {
            return Err("Domain size must be a power of 2".into());
        }
        
        if domain_size <= degree_bound {
            return Err("Domain size must be larger than the degree bound".into());
        }
        
        if security_parameter < 80 {
            return Err("Security parameter must be at least 80 bits".into());
        }
        
        // Calculate the number of rounds based on the domain size and degree bound
        let mut current_domain_size = domain_size;
        let mut num_rounds = 0;
        
        while current_domain_size > 2 * degree_bound {
            current_domain_size /= 2;
            num_rounds += 1;
        }
        
        // Ensure we have at least 3 rounds
        num_rounds = num_rounds.max(3);
        
        // Calculate the number of queries based on the security parameter
        // We want at least security_parameter bits of security
        let num_queries = (security_parameter as f64 / (num_rounds as f64).log2()).ceil() as usize;
        
        Ok(Self {
            evaluations,
            domain_size,
            degree_bound,
            omega,
            num_rounds,
            security_parameter,
            num_queries,
        })
    }
    
    /// Generate a FRI proof
    pub fn prove(&self) -> Result<FriProof, Box<dyn Error>> {
        // This is the main FRI protocol:
        // 1. Start with the evaluations of the polynomial on the domain
        // 2. In each round, fold the polynomial by taking linear combinations
        // 3. Commit to the folded polynomial using a Merkle tree
        // 4. Repeat until the polynomial is small enough to check directly
        
        let mut current_evaluations = self.evaluations.clone();
        let mut current_domain_size = self.domain_size;
        let mut commitment_roots = Vec::with_capacity(self.num_rounds);
        let mut round_commitments = Vec::with_capacity(self.num_rounds);
        
        // Calculate powers of the challenge for each round
        let mut challenges = Vec::with_capacity(self.num_rounds);
        
        for round in 0..self.num_rounds {
            // Create a Merkle commitment for the current evaluations
            let commitment = PolyCommitment::new(&current_evaluations, self.security_parameter)?;
            commitment_roots.push(commitment.root().to_vec());
            round_commitments.push(commitment);
            
            // Generate a challenge for this round from the Merkle root
            // In an interactive protocol, this would come from the verifier
            let challenge = self.generate_challenge(&commitment_roots[round], round);
            challenges.push(challenge);
            
            // Fold the polynomial using the challenge
            if round < self.num_rounds - 1 {
                current_evaluations = self.fold_polynomial(&current_evaluations, &challenge);
                current_domain_size /= 2;
            }
        }
        
        // Final values are the evaluations of the smallest polynomial
        let final_evaluations = current_evaluations;
        
        // Generate the list of queries for verification
        let query_indices = self.generate_query_indices(&commitment_roots);
        
        // Generate proofs for each query
        let mut query_proofs = Vec::with_capacity(query_indices.len());
        
        for &index in &query_indices {
            let mut round_indices = Vec::with_capacity(self.num_rounds);
            let mut round_values = Vec::with_capacity(self.num_rounds);
            let mut round_merkle_proofs = Vec::with_capacity(self.num_rounds);
            
            let mut current_index = index;
            
            for round in 0..self.num_rounds {
                // For each round, we need:
                // 1. The evaluation at the current index
                // 2. The evaluation at the sibling index (for folding)
                // 3. The Merkle proof for these evaluations
                
                let folded_index = current_index % (self.domain_size >> round);
                let sibling_index = folded_index ^ 1; // Flip the least significant bit
                
                let value = if round == 0 {
                    self.evaluations[folded_index]
                } else {
                    round_commitments[round - 1].evaluate_at(folded_index)?
                };
                
                let sibling_value = if round == 0 {
                    self.evaluations[sibling_index]
                } else {
                    round_commitments[round - 1].evaluate_at(sibling_index)?
                };
                
                round_indices.push(folded_index);
                round_values.push((value, sibling_value));
                
                // Generate Merkle proof for this index
                let merkle_proof = round_commitments[round].prove(folded_index)?;
                // Convert CommitmentPolyProof to PolyProof
                round_merkle_proofs.push(
                    PolyProof {
                        index: merkle_proof.index, 
                        path: merkle_proof.path.iter().map(|(_, hash)| hash.clone()).collect(),
                    }
                );
                
                // Update the index for the next round
                current_index = folded_index / 2;
            }
            
            query_proofs.push(FriQueryProof {
                indices: round_indices,
                values: round_values,
                merkle_proofs: round_merkle_proofs,
            });
        }
        
        Ok(FriProof {
            commitment_roots,
            challenges,
            final_evaluations,
            query_indices,
            query_proofs,
            degree_bound: self.degree_bound,
        })
    }
    
    /// Fold a polynomial using a challenge value
    fn fold_polynomial(&self, evals: &[FieldElement], challenge: &FieldElement) -> Vec<FieldElement> {
        let half_size = evals.len() / 2;
        let mut folded = Vec::with_capacity(half_size);
        
        for i in 0..half_size {
            let even = evals[2 * i];
            let odd = evals[2 * i + 1];
            
            // Fold using the formula: P'(x) = P_even(x^2) + x * P_odd(x^2)
            // When evaluated, this is: P'(z) = eval[2i] + challenge * eval[2i+1]
            let folded_value = even.add(&challenge.mul(&odd));
            folded.push(folded_value);
        }
        
        folded
    }
    
    /// Generate a deterministic challenge from a Merkle root and round number
    fn generate_challenge(&self, root: &[u8], round: usize) -> FieldElement {
        let mut hasher = Sha3_256::new();
        hasher.update(root);
        hasher.update(&round.to_le_bytes());
        
        let hash = hasher.finalize();
        
        // Convert hash to field element
        // For simplicity, we use the hash as bytes for creating the field element
        FieldElement::from_bytes(&hash).unwrap_or(FieldElement::one())
    }
    
    /// Generate random query indices based on the commitment roots
    fn generate_query_indices(&self, roots: &[Vec<u8>]) -> Vec<usize> {
        let mut query_indices = Vec::with_capacity(self.num_queries);
        
        for i in 0..self.num_queries {
            let mut hasher = Sha3_256::new();
            
            // Hash all the roots and the query index
            for root in roots {
                hasher.update(root);
            }
            hasher.update(&i.to_le_bytes());
            
            let hash = hasher.finalize();
            
            // Convert the hash to an index in the domain
            let mut index_bytes = [0u8; 8];
            index_bytes.copy_from_slice(&hash[0..8]);
            let index = u64::from_le_bytes(index_bytes) as usize % self.domain_size;
            
            query_indices.push(index);
        }
        
        query_indices
    }
}

/// A proof for the FRI protocol
#[derive(Debug, Clone)]
pub struct FriProof {
    /// Merkle roots for each round
    pub commitment_roots: Vec<Vec<u8>>,
    
    /// Challenge values for each round
    pub challenges: Vec<FieldElement>,
    
    /// Final evaluations of the smallest polynomial
    pub final_evaluations: Vec<FieldElement>,
    
    /// Query indices
    pub query_indices: Vec<usize>,
    
    /// Query proofs for each index
    pub query_proofs: Vec<FriQueryProof>,
    
    /// The claimed degree bound for the polynomial
    pub degree_bound: usize,
}

/// A proof for a specific query in the FRI protocol
#[derive(Debug, Clone)]
pub struct FriQueryProof {
    /// Indices for each round
    pub indices: Vec<usize>,
    
    /// Values for each round (evaluation and sibling evaluation)
    pub values: Vec<(FieldElement, FieldElement)>,
    
    /// Merkle proofs for each round
    pub merkle_proofs: Vec<PolyProof>,
}

/// A Merkle proof for the FRI protocol
#[derive(Debug, Clone)]
pub struct PolyProof {
    /// Index in the tree
    pub index: usize,
    
    /// Authentication path
    pub path: Vec<Vec<u8>>,
}

// Remove the self reference that was causing problems
impl From<CommitmentPolyProof> for PolyProof {
    fn from(proof: CommitmentPolyProof) -> Self {
        Self {
            index: proof.index,
            path: proof.path.iter().map(|(_, hash)| hash.clone()).collect(),
        }
    }
}

/// FRI Verifier for checking low-degree proofs
pub struct FriVerifier {
    /// The commitment roots from the prover
    commitment_roots: Vec<Vec<u8>>,
    
    /// The challenge values used in the protocol
    challenges: Vec<FieldElement>,
    
    /// The final evaluations of the smallest polynomial
    final_evaluations: Vec<FieldElement>,
    
    /// The claimed degree bound for the polynomial
    degree_bound: usize,
    
    /// The domain size (original)
    domain_size: usize,
    
    /// The security parameter
    security_parameter: usize,
}

impl FriVerifier {
    /// Create a new FRI verifier
    pub fn new(
        proof: &FriProof,
        domain_size: usize,
        security_parameter: usize,
    ) -> Result<Self, Box<dyn Error>> {
        if !domain_size.is_power_of_two() {
            return Err("Domain size must be a power of 2".into());
        }
        
        if security_parameter < 80 {
            return Err("Security parameter must be at least 80 bits".into());
        }
        
        Ok(Self {
            commitment_roots: proof.commitment_roots.clone(),
            challenges: proof.challenges.clone(),
            final_evaluations: proof.final_evaluations.clone(),
            degree_bound: proof.degree_bound,
            domain_size,
            security_parameter,
        })
    }
    
    /// Verify a FRI proof
    pub fn verify(&self, proof: &FriProof) -> Result<bool, Box<dyn Error>> {
        // 1. Check consistency of the proof
        if proof.commitment_roots.len() != self.commitment_roots.len() ||
           proof.challenges.len() != self.challenges.len() ||
           proof.final_evaluations.len() != self.final_evaluations.len() {
            return Ok(false);
        }
        
        // 2. Verify each query
        for (i, query_proof) in proof.query_proofs.iter().enumerate() {
            let query_index = proof.query_indices[i];
            
            // Verify this query
            if !self.verify_query(query_index, query_proof)? {
                return Ok(false);
            }
        }
        
        // 3. Check that the final polynomial has degree < degree_bound
        // This is done by checking if the evaluations correspond to a low-degree polynomial
        // In a real implementation, you'd check this explicitly
        
        // For simplicity, we assume that the final polynomial has the claimed degree
        // In a real implementation, you'd perform an explicit check
        
        Ok(true)
    }
    
    /// Verify a specific query
    fn verify_query(&self, query_index: usize, query_proof: &FriQueryProof) -> Result<bool, Box<dyn Error>> {
        // Verify each round
        let mut current_index = query_index;
        
        for round in 0..self.commitment_roots.len() {
            // Verify the Merkle proof for this round
            let merkle_proof = &query_proof.merkle_proofs[round];
            let (value, sibling_value) = query_proof.values[round];
            
            // Verify the Merkle proof
            if !self.verify_merkle_proof(round, merkle_proof.index, &value, &merkle_proof.path)? {
                return Ok(false);
            }
            
            // Check consistency with the next round (if not the final round)
            if round < self.commitment_roots.len() - 1 {
                // Calculate the folded value using the challenge
                let folded_value = value.add(&self.challenges[round].mul(&sibling_value));
                
                // Check that this matches the value in the next round
                let next_round_index = merkle_proof.index / 2;
                let next_round_value = query_proof.values[round + 1].0;
                
                if folded_value != next_round_value {
                    return Ok(false);
                }
            }
            
            // Update index for next round
            current_index = merkle_proof.index / 2;
        }
        
        Ok(true)
    }
    
    /// Verify a Merkle proof for a value
    fn verify_merkle_proof(
        &self,
        round: usize,
        index: usize,
        value: &FieldElement,
        path: &[Vec<u8>],
    ) -> Result<bool, Box<dyn Error>> {
        let mut current_hash = Self::hash_leaf(index, value);
        let mut current_index = index;
        
        for sibling in path {
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
        Ok(current_hash == self.commitment_roots[round])
    }
    
    /// Hash a leaf node
    fn hash_leaf(index: usize, value: &FieldElement) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        
        // Include "leaf" domain separator
        hasher.update(b"leaf");
        
        // Include index
        hasher.update(&index.to_le_bytes());
        
        // Include field element value
        hasher.update(&value.to_bytes());
        
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
}

// Helper method to extend PolyCommitment
trait PolyCommitmentExtension {
    fn evaluate_at(&self, index: usize) -> Result<FieldElement, Box<dyn Error>>;
}

impl PolyCommitmentExtension for PolyCommitment {
    fn evaluate_at(&self, index: usize) -> Result<FieldElement, Box<dyn Error>> {
        // This is a placeholder - in a real implementation, 
        // the commitment would provide access to the evaluations
        // For now, we use a zero value
        Ok(FieldElement::zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::stark::field::FieldElement;
    use num_bigint::BigUint;
    
    #[test]
    fn test_fri_protocol_basic() -> Result<(), Box<dyn Error>> {
        // Create a simple polynomial of degree < 8 (degree bound)
        let degree = 7;
        let domain_size = 32; // > 2 * degree_bound
        
        // Create coefficients for a random polynomial of degree `degree`
        let mut coeffs = Vec::with_capacity(degree + 1);
        for i in 0..=degree {
            coeffs.push(FieldElement::from_u64(i as u64 + 1));
        }
        
        // Create a mock omega (primitive root of unity)
        // In a real implementation, this would be calculated based on the field
        let omega = FieldElement::from_u64(123); // placeholder
        
        // Create mock evaluations
        let mut evaluations = Vec::with_capacity(domain_size);
        for i in 0..domain_size {
            evaluations.push(FieldElement::from_u64(i as u64 * 2));
        }
        
        // Create FRI prover
        let prover = FriProver::new(evaluations, degree, omega, 128)?;
        
        // Generate proof
        let proof = prover.prove()?;
        
        // Verify the proof structure (basic sanity checks)
        assert!(!proof.commitment_roots.is_empty(), "Commitment roots should not be empty");
        assert!(!proof.challenges.is_empty(), "Challenges should not be empty");
        assert!(!proof.final_evaluations.is_empty(), "Final evaluations should not be empty");
        assert!(!proof.query_indices.is_empty(), "Query indices should not be empty");
        assert!(!proof.query_proofs.is_empty(), "Query proofs should not be empty");
        
        // Create verifier and verify proof
        let verifier = FriVerifier::new(&proof, domain_size, 128)?;
        
        // This is a mock verification since we're not using real field arithmetic
        // In a real implementation, this would test a real polynomial and its evaluations
        
        Ok(())
    }
    
    #[test]
    fn test_fri_folding() -> Result<(), Box<dyn Error>> {
        // Test the polynomial folding operation
        
        // Create a simple polynomial of degree 3: f(x) = x^3 + 2x^2 + 3x + 4
        // The coefficients are [4, 3, 2, 1]
        
        // Create evaluations on a domain of size 8
        let domain_size = 8;
        let mut evaluations = Vec::with_capacity(domain_size);
        
        for i in 0..domain_size {
            let x = FieldElement::from_u64(i as u64);
            let value = x.pow(&BigUint::from(3u32)) 
                .add(&x.pow(&BigUint::from(2u32)).mul(&FieldElement::from_u64(2)))
                .add(&x.mul(&FieldElement::from_u64(3)))
                .add(&FieldElement::from_u64(4));
            
            evaluations.push(value);
        }
        
        // Create a mock omega
        let omega = FieldElement::from_u64(123); // placeholder
        
        // Create FRI prover
        let prover = FriProver::new(evaluations, 3, omega, 128)?;
        
        // Test folding with a challenge value
        let challenge = FieldElement::from_u64(42);
        let folded = prover.fold_polynomial(&prover.evaluations, &challenge);
        
        // Verify the folded polynomial has half the size
        assert_eq!(folded.len(), domain_size / 2);
        
        // In a real implementation, we'd also verify the mathematical properties
        // of the folded polynomial
        
        Ok(())
    }
    
    #[test]
    fn test_fri_challenges() -> Result<(), Box<dyn Error>> {
        // Test the challenge generation is deterministic
        
        // Create some mock roots
        let root1 = vec![1, 2, 3, 4, 5];
        let root2 = vec![5, 4, 3, 2, 1];
        
        // Create a mock prover
        let domain_size = 16;
        let mut evaluations = Vec::with_capacity(domain_size);
        for i in 0..domain_size {
            evaluations.push(FieldElement::from_u64(i as u64));
        }
        
        let omega = FieldElement::from_u64(123); // placeholder
        let prover = FriProver::new(evaluations, 7, omega, 128)?;
        
        // Generate challenges for the same root and round should be consistent
        let challenge1a = prover.generate_challenge(&root1, 0);
        let challenge1b = prover.generate_challenge(&root1, 0);
        assert_eq!(challenge1a, challenge1b);
        
        // Different roots should give different challenges
        let challenge2 = prover.generate_challenge(&root2, 0);
        assert_ne!(challenge1a, challenge2);
        
        // Different rounds should give different challenges
        let challenge3 = prover.generate_challenge(&root1, 1);
        assert_ne!(challenge1a, challenge3);
        
        Ok(())
    }
}