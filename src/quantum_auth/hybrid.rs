// src/quantum_auth/hybrid.rs
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::Instant;
use tracing::{debug, info};

use crate::quantum_auth::pq::SphincsAuth;
use rand::rngs::OsRng;
use rand::RngCore;
use ring::signature::{self, Ed25519KeyPair, KeyPair};

/// A hybrid authentication system that combines classical Ed25519 signatures
/// with quantum-resistant SPHINCS+ signatures for maximum security during
/// the transition to post-quantum cryptography.

pub struct HybridAuth {
    classical_keypair: Ed25519KeyPair,
    quantum_auth: SphincsAuth,
}

#[derive(Debug, Clone)]
pub struct HybridProof {
    pub classical: Vec<u8>, // ✅ Just a field definition
    pub quantum: Vec<u8>,
}

/// Signature container that holds both classical and quantum signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub classical: Vec<u8>,
    pub quantum: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug)]
pub enum HybridAuthError {
    ClassicalKeyGeneration,
    ClassicalSigning(String),
    ClassicalVerification(String),
    QuantumOperation(String),
    SerializationError(String),
}

impl std::fmt::Display for HybridAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClassicalKeyGeneration => write!(f, "Failed to generate classical keypair"),
            Self::ClassicalSigning(e) => write!(f, "Classical signing error: {}", e),
            Self::ClassicalVerification(e) => write!(f, "Classical verification error: {}", e),
            Self::QuantumOperation(e) => write!(f, "Quantum operation error: {}", e),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl std::error::Error for HybridAuthError {}

impl HybridAuth {
    /// Creates a new hybrid authentication system with freshly generated keys
    pub fn new() -> Result<Self, Box<dyn Error>> {
        // Generate classical Ed25519 keypair
        debug!("Generating classical Ed25519 keypair");
        let classical_keypair = Self::generate_ed25519_keypair()?;

        // Create quantum-resistant SPHINCS+ auth
        debug!("Initializing quantum-resistant SPHINCS+ auth");
        let quantum_auth = SphincsAuth::new()?;

        Ok(Self {
            classical_keypair,
            quantum_auth,
        })
    }

    /// Sign a message with both classical and quantum algorithms
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature, Box<dyn Error>> {
        let start = Instant::now();

        // Classical Ed25519 signature
        let classical_sig = self.classical_keypair.sign(message);
        let classical_time = start.elapsed();
        debug!(
            "Generated classical Ed25519 signature in {:?}",
            classical_time
        );

        // Quantum-resistant SPHINCS+ signature
        let quantum_start = Instant::now();
        let quantum_sig = self
            .quantum_auth
            .sign(message)
            .map_err(|e| HybridAuthError::QuantumOperation(e.to_string()))?;
        let quantum_time = quantum_start.elapsed();
        debug!("Generated quantum SPHINCS+ signature in {:?}", quantum_time);

        // Create combined signature with timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let signature = HybridSignature {
            classical: classical_sig.as_ref().to_vec(),
            quantum: quantum_sig,
            timestamp,
        };

        info!(
            "Hybrid signature generated - classical: {}B, quantum: {}B, total time: {:?}",
            signature.classical.len(),
            signature.quantum.len(),
            start.elapsed()
        );

        Ok(signature)
    }

    /// Verify a hybrid signature
    pub fn verify(
        &self,
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<bool, Box<dyn Error>> {
        let start = Instant::now();

        // Classical verification with Ed25519
        let classical_start = Instant::now();
        let classical_valid = self.verify_classical(message, &signature.classical)?;
        let classical_time = classical_start.elapsed();

        if !classical_valid {
            debug!(
                "Classical signature verification failed in {:?}",
                classical_time
            );
            return Ok(false);
        }
        debug!("Classical signature verified in {:?}", classical_time);

        // Quantum verification with SPHINCS+
        let quantum_start = Instant::now();
        let quantum_valid = self
            .quantum_auth
            .verify(message, &signature.quantum)
            .map_err(|e| HybridAuthError::QuantumOperation(e.to_string()))?;
        let quantum_time = quantum_start.elapsed();

        if !quantum_valid {
            debug!(
                "Quantum signature verification failed in {:?}",
                quantum_time
            );
            return Ok(false);
        }
        debug!("Quantum signature verified in {:?}", quantum_time);

        // Both must be valid
        info!(
            "Hybrid signature verified successfully in {:?}",
            start.elapsed()
        );
        Ok(true)
    }

    /// Get the classical public key
    pub fn get_classical_public_key(&self) -> &[u8] {
        self.classical_keypair.public_key().as_ref()
    }

    /// Get the quantum public key
    pub fn get_quantum_public_key(&self) -> &[u8] {
        self.quantum_auth.get_public_key()
    }

    /// Serialize signature for transport (e.g., in HTTP header)
    pub fn serialize_signature(signature: &HybridSignature) -> Result<String, Box<dyn Error>> {
        let serialized = bincode::serialize(signature)
            .map_err(|e| HybridAuthError::SerializationError(e.to_string()))?;
        Ok(base64::encode(&serialized))
    }

    /// Deserialize signature from transport format
    pub fn deserialize_signature(data: &str) -> Result<HybridSignature, Box<dyn Error>> {
        let bytes =
            base64::decode(data).map_err(|e| HybridAuthError::SerializationError(e.to_string()))?;

        bincode::deserialize(&bytes)
            .map_err(|e| HybridAuthError::SerializationError(e.to_string()))
            .map_err(|e| e.into())
    }
    pub fn authenticate(&self) -> Result<HybridProof, Box<dyn Error>> {
        debug!("Generating hybrid authentication proof...");

        let classical_proof = self.classical_keypair.sign(b"Hybrid Authentication");
        let classical_proof_bytes = classical_proof.as_ref().to_vec(); // ✅ Convert Signature to Vec<u8>

        let quantum_proof = self.quantum_auth.sign(&classical_proof_bytes)?;

        Ok(HybridProof {
            classical: classical_proof_bytes, // ✅ Now matches the struct field type
            quantum: quantum_proof,
        })
    }

    /// Generate Ed25519 keypair for classical signatures
    fn generate_ed25519_keypair() -> Result<Ed25519KeyPair, Box<dyn Error>> {
        // Generate random seed
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);

        // Create keypair from random seed
        let keypair = Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| HybridAuthError::ClassicalKeyGeneration)?;

        Ok(keypair)
    }

    /// Verify classical Ed25519 signature
    fn verify_classical(
        &self,
        message: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, Box<dyn Error>> {
        let public_key = self.classical_keypair.public_key();

        // Use the appropriate ring API for verification
        match signature::UnparsedPublicKey::new(&signature::ED25519, public_key.as_ref())
            .verify(message, signature_bytes)
        {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_sign_verify() -> Result<(), Box<dyn Error>> {
        // Create hybrid auth
        let auth = HybridAuth::new()?;

        // Test message
        let message = b"This is a test message for hybrid authentication";

        // Sign the message
        let signature = auth.sign(message)?;

        // Verify the signature
        let valid = auth.verify(message, &signature)?;
        assert!(valid, "Signature verification failed");

        // Verify with incorrect message
        let wrong_message = b"This is a wrong message";
        let valid = auth.verify(wrong_message, &signature)?;
        assert!(!valid, "Signature should not verify with wrong message");

        Ok(())
    }

    #[test]
    fn test_serialization() -> Result<(), Box<dyn Error>> {
        // Create hybrid auth
        let auth = HybridAuth::new()?;

        // Test message
        let message = b"Test message for serialization";

        // Sign the message
        let signature = auth.sign(message)?;

        // Serialize for transport
        let serialized = HybridAuth::serialize_signature(&signature)?;

        // Deserialize
        let deserialized = HybridAuth::deserialize_signature(&serialized)?;

        // Verify deserialized signature
        let valid = auth.verify(message, &deserialized)?;
        assert!(valid, "Deserialized signature verification failed");

        Ok(())
    }
}
