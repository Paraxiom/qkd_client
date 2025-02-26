// src/quantum_auth/pq/sphincs.rs
use serde::{Deserialize, Serialize};
use std::error::Error;
use tracing::{debug, info};

// Import from the real pqcrypto crates
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

// Import the specific SPHINCS+ module - this is the correct module name we found
use pqcrypto_sphincsplus::sphincssha2128fsimple;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SphincsVariant {
    Sha2128f,  // SHA-256, 128-bit security, fast
    Sha2128s,  // SHA-256, 128-bit security, small
    Shake128f, // SHAKE-256, 128-bit security, fast
    Shake128s, // SHAKE-256, 128-bit security, small
}

impl SphincsVariant {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha2128f => "SPHINCS+-SHA2-128f-simple",
            Self::Sha2128s => "SPHINCS+-SHA2-128s-simple",
            Self::Shake128f => "SPHINCS+-SHAKE-128f-simple",
            Self::Shake128s => "SPHINCS+-SHAKE-128s-simple",
        }
    }
}

// SPHINCS+ Keys with serialization support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphincsPublicKey {
    pub key_bytes: Vec<u8>,
    pub variant: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphincsPrivateKey {
    pub key_bytes: Vec<u8>,
    pub variant: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphincsSignature {
    pub sig_bytes: Vec<u8>,
    pub variant: String,
}

pub struct SphincsAuth {
    public_key: sphincssha2128fsimple::PublicKey,
    private_key: sphincssha2128fsimple::SecretKey,
    variant: SphincsVariant,
}

// Custom error type for SPHINCS+ operations
#[derive(Debug)]
pub enum SphincsError {
    InvalidKeySize(usize, usize),
    InvalidSignatureSize(usize, usize),
    SignatureVerificationFailed,
    KeyGenerationFailed,
    SerializationError(String),
    ExternalLibraryError(String),
}

impl std::fmt::Display for SphincsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeySize(actual, expected) => {
                write!(f, "Invalid key size: expected {}, got {}", expected, actual)
            }
            Self::InvalidSignatureSize(actual, expected) => write!(
                f,
                "Invalid signature size: expected {}, got {}",
                expected, actual
            ),
            Self::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            Self::KeyGenerationFailed => write!(f, "Key generation failed"),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
            Self::ExternalLibraryError(e) => write!(f, "External library error: {}", e),
        }
    }
}

impl std::error::Error for SphincsError {}

impl SphincsAuth {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        debug!("Initializing SPHINCS+ authentication with real implementation");

        // Default to SHA2-128f variant
        let variant = SphincsVariant::Sha2128f;
        info!("Using {} variant", variant.name());

        // Generate keypair using the real pqcrypto-sphincsplus
        debug!("Generating SPHINCS+ keypair - this may take a moment...");
        let start = std::time::Instant::now();

        let (pk, sk) = sphincssha2128fsimple::keypair();

        debug!("SPHINCS+ keypair generated in {:?}", start.elapsed());
        debug!("  Public key size: {} bytes", pk.as_bytes().len());
        debug!("  Secret key size: {} bytes", sk.as_bytes().len());

        Ok(Self {
            public_key: pk,
            private_key: sk,
            variant,
        })
    }

    pub fn with_variant(variant: SphincsVariant) -> Result<Self, Box<dyn Error>> {
        debug!(
            "Initializing SPHINCS+ authentication with variant {}",
            variant.name()
        );

        // For now, we only support SHA2-128f with the real implementation
        if variant != SphincsVariant::Sha2128f {
            debug!(
                "Requested variant {} not available, using {} instead",
                variant.name(),
                SphincsVariant::Sha2128f.name()
            );
        }

        // Generate keypair using pqcrypto - only one implementation is currently used
        let (pk, sk) = sphincssha2128fsimple::keypair();

        Ok(Self {
            public_key: pk,
            private_key: sk,
            variant: SphincsVariant::Sha2128f, // Override with the variant we're actually using
        })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        debug!(
            "Signing with SPHINCS+ ({}) - message size: {}B",
            self.variant.name(),
            message.len()
        );

        // Sign the message using the real SPHINCS+ implementation
        let start = std::time::Instant::now();
        let signature = sphincssha2128fsimple::detached_sign(message, &self.private_key);
        let sign_time = start.elapsed();

        // Create our signature wrapper with variant info
        let sphincs_sig = SphincsSignature {
            sig_bytes: signature.as_bytes().to_vec(),
            variant: self.variant.name().to_string(),
        };

        // Serialize the signature for transmission
        let serialized = bincode::serialize(&sphincs_sig)
            .map_err(|e| SphincsError::SerializationError(e.to_string()))?;

        debug!(
            "Generated SPHINCS+ signature: {}B in {:?}",
            serialized.len(),
            sign_time
        );
        Ok(serialized)
    }

    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<bool, Box<dyn Error>> {
        debug!(
            "Verifying SPHINCS+ signature - message size: {}B, signature size: {}B",
            message.len(),
            signature_bytes.len()
        );

        // Deserialize the signature structure
        let signature: SphincsSignature = match bincode::deserialize(signature_bytes) {
            Ok(sig) => sig,
            Err(e) => {
                debug!("Failed to deserialize signature: {}", e);
                return Err(Box::new(SphincsError::SerializationError(e.to_string())));
            }
        };

        // Check if signature variant matches our variant
        if signature.variant != self.variant.name() {
            debug!(
                "Signature variant mismatch: expected {}, got {}",
                self.variant.name(),
                signature.variant
            );
            return Ok(false);
        }

        // Convert bytes to DetachedSignature using the appropriate module
        let detached_signature =
            match sphincssha2128fsimple::DetachedSignature::from_bytes(&signature.sig_bytes) {
                Ok(sig) => sig,
                Err(e) => {
                    debug!("Invalid signature format: {}", e);
                    return Ok(false);
                }
            };

        // Verify the signature using the real SPHINCS+ implementation
        let start = std::time::Instant::now();
        let result = match sphincssha2128fsimple::verify_detached_signature(
            &detached_signature,
            message,
            &self.public_key,
        ) {
            Ok(_) => {
                info!(
                    "✅ SPHINCS+ signature verified successfully in {:?}",
                    start.elapsed()
                );
                true
            }
            Err(e) => {
                debug!("❌ SPHINCS+ signature verification failed: {}", e);
                false
            }
        };

        Ok(result)
    }

    // Get public key bytes
    pub fn get_public_key(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    // Serialize public key for storage or transmission
    pub fn serialize_public_key(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let pk = SphincsPublicKey {
            key_bytes: self.public_key.as_bytes().to_vec(),
            variant: self.variant.name().to_string(),
        };

        Ok(bincode::serialize(&pk)?)
    }

    // Deserialize public key from storage or transmission
    pub fn deserialize_public_key(data: &[u8]) -> Result<SphincsPublicKey, Box<dyn Error>> {
        Ok(bincode::deserialize(data)?)
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincs_sign_verify() -> Result<(), Box<dyn Error>> {
        // Create a new SPHINCS+ instance
        let sphincs = SphincsAuth::new()?;

        // Test message
        let message = b"This is a test message";

        // Sign the message
        let signature = sphincs.sign(message)?;

        // Verify the signature
        let valid = sphincs.verify(message, &signature)?;
        assert!(valid, "Signature verification failed");

        // Verify with incorrect message
        let wrong_message = b"This is a wrong message";
        let valid = sphincs.verify(wrong_message, &signature)?;
        assert!(!valid, "Signature should not verify with wrong message");

        Ok(())
    }

    #[test]
    fn test_key_serialization() -> Result<(), Box<dyn Error>> {
        // Create a new SPHINCS+ instance
        let sphincs = SphincsAuth::new()?;

        // Serialize the public key
        let serialized = sphincs.serialize_public_key()?;

        // Deserialize the public key
        let deserialized = SphincsAuth::deserialize_public_key(&serialized)?;

        // Verify they match
        assert_eq!(sphincs.get_public_key(), deserialized.key_bytes);
        assert_eq!(sphincs.variant.name(), deserialized.variant);

        Ok(())
    }
}
