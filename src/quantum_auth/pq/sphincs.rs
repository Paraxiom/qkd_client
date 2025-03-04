// src/quantum_auth/pq/sphincs.rs
use serde::{Deserialize, Serialize};
use std::error::Error;
use tracing::{debug, info, warn};

// Import from the real pqcrypto crates
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

// Import all available SPHINCS+ variants for different security levels
use pqcrypto_sphincsplus::sphincssha2128fsimple;  // 128-bit, fast, small signatures
use pqcrypto_sphincsplus::sphincssha2128ssimple;  // 128-bit, small, larger signatures 
use pqcrypto_sphincsplus::sphincssha2192fsimple;  // 192-bit, fast
use pqcrypto_sphincsplus::sphincssha2192ssimple;  // 192-bit, small
use pqcrypto_sphincsplus::sphincssha2256fsimple;  // 256-bit, fast
use pqcrypto_sphincsplus::sphincssha2256ssimple;  // 256-bit, small

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SphincsVariant {
    Sha2128f,  // SHA-256, 128-bit security, fast
    Sha2128s,  // SHA-256, 128-bit security, small
    Sha2192f,  // SHA-256, 192-bit security, fast
    Sha2192s,  // SHA-256, 192-bit security, small
    Sha2256f,  // SHA-256, 256-bit security, fast (high security, recommended)
    Sha2256s,  // SHA-256, 256-bit security, small
}

impl SphincsVariant {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha2128f => "SPHINCS+-SHA2-128f-simple",
            Self::Sha2128s => "SPHINCS+-SHA2-128s-simple",
            Self::Sha2192f => "SPHINCS+-SHA2-192f-simple",
            Self::Sha2192s => "SPHINCS+-SHA2-192s-simple",
            Self::Sha2256f => "SPHINCS+-SHA2-256f-simple",
            Self::Sha2256s => "SPHINCS+-SHA2-256s-simple",
        }
    }
    
    pub fn security_bits(&self) -> usize {
        match self {
            Self::Sha2128f | Self::Sha2128s => 128,
            Self::Sha2192f | Self::Sha2192s => 192,
            Self::Sha2256f | Self::Sha2256s => 256,
        }
    }
    
    pub fn is_fast(&self) -> bool {
        match self {
            Self::Sha2128f | Self::Sha2192f | Self::Sha2256f => true,
            _ => false,
        }
    }
}

// SPHINCS+ Keys with serialization support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphincsPublicKey {
    pub key_bytes: Vec<u8>,
    pub variant: String,
    pub security_bits: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphincsPrivateKey {
    pub key_bytes: Vec<u8>,
    pub variant: String,
    pub security_bits: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphincsSignature {
    pub sig_bytes: Vec<u8>,
    pub variant: String,
    pub security_bits: usize,
}

// Trait to unify operations across different SPHINCS+ variants
trait SphincsVariantOps {
    fn keypair() -> (Vec<u8>, Vec<u8>);
    fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
    fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), Box<dyn Error>>;
}

// Implementation helpers for each variant
struct Sphincs128f;
struct Sphincs128s;
struct Sphincs192f;
struct Sphincs192s;
struct Sphincs256f;
struct Sphincs256s;

impl SphincsVariantOps for Sphincs128f {
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = sphincssha2128fsimple::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }
    
    fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let sk = sphincssha2128fsimple::SecretKey::from_bytes(secret_key)
            .map_err(|e| format!("Invalid secret key: {}", e))?;
        let signature = sphincssha2128fsimple::detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }
    
    fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), Box<dyn Error>> {
        let pk = sphincssha2128fsimple::PublicKey::from_bytes(public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        let sig = sphincssha2128fsimple::DetachedSignature::from_bytes(signature)
            .map_err(|e| format!("Invalid signature: {}", e))?;
        sphincssha2128fsimple::verify_detached_signature(&sig, message, &pk)
            .map_err(|e| format!("Signature verification failed: {}", e).into())
    }
}

impl SphincsVariantOps for Sphincs128s {
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = sphincssha2128ssimple::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }
    
    fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let sk = sphincssha2128ssimple::SecretKey::from_bytes(secret_key)
            .map_err(|e| format!("Invalid secret key: {}", e))?;
        let signature = sphincssha2128ssimple::detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }
    
    fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), Box<dyn Error>> {
        let pk = sphincssha2128ssimple::PublicKey::from_bytes(public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        let sig = sphincssha2128ssimple::DetachedSignature::from_bytes(signature)
            .map_err(|e| format!("Invalid signature: {}", e))?;
        sphincssha2128ssimple::verify_detached_signature(&sig, message, &pk)
            .map_err(|e| format!("Signature verification failed: {}", e).into())
    }
}

impl SphincsVariantOps for Sphincs192f {
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = sphincssha2192fsimple::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }
    
    fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let sk = sphincssha2192fsimple::SecretKey::from_bytes(secret_key)
            .map_err(|e| format!("Invalid secret key: {}", e))?;
        let signature = sphincssha2192fsimple::detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }
    
    fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), Box<dyn Error>> {
        let pk = sphincssha2192fsimple::PublicKey::from_bytes(public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        let sig = sphincssha2192fsimple::DetachedSignature::from_bytes(signature)
            .map_err(|e| format!("Invalid signature: {}", e))?;
        sphincssha2192fsimple::verify_detached_signature(&sig, message, &pk)
            .map_err(|e| format!("Signature verification failed: {}", e).into())
    }
}

impl SphincsVariantOps for Sphincs192s {
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = sphincssha2192ssimple::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }
    
    fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let sk = sphincssha2192ssimple::SecretKey::from_bytes(secret_key)
            .map_err(|e| format!("Invalid secret key: {}", e))?;
        let signature = sphincssha2192ssimple::detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }
    
    fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), Box<dyn Error>> {
        let pk = sphincssha2192ssimple::PublicKey::from_bytes(public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        let sig = sphincssha2192ssimple::DetachedSignature::from_bytes(signature)
            .map_err(|e| format!("Invalid signature: {}", e))?;
        sphincssha2192ssimple::verify_detached_signature(&sig, message, &pk)
            .map_err(|e| format!("Signature verification failed: {}", e).into())
    }
}

impl SphincsVariantOps for Sphincs256f {
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = sphincssha2256fsimple::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }
    
    fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let sk = sphincssha2256fsimple::SecretKey::from_bytes(secret_key)
            .map_err(|e| format!("Invalid secret key: {}", e))?;
        let signature = sphincssha2256fsimple::detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }
    
    fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), Box<dyn Error>> {
        let pk = sphincssha2256fsimple::PublicKey::from_bytes(public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        let sig = sphincssha2256fsimple::DetachedSignature::from_bytes(signature)
            .map_err(|e| format!("Invalid signature: {}", e))?;
        sphincssha2256fsimple::verify_detached_signature(&sig, message, &pk)
            .map_err(|e| format!("Signature verification failed: {}", e).into())
    }
}

impl SphincsVariantOps for Sphincs256s {
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = sphincssha2256ssimple::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }
    
    fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let sk = sphincssha2256ssimple::SecretKey::from_bytes(secret_key)
            .map_err(|e| format!("Invalid secret key: {}", e))?;
        let signature = sphincssha2256ssimple::detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }
    
    fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), Box<dyn Error>> {
        let pk = sphincssha2256ssimple::PublicKey::from_bytes(public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        let sig = sphincssha2256ssimple::DetachedSignature::from_bytes(signature)
            .map_err(|e| format!("Invalid signature: {}", e))?;
        sphincssha2256ssimple::verify_detached_signature(&sig, message, &pk)
            .map_err(|e| format!("Signature verification failed: {}", e).into())
    }
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
    UnsupportedVariant(String),
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
            Self::UnsupportedVariant(v) => write!(f, "Unsupported SPHINCS+ variant: {}", v),
        }
    }
}

impl std::error::Error for SphincsError {}

/// Main SPHINCS+ authentication class with enhanced security options
pub struct SphincsAuth {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    variant: SphincsVariant,
}

impl SphincsAuth {
    /// Create a new SPHINCS+ authentication instance with default parameters
    /// Default is now 256-bit security (highest) with fast parameter set
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Self::with_variant(SphincsVariant::Sha2256f)
    }
    
    /// Create a new SPHINCS+ authentication instance with specified variant
    pub fn with_variant(variant: SphincsVariant) -> Result<Self, Box<dyn Error>> {
        debug!(
            "Initializing SPHINCS+ authentication with variant {} ({})",
            variant.name(),
            format!("{}-bit security", variant.security_bits())
        );
        
        info!(
            "Using SPHINCS+ {} variant with {}-bit security {}",
            if variant.is_fast() { "fast" } else { "small" },
            variant.security_bits(),
            if variant.security_bits() >= 256 {
                "(high security, recommended for long-term protection)"
            } else if variant.security_bits() >= 192 {
                "(medium-high security)"
            } else {
                "(standard security)"
            }
        );
        
        // Generate keypair for the requested variant
        let start = std::time::Instant::now();
        
        let (pk, sk) = match variant {
            SphincsVariant::Sha2128f => Sphincs128f::keypair(),
            SphincsVariant::Sha2128s => Sphincs128s::keypair(),
            SphincsVariant::Sha2192f => Sphincs192f::keypair(),
            SphincsVariant::Sha2192s => Sphincs192s::keypair(),
            SphincsVariant::Sha2256f => Sphincs256f::keypair(),
            SphincsVariant::Sha2256s => Sphincs256s::keypair(),
        };
        
        debug!("SPHINCS+ keypair generated in {:?}", start.elapsed());
        debug!("  Public key size: {} bytes", pk.len());
        debug!("  Secret key size: {} bytes", sk.len());
        
        Ok(Self {
            public_key: pk,
            private_key: sk,
            variant,
        })
    }
    
    /// Sign a message using SPHINCS+
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        debug!(
            "Signing with SPHINCS+ ({}) - message size: {}B",
            self.variant.name(),
            message.len()
        );
        
        // Sign the message using the appropriate variant
        let start = std::time::Instant::now();
        
        let signature_bytes = match self.variant {
            SphincsVariant::Sha2128f => Sphincs128f::sign(message, &self.private_key)?,
            SphincsVariant::Sha2128s => Sphincs128s::sign(message, &self.private_key)?,
            SphincsVariant::Sha2192f => Sphincs192f::sign(message, &self.private_key)?,
            SphincsVariant::Sha2192s => Sphincs192s::sign(message, &self.private_key)?,
            SphincsVariant::Sha2256f => Sphincs256f::sign(message, &self.private_key)?,
            SphincsVariant::Sha2256s => Sphincs256s::sign(message, &self.private_key)?,
        };
        
        let sign_time = start.elapsed();
        
        // Create our signature wrapper with variant info
        let sphincs_sig = SphincsSignature {
            sig_bytes: signature_bytes,
            variant: self.variant.name().to_string(),
            security_bits: self.variant.security_bits(),
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
    
    /// Verify a message signature using SPHINCS+
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
            // Optionally, we could support cross-variant verification
            // But for now, we require matching variants
            return Ok(false);
        }
        
        // Verify the signature using the appropriate variant
        let start = std::time::Instant::now();
        
        let result = match self.variant {
            SphincsVariant::Sha2128f => {
                match Sphincs128f::verify(message, &signature.sig_bytes, &self.public_key) {
                    Ok(_) => true,
                    Err(e) => {
                        debug!("Signature verification failed: {}", e);
                        false
                    }
                }
            },
            SphincsVariant::Sha2128s => {
                match Sphincs128s::verify(message, &signature.sig_bytes, &self.public_key) {
                    Ok(_) => true,
                    Err(e) => {
                        debug!("Signature verification failed: {}", e);
                        false
                    }
                }
            },
            SphincsVariant::Sha2192f => {
                match Sphincs192f::verify(message, &signature.sig_bytes, &self.public_key) {
                    Ok(_) => true,
                    Err(e) => {
                        debug!("Signature verification failed: {}", e);
                        false
                    }
                }
            },
            SphincsVariant::Sha2192s => {
                match Sphincs192s::verify(message, &signature.sig_bytes, &self.public_key) {
                    Ok(_) => true,
                    Err(e) => {
                        debug!("Signature verification failed: {}", e);
                        false
                    }
                }
            },
            SphincsVariant::Sha2256f => {
                match Sphincs256f::verify(message, &signature.sig_bytes, &self.public_key) {
                    Ok(_) => true,
                    Err(e) => {
                        debug!("Signature verification failed: {}", e);
                        false
                    }
                }
            },
            SphincsVariant::Sha2256s => {
                match Sphincs256s::verify(message, &signature.sig_bytes, &self.public_key) {
                    Ok(_) => true,
                    Err(e) => {
                        debug!("Signature verification failed: {}", e);
                        false
                    }
                }
            },
        };
        
        let verify_time = start.elapsed();
        
        if result {
            info!("✅ SPHINCS+ signature verified successfully in {:?}", verify_time);
        } else {
            warn!("❌ SPHINCS+ signature verification failed in {:?}", verify_time);
        }
        
        Ok(result)
    }
    
    /// Get public key bytes
    pub fn get_public_key(&self) -> &[u8] {
        &self.public_key
    }
    
    /// Get private key bytes
    pub fn get_private_key(&self) -> &[u8] {
        &self.private_key
    }
    
    /// Get the variant used by this instance
    pub fn get_variant(&self) -> SphincsVariant {
        self.variant
    }
    
    /// Serialize public key for storage or transmission
    pub fn serialize_public_key(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let pk = SphincsPublicKey {
            key_bytes: self.public_key.clone(),
            variant: self.variant.name().to_string(),
            security_bits: self.variant.security_bits(),
        };
        
        Ok(bincode::serialize(&pk)?)
    }
    
    /// Deserialize public key from storage or transmission
    pub fn deserialize_public_key(data: &[u8]) -> Result<SphincsPublicKey, Box<dyn Error>> {
        Ok(bincode::deserialize(data)?)
    }
    
    /// Create a SphincsAuth instance from an existing public key
    pub fn from_public_key(public_key: &SphincsPublicKey) -> Result<Self, Box<dyn Error>> {
        let variant = match public_key.variant.as_str() {
            "SPHINCS+-SHA2-128f-simple" => SphincsVariant::Sha2128f,
            "SPHINCS+-SHA2-128s-simple" => SphincsVariant::Sha2128s,
            "SPHINCS+-SHA2-192f-simple" => SphincsVariant::Sha2192f,
            "SPHINCS+-SHA2-192s-simple" => SphincsVariant::Sha2192s,
            "SPHINCS+-SHA2-256f-simple" => SphincsVariant::Sha2256f,
            "SPHINCS+-SHA2-256s-simple" => SphincsVariant::Sha2256s,
            _ => return Err(Box::new(SphincsError::UnsupportedVariant(public_key.variant.clone()))),
        };
        
        Ok(Self {
            public_key: public_key.key_bytes.clone(),
            private_key: Vec::new(), // Empty private key for verification-only
            variant,
        })
    }
    
    /// Get the estimated signature size for the current variant
    pub fn get_estimated_signature_size(&self) -> usize {
        match self.variant {
            SphincsVariant::Sha2128f => 17_088,
            SphincsVariant::Sha2128s => 7_856,
            SphincsVariant::Sha2192f => 35_664,
            SphincsVariant::Sha2192s => 16_224,
            SphincsVariant::Sha2256f => 49_216,
            SphincsVariant::Sha2256s => 29_792,
        }
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sphincs_sign_verify() -> Result<(), Box<dyn Error>> {
        // Create a new SPHINCS+ instance with default 256-bit security
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
        assert_eq!(sphincs.variant.security_bits(), deserialized.security_bits);
        
        Ok(())
    }
    
    #[test]
    fn test_different_security_levels() -> Result<(), Box<dyn Error>> {
        // Test all variants
        let variants = [
            SphincsVariant::Sha2128f,
            SphincsVariant::Sha2128s,
            SphincsVariant::Sha2192f,
            SphincsVariant::Sha2192s,
            SphincsVariant::Sha2256f,
            SphincsVariant::Sha2256s,
        ];
        
        for variant in &variants {
            // Create an instance with this variant
            let sphincs = SphincsAuth::with_variant(*variant)?;
            
            // Test message
            let message = b"Testing different security levels";
            
            // Sign and verify
            let signature = sphincs.sign(message)?;
            let valid = sphincs.verify(message, &signature)?;
            
            assert!(valid, "Verification failed for variant: {}", variant.name());
            
            // Check signature size
            let sig: SphincsSignature = bincode::deserialize(&signature)?;
            debug!(
                "Variant: {}, Signature size: {}B",
                variant.name(),
                sig.sig_bytes.len()
            );
        }
        
        Ok(())
    }
}