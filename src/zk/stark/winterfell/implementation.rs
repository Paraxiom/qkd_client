use crate::zk::stark::winterfell::config;
use crate::zk::stark::winterfell::qkd_bridge::QkdStarkBridge;
use crate::zk::stark::winterfell::vrf_air;
use crate::qkd::QkdClient;
use std::path::Path;
use thiserror::Error;
use tracing::{info, error};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};

/// Initialize the QKD-STARK bridge from configuration
pub fn init_from_config(config_path: &Path) -> Result<QkdStarkBridge, InitError> {
    use tracing::info;
    
    // Load configuration
    let config = config::QkdStarkConfig::from_file(config_path)
        .map_err(|e| InitError::ConfigError(e))?;
    
    // Initialize QKD client
    info!("Initializing QKD client with endpoint: {}", config.qkd_endpoint());
    let qkd_client = QkdClient::new(
        config.qkd_endpoint(),
        config.auth_token()
    ).map_err(|e| InitError::QkdClientInitFailed(e.to_string()))?;
    
    // Create VRF prover
    info!("Initializing VRF prover with security level: {} bits", 
          config.security.security_bits);
    let prover = config.build_prover();
    
    // Create and return the bridge
    let bridge = QkdStarkBridge::new(
        qkd_client,
        prover,
        config.max_proof_time(),
    );
    
    info!("QKD-STARK bridge initialized successfully");
    Ok(bridge)
}

/// Error type for initialization
#[derive(Debug, Error)]
pub enum InitError {
    #[error("Configuration error: {0}")]
    ConfigError(#[from] config::ConfigError),
    
    #[error("Failed to initialize QKD client: {0}")]
    QkdClientInitFailed(String),
}

/// Run a complete example of VRF generation with STARK proof
pub fn run_example() -> Result<(), ExampleError> {
    // Create example config
    let config_str = config::example_config();
    let config: config::QkdStarkConfig = toml::from_str(&config_str)
        .map_err(|e| ExampleError::ParseError(e.to_string()))?;
    
    // Create prover
    let prover = config.build_prover();
    
    // Example QKD key (in a real system, this would come from the QKD device)
    let key = [0x42u8; 32];
    
    // Example input
    let input = b"Example input for VRF";
    
    // Compute the VRF output
    let mut hmac = Hmac::<Sha256>::new_from_slice(&key)
        .map_err(|_| ExampleError::CryptoError("Failed to initialize HMAC".to_string()))?;
    hmac.update(input);
    let vrf_output = hmac.finalize().into_bytes().to_vec();
    
    // Create public inputs
    let pub_inputs = vrf_air::VrfPublicInputs::new(
        &Sha256::digest(input).as_slice(), 
        &vrf_output
    ).map_err(|e| ExampleError::InvalidInput(format!("{:?}", e)))?;
    
    // Generate proof
    info!("Generating STARK proof for VRF...");
    let proof = prover.build_proof(&key, input, &pub_inputs)
        .map_err(|e| ExampleError::ProofError(format!("{:?}", e)))?;
    
    // Verify proof
    info!("Verifying proof...");
    let result = prover.verify_proof(&proof, &pub_inputs)
        .map_err(|e| ExampleError::VerificationError(format!("{:?}", e)))?;
    
    if result {
        info!("Proof verified successfully!");
        Ok(())
    } else {
        error!("Proof verification failed!");
        Err(ExampleError::VerificationFailed)
    }
}

/// Error type for the example
#[derive(Debug, Error)]
pub enum ExampleError {
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Proof generation error: {0}")]
    ProofError(String),
    
    #[error("Verification error: {0}")]
    VerificationError(String),
    
    #[error("Verification failed")]
    VerificationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    #[ignore = "Requires actual QKD client"]
    fn test_end_to_end_flow() {
        // Create a temporary configuration file
        let config_str = config::example_config();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(config_str.as_bytes()).unwrap();
        
        // Initialize bridge from config
        let bridge_result = init_from_config(file.path());
        assert!(bridge_result.is_ok());
        
        // Use the bridge to generate a VRF output and proof
        let bridge = bridge_result.unwrap();
        let result = bridge.generate_vrf_with_proof("test-key", b"test input");
        assert!(result.is_ok());
        
        let (vrf_output, proof) = result.unwrap();
        
        // Verify the proof
        let verification = bridge.verify_vrf_proof(b"test input", &vrf_output, &proof);
        assert!(verification.is_ok());
        assert!(verification.unwrap());
    }
}