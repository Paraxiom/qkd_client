use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs;
use std::time::Duration;
use winterfell::ProofOptions;
use winter_air::{FieldExtension, BatchingMethod};
use crate::zk::stark::winterfell::vrf_prover::{VrfProver, PerformanceMode};
use thiserror::Error;
use tracing::{info, warn, debug};
use winterfell::BatchingMethod;
/// Configuration for the QKD STARK Integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QkdStarkConfig {
    /// STARK proving parameters
    #[serde(default = "default_stark_params")]
    pub stark_params: StarkParams,
    
    /// QKD parameters
    pub qkd: QkdParams,
    
    /// Security parameters
    #[serde(default = "default_security_params")]
    pub security: SecurityParams,
    
    /// Performance tuning parameters
    #[serde(default = "default_performance_params")]
    pub performance: PerformanceParams,
}

/// STARK proof generation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkParams {
    /// Number of queries for the FRI protocol
    pub num_queries: usize,
    
    /// Blowup factor for the low-degree extension
    pub blowup_factor: usize,
    
    /// Grinding factor for zero-knowledge
    pub grinding_factor: u32,
    
    /// FRI protocol folding factor
    pub fri_folding_factor: usize,
    
    /// FRI protocol maximum remainder degree
    pub fri_max_remainder_size: usize,
    
    /// Enable debug mode for proofs
    #[serde(default)]
    pub debug_mode: bool,
}

/// QKD connection and key management parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QkdParams {
    /// QKD endpoint URL
    pub endpoint: String,
    
    /// Authentication token/key (if required)
    #[serde(default)]
    pub auth_token: Option<String>,
    
    /// Key rotation interval in seconds
    pub key_rotation_interval_secs: u64,
    
    /// Maximum attempts to retrieve a key
    #[serde(default = "default_max_key_retrieval_attempts")]
    pub max_key_retrieval_attempts: usize,
    
    /// Key size in bytes
    #[serde(default = "default_key_size")]
    pub key_size: usize,
}

/// Security parameters for the QKD STARK system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityParams {
    /// Minimum entropy required for keys (in bits)
    pub min_entropy: u32,
    
    /// Security level in bits (affects proof parameters)
    pub security_bits: usize,
    
    /// Whether to zeroize sensitive data (should be true in production)
    #[serde(default = "default_zeroize")]
    pub zeroize_sensitive_data: bool,
    
    /// Minimum key size in bytes
    pub min_key_size: usize,
}

/// Performance tuning parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceParams {
    /// Maximum time allowed for proof generation (milliseconds)
    pub max_proof_time_ms: u64,
    
    /// Performance mode
    #[serde(default)]
    pub mode: String,
    
    /// Max memory usage in MB
    #[serde(default = "default_max_memory")]
    pub max_memory_mb: usize,
    
    /// Number of threads to use (0 = automatic)
    #[serde(default)]
    pub num_threads: usize,
}

impl QkdStarkConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        debug!("Loading configuration from {:?}", path);
        
        // Read the file content
        let config_str = fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(format!("Failed to read config file: {}", e)))?;
            
        // Parse the TOML content
        let config: Self = toml::from_str(&config_str)
            .map_err(|e| ConfigError::ParseError(format!("Failed to parse config: {}", e)))?;
        
        // Validate the configuration
        config.validate()?;
        
        info!("Configuration loaded successfully");
        debug!("Configured security level: {} bits", config.security.security_bits);
        debug!("Configured QKD endpoint: {}", config.qkd.endpoint);
        
        Ok(config)
    }
    
    /// Validate the configuration parameters
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Check security parameters
        if self.security.min_entropy < MINIMUM_ALLOWED_ENTROPY {
            return Err(ConfigError::InsecureParameters(
                format!("min_entropy must be at least {}", MINIMUM_ALLOWED_ENTROPY)
            ));
        }
        
        if self.security.security_bits < MINIMUM_SECURITY_BITS {
            return Err(ConfigError::InsecureParameters(
                format!("security_bits must be at least {}", MINIMUM_SECURITY_BITS)
            ));
        }
        
        if self.security.min_key_size < MINIMUM_KEY_SIZE {
            return Err(ConfigError::InsecureParameters(
                format!("min_key_size must be at least {} bytes", MINIMUM_KEY_SIZE)
            ));
        }
        
        // Check STARK parameters
        if self.stark_params.num_queries < 16 {
            return Err(ConfigError::InvalidParameters(
                "num_queries must be at least 16".to_string()
            ));
        }
        
        if !self.stark_params.blowup_factor.is_power_of_two() {
            return Err(ConfigError::InvalidParameters(
                "blowup_factor must be a power of 2".to_string()
            ));
        }
        
        // Check that key rotation interval is reasonable
        if self.qkd.key_rotation_interval_secs < 60 {
            warn!("Key rotation interval is very short: {} seconds", 
                  self.qkd.key_rotation_interval_secs);
        }
        
        Ok(())
    }
    
    /// Create a VRF prover from the configuration
    pub fn build_prover(&self) -> VrfProver {
        let options = ProofOptions::new(
            self.stark_params.num_queries,
            self.stark_params.blowup_factor,
            self.stark_params.grinding_factor,
            FieldExtension::None,  // Field extension parameter
            self.stark_params.fri_max_remainder_size,
            self.stark_params.fri_folding_factor,
            BatchingMethod::Linear,  // First batching method - use actual enum variant
            BatchingMethod::Linear   // Second batching method - use actual enum variant
        );
        
        let mut prover = VrfProver::new(options);
        
        // Optimize based on security level and performance mode
        let mode = match self.performance.mode.to_lowercase().as_str() {
            "fast" => PerformanceMode::Fast,
            "security" | "maxsecurity" => PerformanceMode::MaxSecurity,
            _ => PerformanceMode::Balanced,
        };
        
        prover.optimize_options(self.security.security_bits, mode);
        
        prover
    }
    
    /// Get the key rotation interval
    pub fn key_rotation_interval(&self) -> Duration {
        Duration::from_secs(self.qkd.key_rotation_interval_secs)
    }
    
    /// Get the maximum proof generation time
    pub fn max_proof_time(&self) -> Duration {
        Duration::from_millis(self.performance.max_proof_time_ms)
    }
    
    /// Get the QKD endpoint URL
    pub fn qkd_endpoint(&self) -> &str {
        &self.qkd.endpoint
    }
    
    /// Get the authentication token if available
    pub fn auth_token(&self) -> Option<&str> {
        self.qkd.auth_token.as_deref()
    }
    
    /// Get the maximum number of key retrieval attempts
    pub fn max_key_retrieval_attempts(&self) -> usize {
        self.qkd.max_key_retrieval_attempts
    }
    
    /// Check if sensitive data should be zeroized
    pub fn zeroize_sensitive_data(&self) -> bool {
        self.security.zeroize_sensitive_data
    }
}

// Default values for configuration

fn default_stark_params() -> StarkParams {
    StarkParams {
        num_queries: 40,
        blowup_factor: 8,
        grinding_factor: 16,
        fri_folding_factor: 4,
        fri_max_remainder_size: 31,
        debug_mode: false,
    }
}

fn default_security_params() -> SecurityParams {
    SecurityParams {
        min_entropy: 256,
        security_bits: 128,
        zeroize_sensitive_data: true,
        min_key_size: 32,
    }
}

fn default_performance_params() -> PerformanceParams {
    PerformanceParams {
        max_proof_time_ms: 10000, // 10 seconds
        mode: "balanced".to_string(),
        max_memory_mb: 1024,
        num_threads: 0,
    }
}

fn default_max_key_retrieval_attempts() -> usize {
    3
}

fn default_key_size() -> usize {
    32
}

fn default_max_memory() -> usize {
    1024 // 1 GB
}

fn default_zeroize() -> bool {
    true
}

// Constants
const MINIMUM_ALLOWED_ENTROPY: u32 = 256;
const MINIMUM_SECURITY_BITS: usize = 80;
const MINIMUM_KEY_SIZE: usize = 32;

/// Error type for QKD STARK configuration
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    IoError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Insecure parameters: {0}")]
    InsecureParameters(String),
    
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
}

/// Example of a valid configuration file
pub fn example_config() -> String {
    r#"# QKD STARK Integration Configuration

# STARK proving parameters
[stark_params]
num_queries = 40
blowup_factor = 8
grinding_factor = 16
fri_folding_factor = 4
fri_max_remainder_size = 31
debug_mode = false

# QKD connection parameters
[qkd]
endpoint = "https://qkd-server.example.com/api/v1"
auth_token = "YOUR_AUTH_TOKEN"
key_rotation_interval_secs = 3600 # 1 hour
max_key_retrieval_attempts = 3
key_size = 32 # bytes

# Security parameters
[security]
min_entropy = 256 # bits
security_bits = 128 # overall security level
zeroize_sensitive_data = true
min_key_size = 32 # bytes

# Performance parameters
[performance]
max_proof_time_ms = 10000 # 10 seconds
mode = "balanced" # "fast", "balanced", or "maxsecurity"
max_memory_mb = 1024 # 1 GB
num_threads = 0 # 0 = automatic
"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;
    
    #[test]
    fn test_parse_valid_config() {
        let config_str = example_config();
        let config: QkdStarkConfig = toml::from_str(&config_str).unwrap();
        
        assert_eq!(config.qkd.endpoint, "https://qkd-server.example.com/api/v1");
        assert_eq!(config.stark_params.num_queries, 40);
        assert_eq!(config.security.security_bits, 128);
    }
    
    #[test]
    fn test_validation() {
        // Create config with invalid parameters
        let mut config = QkdStarkConfig {
            stark_params: default_stark_params(),
            qkd: QkdParams {
                endpoint: "https://example.com".to_string(),
                auth_token: None,
                key_rotation_interval_secs: 3600,
                max_key_retrieval_attempts: 3,
                key_size: 32,
            },
            security: SecurityParams {
                min_entropy: 64, // Too low - should fail validation
                security_bits: 128,
                zeroize_sensitive_data: true,
                min_key_size: 32,
            },
            performance: default_performance_params(),
        };
        
        // Validation should fail due to low min_entropy
        assert!(config.validate().is_err());
        
        // Fix the min_entropy and make the blowup_factor invalid
        config.security.min_entropy = 256;
        config.stark_params.blowup_factor = 6; // Not a power of 2
        
        // Validation should fail due to invalid blowup_factor
        assert!(config.validate().is_err());
        
        // Fix all parameters
        config.stark_params.blowup_factor = 8;
        
        // Validation should succeed
        assert!(config.validate().is_ok());
    }
}