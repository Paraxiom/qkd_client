// src/qkd/key_manager.rs
use crate::qkd::etsi_api::{ETSIClient, QKDKey, KeyStatus, Side, DeviceType};
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn, error};
use std::time::{Duration, Instant, SystemTime};

/// Quantum Key usage tracking record
#[derive(Debug, Clone)]
pub struct KeyUsageRecord {
    pub key_id: String,
    pub used_at: SystemTime,
    pub used_by: String,
    pub purpose: String,
    pub key_size: usize,
    pub qber: f32,
}

/// Secure quantum key manager that ensures proper key usage and lifecycle
pub struct SecureKeyManager {
    etsi_client: ETSIClient,
    /// Map of key_id to keys marked as consumed but not yet deleted
    pending_deletion: Arc<Mutex<HashMap<String, Instant>>>,
    /// History of key usage for auditing
    usage_history: Arc<Mutex<Vec<KeyUsageRecord>>>,
    /// Maximum time a key can remain in the cache before being rotated
    max_key_age: Duration,
    /// Key history record retention period
    history_retention: Duration,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KeyUsagePurpose {
    Encryption,
    Authentication,
    Signing,
    VRF,
    ZeroKnowledgeProof,
    KeyEncapsulation,
    ByzantineConsensus,
    Other(String),
}

impl KeyUsagePurpose {
    fn as_str(&self) -> String {
        match self {
            Self::Encryption => "encryption".to_string(),
            Self::Authentication => "authentication".to_string(),
            Self::Signing => "signing".to_string(),
            Self::VRF => "verifiable_random_function".to_string(),
            Self::ZeroKnowledgeProof => "zero_knowledge_proof".to_string(),
            Self::KeyEncapsulation => "key_encapsulation".to_string(),
            Self::ByzantineConsensus => "byzantine_consensus".to_string(),
            Self::Other(purpose) => purpose.clone(),
        }
    }
}

#[derive(Debug)]
pub enum KeyManagerError {
    KeyNotAvailable,
    KeyAlreadyUsed(String),
    KeyExpired(String),
    EtsiClientError(Box<dyn Error + Send + Sync>),
    InternalError(String),
}

impl std::fmt::Display for KeyManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyNotAvailable => write!(f, "No suitable quantum key available"),
            Self::KeyAlreadyUsed(key_id) => write!(f, "Key {} has already been used", key_id),
            Self::KeyExpired(key_id) => write!(f, "Key {} has expired", key_id),
            Self::EtsiClientError(e) => write!(f, "ETSI client error: {}", e),
            Self::InternalError(msg) => write!(f, "Internal key manager error: {}", msg),
        }
    }
}

impl std::error::Error for KeyManagerError {}

impl SecureKeyManager {
    /// Create a new secure key manager for Alice (key generator)
    pub fn new_alice(device_type: DeviceType, cert_path: &Path) -> Result<Self, Box<dyn Error>> {
        let etsi_client = ETSIClient::new(device_type, Side::Alice, cert_path, None)?;
        
        Ok(Self {
            etsi_client,
            pending_deletion: Arc::new(Mutex::new(HashMap::new())),
            usage_history: Arc::new(Mutex::new(Vec::new())),
            max_key_age: Duration::from_secs(3600), // Default: 1 hour max age
            history_retention: Duration::from_secs(86400 * 30), // Default: 30 days retention
        })
    }
    
    /// Create a new secure key manager for Bob (key receiver)
    pub fn new_bob(device_type: DeviceType, cert_path: &Path) -> Result<Self, Box<dyn Error>> {
        let etsi_client = ETSIClient::new(device_type, Side::Bob, cert_path, None)?;
        
        Ok(Self {
            etsi_client,
            pending_deletion: Arc::new(Mutex::new(HashMap::new())),
            usage_history: Arc::new(Mutex::new(Vec::new())),
            max_key_age: Duration::from_secs(3600), // Default: 1 hour max age
            history_retention: Duration::from_secs(86400 * 30), // Default: 30 days retention
        })
    }

    /// Create a new secure key manager with custom settings
    pub fn with_settings(
        etsi_client: ETSIClient,
        max_key_age: Duration,
        history_retention: Duration,
    ) -> Self {
        Self {
            etsi_client,
            pending_deletion: Arc::new(Mutex::new(HashMap::new())),
            usage_history: Arc::new(Mutex::new(Vec::new())),
            max_key_age,
            history_retention,
        }
    }

    /// Get a quantum key for use - this marks the key as used for the specified purpose
    pub async fn get_key(
        &self,
        key_size: usize,
        dest_id: &str,
        purpose: KeyUsagePurpose,
        requester_id: &str,
    ) -> Result<QKDKey, KeyManagerError> {
        debug!(
            "Requesting quantum key of size {}B for {} by {}",
            key_size,
            purpose.as_str(),
            requester_id
        );

        // Request a key from the QKD device
        let key = match self.etsi_client.get_key_alice(key_size, dest_id, None).await {
            Ok(k) => k,
            Err(e) => {
                let err_str = e.to_string();
                return Err(KeyManagerError::InternalError(err_str));
            }
        };

        // Verify key status
        if key.metadata.status != KeyStatus::Available {
            return Err(KeyManagerError::KeyNotAvailable);
        }

        // Record key usage
        self.record_key_usage(&key.key_id, requester_id, &purpose.as_str(), key.metadata.key_size, key.metadata.qber).await;

        info!(
            "Allocated quantum key {} ({} bytes) to {} for {}",
            key.key_id,
            key.metadata.key_size,
            requester_id,
            purpose.as_str()
        );

        Ok(key)
    }

    /// Get a specific quantum key by ID - for verification purposes
    pub async fn get_key_by_id(
        &self,
        key_id: &str,
        purpose: KeyUsagePurpose,
        requester_id: &str,
    ) -> Result<QKDKey, KeyManagerError> {
        debug!(
            "Retrieving specific quantum key {} for {} by {}",
            key_id,
            purpose.as_str(),
            requester_id
        );

        // Check if this key has already been used
        if self.is_key_used(key_id).await {
            return Err(KeyManagerError::KeyAlreadyUsed(key_id.to_string()));
        }

        // Get the key from the QKD device
        let key = match self.etsi_client.get_key_bob(key_id).await {
            Ok(k) => k,
            Err(e) => {
                let err_str = e.to_string();
                return Err(KeyManagerError::InternalError(err_str));
            }
        };

        // Verify key status
        if key.metadata.status != KeyStatus::Available {
            return Err(KeyManagerError::KeyNotAvailable);
        }

        // Record key usage
        self.record_key_usage(&key.key_id, requester_id, &purpose.as_str(), key.metadata.key_size, key.metadata.qber).await;

        info!(
            "Retrieved quantum key {} ({} bytes) for {} by {}",
            key.key_id,
            key.metadata.key_size,
            purpose.as_str(),
            requester_id
        );

        Ok(key)
    }

    /// Mark a key as consumed and schedule it for deletion
    pub async fn consume_key(&self, key_id: &str) -> Result<(), KeyManagerError> {
        debug!("Marking key {} as consumed", key_id);

        // Add to pending deletion
        {
            let mut pending = self.pending_deletion.lock().await;
            pending.insert(key_id.to_string(), Instant::now());
        }

        // Instead of spawning a task, just try to delete immediately
        match self.etsi_client.delete_key(key_id).await {
            Ok(true) => {
                info!("Successfully deleted consumed key: {}", key_id);
                // Remove from pending deletion
                let mut pending = self.pending_deletion.lock().await;
                pending.remove(key_id);
            }
            Ok(false) => {
                warn!("Key {} not found for deletion - may already be deleted", key_id);
                // Remove from pending deletion anyway
                let mut pending = self.pending_deletion.lock().await;
                pending.remove(key_id);
            }
            Err(e) => {
                // Key remains in pending_deletion for retry later
                let err_str = e.to_string();
                warn!("Failed to delete key {}: {}", key_id, err_str);
            }
        }

        Ok(())
    }

    /// Check if a key has been used
    async fn is_key_used(&self, key_id: &str) -> bool {
        // Check pending deletion
        {
            let pending = self.pending_deletion.lock().await;
            if pending.contains_key(key_id) {
                return true;
            }
        }

        // Check usage history
        {
            let history = self.usage_history.lock().await;
            for record in history.iter() {
                if record.key_id == key_id {
                    return true;
                }
            }
        }

        false
    }

    /// Record key usage for auditing
    async fn record_key_usage(&self, key_id: &str, requester_id: &str, purpose: &str, key_size: usize, qber: f32) {
        let usage_record = KeyUsageRecord {
            key_id: key_id.to_string(),
            used_at: SystemTime::now(),
            used_by: requester_id.to_string(),
            purpose: purpose.to_string(),
            key_size,
            qber,
        };

        let mut history = self.usage_history.lock().await;
        history.push(usage_record);

        // Prune old records
        let now = SystemTime::now();
        history.retain(|record| {
            match now.duration_since(record.used_at) {
                Ok(duration) => duration < self.history_retention,
                Err(_) => true, // Keep records with clock issues
            }
        });
    }

    /// Maintenance task to clean up expired keys and retry failed deletions
    pub async fn run_maintenance(&self) -> Result<(), KeyManagerError> {
        debug!("Running key manager maintenance task");

        // Retry deleting keys that failed previously
        let pending_keys: Vec<String> = {
            let pending = self.pending_deletion.lock().await;
            pending.keys().cloned().collect()
        };
        
        for key_id in pending_keys {
            // Try to delete the key
            match self.etsi_client.delete_key(&key_id).await {
                Ok(true) => {
                    info!("Successfully deleted key on retry: {}", key_id);
                    let mut pending = self.pending_deletion.lock().await;
                    pending.remove(&key_id);
                }
                Ok(false) => {
                    warn!("Key {} not found for deletion on retry", key_id);
                    let mut pending = self.pending_deletion.lock().await;
                    pending.remove(&key_id);
                }
                Err(e) => {
                    let err_str = e.to_string();
                    warn!("Failed to delete key {} on retry: {}", key_id, err_str);
                    // We'll try again next time
                }
            }
        }

        // Clean up history records beyond retention period
        {
            let now = SystemTime::now();
            let mut history = self.usage_history.lock().await;
            let initial_len = history.len();
            
            history.retain(|record| {
                match now.duration_since(record.used_at) {
                    Ok(duration) => duration < self.history_retention,
                    Err(_) => true, // Keep records with clock issues
                }
            });
            
            let removed = initial_len - history.len();
            if removed > 0 {
                debug!("Cleaned up {} expired key usage records", removed);
            }
        }

        // Force clear the ETSIClient's cache to ensure it gets fresh keys
        self.etsi_client.clear_cache().await;

        Ok(())
    }

    /// Get available quantum key size
    pub async fn get_available_key_size(&self) -> Result<usize, KeyManagerError> {
        match self.etsi_client.get_available_key_size().await {
            Ok(size) => Ok(size),
            Err(e) => {
                let err_str = e.to_string();
                Err(KeyManagerError::InternalError(err_str))
            }
        }
    }

    /// Get key usage statistics
    pub async fn get_usage_statistics(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        
        let history = self.usage_history.lock().await;
        for record in history.iter() {
            *stats.entry(record.purpose.clone()).or_insert(0) += 1;
        }
        
        stats
    }

    /// Get average QBER for keys used
    pub async fn get_average_qber(&self) -> f32 {
        let history = self.usage_history.lock().await;
        
        if history.is_empty() {
            return 0.0;
        }
        
        let total_qber: f32 = history.iter().map(|r| r.qber).sum();
        total_qber / history.len() as f32
    }

    /// Run maintenance once
    pub async fn perform_maintenance(&self) {
        match self.run_maintenance().await {
            Ok(_) => debug!("Key manager maintenance completed successfully"),
            Err(e) => error!("Key manager maintenance error: {}", e),
        }
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_key_manager_basics() -> Result<(), Box<dyn Error>> {
        // Create key manager with simulated device
        let key_manager = SecureKeyManager::new_alice(
            DeviceType::Simulated,
            &PathBuf::from("certificate/default_cert.pem"),
        )?;
        
        // Get a key for encryption
        let key = key_manager.get_key(
            32, 
            "test-destination", 
            KeyUsagePurpose::Encryption,
            "test-requester"
        ).await?;
        
        // Verify key has correct size
        assert_eq!(key.metadata.key_size, 32);
        
        // Mark key as consumed
        key_manager.consume_key(&key.key_id).await?;
        
        // Get usage statistics
        let stats = key_manager.get_usage_statistics().await;
        assert_eq!(stats.get("encryption"), Some(&1));
        
        Ok(())
    }
}