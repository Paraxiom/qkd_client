// src/qkd/key_manager.rs
use crate::qkd::etsi_api::{DeviceType, ETSIClient, QKDKey, KeyStatus, Side};
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Key usage purpose enum
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum KeyUsagePurpose {
    /// Key used for encryption
    Encryption,
    /// Key used for authentication
    Authentication,
    /// Key used for VRF (Verifiable Random Function)
    VRF,
}

impl std::fmt::Display for KeyUsagePurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyUsagePurpose::Encryption => write!(f, "encryption"),
            KeyUsagePurpose::Authentication => write!(f, "authentication"),
            KeyUsagePurpose::VRF => write!(f, "verifiable_random_function"),
        }
    }
}

/// Secure Key Manager for QKD Keys
pub struct SecureKeyManager {
    // QKD client for retrieving keys
    client: ETSIClient,
    // Map of keys in use, keyed by key_id
    keys_in_use: Arc<Mutex<HashMap<String, (KeyUsagePurpose, String)>>>,
    // Usage statistics by purpose
    usage_stats: Arc<Mutex<HashMap<KeyUsagePurpose, usize>>>,
    // Last access time by key_id
    last_access: Arc<Mutex<HashMap<String, SystemTime>>>,
    // Maximum key age before expiration
    max_key_age: Duration,
}

impl SecureKeyManager {
    /// Create a new key manager with the provided client
    pub fn new(client: ETSIClient) -> Self {
        Self {
            client,
            keys_in_use: Arc::new(Mutex::new(HashMap::new())),
            usage_stats: Arc::new(Mutex::new(HashMap::new())),
            last_access: Arc::new(Mutex::new(HashMap::new())),
            max_key_age: Duration::from_secs(3600), // Default 1 hour max age
        }
    }

    /// Create a new key manager for Alice with the given device type and certificates
    pub fn new_alice(
        device_type: DeviceType,
        cert_path: &Path,
        root_cert_path: Option<&Path>,
    ) -> Result<Self, Box<dyn Error>> {
        let client = ETSIClient::new(
            device_type,
            Side::Alice,
            cert_path,
            root_cert_path,
            None,
        )?;
        
        Ok(Self::new(client))
    }

    /// Create a new key manager for Bob with the given device type and certificates
    pub fn new_bob(
        device_type: DeviceType,
        cert_path: &Path,
        root_cert_path: Option<&Path>,
    ) -> Result<Self, Box<dyn Error>> {
        let client = ETSIClient::new(
            device_type,
            Side::Bob,
            cert_path,
            root_cert_path,
            None,
        )?;
        
        Ok(Self::new(client))
    }

    /// Get a new key for Alice for the specified purpose
    ///
    /// # Arguments
    /// * `key_size` - Size of the requested key in bytes
    /// * `dest_id` - Destination ID (Bob's identifier)
    /// * `purpose` - Purpose of the key
    /// * `requester_id` - ID of the entity requesting the key
    pub async fn get_key(
        &self,
        key_size: usize,
        dest_id: &str,
        purpose: KeyUsagePurpose,
        requester_id: &str,
    ) -> Result<QKDKey, Box<dyn Error>> {
        // Get key from QKD device
        let key = self.client.get_key_alice(key_size, dest_id, None).await?;
        
        // Mark key as in use for this purpose
        {
            let mut keys_in_use = self.keys_in_use.lock().await;
            keys_in_use.insert(key.key_id.clone(), (purpose, requester_id.to_string()));
            
            // Update usage statistics
            let mut stats = self.usage_stats.lock().await;
            *stats.entry(purpose).or_insert(0) += 1;
            
            // Update last access time
            let mut last_access = self.last_access.lock().await;
            last_access.insert(key.key_id.clone(), SystemTime::now());
        }
        
        info!("Allocated quantum key {} ({} bytes) to {} for {}", 
            key.key_id, key.metadata.key_size, requester_id, purpose);
        
        Ok(key)
    }
    
    /// Get a specific key by ID for Bob
    ///
    /// # Arguments
    /// * `key_id` - ID of the key to retrieve
    /// * `purpose` - Purpose of the key
    /// * `requester_id` - ID of the entity requesting the key
    pub async fn get_key_by_id(
        &self,
        key_id: &str,
        purpose: KeyUsagePurpose,
        requester_id: &str,
    ) -> Result<QKDKey, Box<dyn Error>> {
        // Check if the key is already in use
        {
            let keys_in_use = self.keys_in_use.lock().await;
            if let Some((existing_purpose, existing_requester)) = keys_in_use.get(key_id) {
                if *existing_purpose == purpose && existing_requester == requester_id {
                    // Same purpose and requester, might be a retry - allow it
                    debug!("Key {} already in use by the same requester, allowing retry", key_id);
                } else {
                    // Key already in use for a different purpose or by a different requester
                    return Err(format!("Key {} has already been used", key_id).into());
                }
            }
        }
        
        // Get key from QKD device
        let key = self.client.get_key_bob(key_id).await?;
        
        // Mark key as in use for this purpose
        {
            let mut keys_in_use = self.keys_in_use.lock().await;
            keys_in_use.insert(key.key_id.clone(), (purpose, requester_id.to_string()));
            
            // Update usage statistics
            let mut stats = self.usage_stats.lock().await;
            *stats.entry(purpose).or_insert(0) += 1;
            
            // Update last access time
            let mut last_access = self.last_access.lock().await;
            last_access.insert(key.key_id.clone(), SystemTime::now());
        }
        
        info!("Retrieved quantum key {} ({} bytes) for {} by {}", 
            key.key_id, key.metadata.key_size, purpose, requester_id);
        
        Ok(key)
    }
    
    /// Mark a key as consumed (will prevent reuse)
    ///
    /// # Arguments
    /// * `key_id` - ID of the key to mark as consumed
    pub async fn consume_key(&self, key_id: &str) -> Result<(), Box<dyn Error>> {
        // Remove from in-use map
        {
            let mut keys_in_use = self.keys_in_use.lock().await;
            keys_in_use.remove(key_id);
        }
        
        // Delete from QKD device
        let result = self.client.delete_key(key_id).await?;
        
        if result {
            info!("Successfully deleted consumed key: {}", key_id);
        } else {
            warn!("Failed to delete consumed key: {}", key_id);
        }
        
        Ok(())
    }
    
    /// Get key usage statistics
    pub async fn get_usage_statistics(&self) -> HashMap<KeyUsagePurpose, usize> {
        let stats = self.usage_stats.lock().await;
        stats.clone()
    }
    
    /// Expire old keys based on max_key_age
    pub async fn expire_old_keys(&self) -> Result<usize, Box<dyn Error>> {
        let now = SystemTime::now();
        let mut expired_count = 0;
        
        // Find keys to expire
        let keys_to_expire = {
            let last_access = self.last_access.lock().await;
            let mut to_expire = Vec::new();
            
            for (key_id, access_time) in last_access.iter() {
                if let Ok(elapsed) = now.duration_since(*access_time) {
                    if elapsed > self.max_key_age {
                        to_expire.push(key_id.clone());
                    }
                }
            }
            
            to_expire
        };
        
        // Expire the keys
        for key_id in keys_to_expire {
            if let Ok(()) = self.consume_key(&key_id).await {
                expired_count += 1;
            }
        }
        
        debug!("Expired {} old keys", expired_count);
        Ok(expired_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    
    #[tokio::test]
    async fn test_key_allocation() -> Result<(), Box<dyn Error>> {
        // Create simulated client
        let client = ETSIClient::new(
            DeviceType::Simulated,
            Side::Alice,
            &PathBuf::from("nonexistent-cert.pem"),
            None,
            None,
        )?;
        
        let manager = SecureKeyManager::new(client);
        
        // Get a key
        let key = manager.get_key(32, "test-dest", KeyUsagePurpose::Encryption, "test").await?;
        
        // Verify it has the right size
        assert_eq!(key.metadata.key_size, 32);
        
        // Get usage stats
        let stats = manager.get_usage_statistics().await;
        assert_eq!(stats.get(&KeyUsagePurpose::Encryption), Some(&1));
        
        // Mark key as consumed
        manager.consume_key(&key.key_id).await?;
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_key_reuse_prevention() -> Result<(), Box<dyn Error>> {
        // Create simulated client
        let alice_client = ETSIClient::new(
            DeviceType::Simulated,
            Side::Alice,
            &PathBuf::from("nonexistent-cert.pem"),
            None,
            None,
        )?;
        
        let bob_client = ETSIClient::new(
            DeviceType::Simulated,
            Side::Bob,
            &PathBuf::from("nonexistent-cert.pem"),
            None,
            None,
        )?;
        
        let alice_manager = SecureKeyManager::new(alice_client);
        let bob_manager = SecureKeyManager::new(bob_client);
        
        // Alice gets a key
        let key = alice_manager.get_key(32, "test-dest", KeyUsagePurpose::Encryption, "test1").await?;
        
        // Bob retrieves the same key
        let bob_key = bob_manager.get_key_by_id(&key.key_id, KeyUsagePurpose::Encryption, "test2").await?;
        
        // Verify it's the same key
        assert_eq!(key.key_bytes, bob_key.key_bytes);
        
        // Try to reuse the key for a different purpose (should fail)
        let reuse_result = bob_manager.get_key_by_id(&key.key_id, KeyUsagePurpose::Authentication, "test3").await;
        assert!(reuse_result.is_err(), "Key reuse should be prevented");
        
        Ok(())
    }
}