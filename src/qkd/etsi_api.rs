// src/qkd/etsi_api.rs
use reqwest::{Certificate, Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// ETSI QKD API Implementation
/// Based on ETSI GS QKD 014 standard
/// This client provides access to QKD key management services

#[derive(Debug, Clone)]
pub enum Side {
    Alice,
    Bob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QKDKey {
    pub key_id: String,
    pub key_bytes: Vec<u8>,
    pub timestamp: u64,
    pub metadata: KeyMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub source: String, // "toshiba", "idq", etc.
    pub qber: f32,      // Quantum Bit Error Rate
    pub key_size: usize,
    pub status: KeyStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyStatus {
    Available,
    Pending,
    Consumed,
    Expired,
    Error(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyRequest {
    pub requested_key_size: usize,
    pub destination_id: String,
    pub sae_id: Option<String>,
    pub key_expansion_algorithm: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyResponse {
    pub key_id: String,
    pub key: Option<String>, // Base64-encoded key material, might be absent in some responses
    pub status: String,
    pub metadata: ResponseMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseMetadata {
    pub qber: f32,
    pub timestamp: u64,
    pub source_id: String,
    pub destination_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyStatusResponse {
    pub key_id: String,
    pub status: String,
    pub estimated_time: Option<u64>, // Seconds until key is ready if Pending
}

#[derive(Debug, Clone)]
pub enum DeviceType {
    Toshiba,
    IDQ,
    Basejump, // Added Basejump device type
    Simulated,
}

pub struct ETSIClient {
    base_url: String,
    client: Client,
    device_type: DeviceType,
    auth_token: Option<String>,
    key_cache: Arc<Mutex<Vec<QKDKey>>>, // Cache for retrieved keys
}

impl ETSIClient {
    /// Create a new ETSI QKD client
    ///
    /// # Arguments
    /// * `device_type` - Type of QKD device (Toshiba, IDQ, etc.)
    /// * `side` - The side of the QKD device (Alice or Bob)
    /// * `cert_path` - Path to TLS certificate for secure communication
    /// * `root_cert_path` - Optional path to root CA certificate
    /// * `auth_token` - Optional authentication token for API access
    pub fn new(
        device_type: DeviceType,
        side: Side,
        cert_path: &Path,
        root_cert_path: Option<&Path>,
        auth_token: Option<String>,
    ) -> Result<Self, Box<dyn Error>> {
        let base_url = match device_type {
            DeviceType::Toshiba => match side {
                Side::Alice => "https://192.168.0.4/api/v1",
                Side::Bob => "https://192.168.0.2/api/v1",
            },
            DeviceType::IDQ => match side {
                Side::Alice => "https://192.168.101.202/api/v1",
                Side::Bob => "https://192.168.101.207/api/v1",
            },
            DeviceType::Basejump => match side {
                Side::Alice => "https://192.168.0.101/api/v1",
                Side::Bob => "https://192.168.101.102/api/v1",
            },
            DeviceType::Simulated => "http://localhost:8000/api/v1",
        };

        let mut client_builder = Client::builder();

        // Load certificate if needed and if the path exists
        if matches!(device_type, DeviceType::Simulated) {
            debug!("Using simulated device, skipping certificate loading");
            // For simulated devices, we can also disable certificate verification
            client_builder = client_builder.danger_accept_invalid_certs(true);
        } else {
            // Load the device certificate
            if cert_path.exists() {
                debug!("Loading certificate from {:?}", cert_path);
                let cert_data = fs::read(cert_path)?;
                let cert = Certificate::from_pem(&cert_data)?;
                client_builder = client_builder.add_root_certificate(cert);

                // Load root certificate if provided
                if let Some(root_path) = root_cert_path {
                    if root_path.exists() {
                        debug!("Loading root certificate from {:?}", root_path);
                        let root_data = fs::read(root_path)?;
                        let root_cert = Certificate::from_pem(&root_data)?;
                        client_builder = client_builder.add_root_certificate(root_cert);
                    } else {
                        warn!("Root certificate path {:?} does not exist", root_path);
                    }
                }
            } else {
                warn!(
                    "Certificate path {:?} does not exist, proceeding without certificate",
                    cert_path
                );
            }

            // For real devices, we may need to disable certificate verification if there are issues
            // with self-signed certificates or complex certificate chains
            // Uncomment this line if you're having certificate verification issues
            // client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        // Create client with certificate
        let client = client_builder.build()?;

        Ok(Self {
            base_url: base_url.to_string(),
            client,
            device_type,
            auth_token,
            key_cache: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Request a QKD key from Alice's side
    /// This method requests a new quantum key from the QKD device
    ///
    /// # Arguments
    /// * `key_size` - Size of the requested key in bytes
    /// * `dest_id` - Destination ID (Bob's identifier)
    /// * `sae_id` - Optional SAE (Secure Authentication Encapsulation) ID
    pub async fn get_key_alice(
        &self,
        key_size: usize,
        dest_id: &str,
        sae_id: Option<&str>,
    ) -> Result<QKDKey, Box<dyn Error>> {
        debug!(
            "Requesting key from Alice's side, size: {} bytes, destination: {}",
            key_size, dest_id
        );

        // Check key cache first
        {
            let cache = self.key_cache.lock().await;
            for key in cache.iter() {
                if key.metadata.key_size >= key_size && key.metadata.status == KeyStatus::Available
                {
                    debug!("Found suitable key in cache: {}", key.key_id);
                    return Ok(key.clone());
                }
            }
        }

        // For simulated device, generate a simulated key instead of making HTTP request
        if matches!(self.device_type, DeviceType::Simulated) {
            return self.generate_simulated_key(key_size, dest_id, None).await;
        }

        // Prepare request based on device type
        let endpoint = match self.device_type {
            DeviceType::Toshiba => format!("{}/keys/request", self.base_url),
            DeviceType::IDQ => format!("{}/sae/keys", self.base_url),
            DeviceType::Basejump => format!("{}/key-management/keys", self.base_url),
            DeviceType::Simulated => format!("{}/keys", self.base_url),
        };

        // Build request payload
        let request = KeyRequest {
            requested_key_size: key_size,
            destination_id: dest_id.to_string(),
            sae_id: sae_id.map(|s| s.to_string()),
            key_expansion_algorithm: "none".to_string(), // No expansion by default
            metadata: None,
        };

        // Build request with authentication if provided
        let mut req_builder = self.client.post(&endpoint).json(&request);
        if let Some(token) = &self.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }

        // Send request
        let response = req_builder.send().await?;

        // Handle response
        match response.status() {
            StatusCode::OK | StatusCode::CREATED => {
                let key_response: KeyResponse = response.json().await?;

                // Handle case where key might be pending
                if key_response.status == "pending" {
                    debug!("Key generation is pending, polling for status");
                    return self.poll_key_status(&key_response.key_id, 10, 1000).await;
                }

                // Process the key response
                if let Some(key_b64) = key_response.key {
                    let key_bytes = base64::decode(&key_b64)?;
                    let key_size = key_bytes.len();

                    let qkd_key = QKDKey {
                        key_id: key_response.key_id,
                        key_bytes,
                        timestamp: key_response.metadata.timestamp,
                        metadata: KeyMetadata {
                            source: key_response.metadata.source_id,
                            qber: key_response.metadata.qber,
                            key_size,
                            status: KeyStatus::Available,
                        },
                    };

                    // Add to cache
                    {
                        let mut cache = self.key_cache.lock().await;
                        cache.push(qkd_key.clone());

                        // Limit cache size
                        if cache.len() > 50 {
                            cache.remove(0);
                        }
                    }

                    info!(
                        "Successfully retrieved key: {}, size: {}",
                        qkd_key.key_id, qkd_key.metadata.key_size
                    );
                    Ok(qkd_key)
                } else {
                    Err(format!(
                        "No key material in response for key_id: {}",
                        key_response.key_id
                    )
                    .into())
                }
            }
            status => {
                let error_text = response.text().await?;
                error!("Error retrieving key: {}", error_text);
                Err(format!("Error retrieving key: {} - {}", status, error_text).into())
            }
        }
    }

    /// Retrieve a QKD key from Bob's side
    /// This method retrieves a quantum key that was previously distributed by Alice
    ///
    /// # Arguments
    /// * `key_id` - ID of the key to retrieve
    pub async fn get_key_bob(&self, key_id: &str) -> Result<QKDKey, Box<dyn Error>> {
        debug!("Retrieving key from Bob's side, key_id: {}", key_id);

        // Check key cache first
        {
            let cache = self.key_cache.lock().await;
            for key in cache.iter() {
                if key.key_id == key_id && key.metadata.status == KeyStatus::Available {
                    debug!("Found key in cache: {}", key.key_id);
                    return Ok(key.clone());
                }
            }
        }

        // For simulated device, regenerate the same key deterministically
        if matches!(self.device_type, DeviceType::Simulated) {
            // Parse the key_id to extract the necessary information
            // The key_id format is expected to be: "{dest_id}-{key_size}-{uuid}"
            let parts: Vec<&str> = key_id.split('-').collect();

            if parts.len() >= 3 {
                // Extract the destination ID and key size from the key_id
                let mut dest_id = parts[0].to_string();

                // If there are more than 3 parts, the destination ID might contain hyphens
                // We need to reconstruct it properly
                if parts.len() > 3 {
                    // The destination could have hyphens, so reconstruct it
                    // assuming the second-to-last part is the key size
                    let size_index = parts.len() - 2;
                    dest_id = parts[0..size_index].join("-");
                    let key_size = parts[size_index].parse::<usize>().unwrap_or(32);

                    // Use the exact key_id to ensure deterministic generation
                    return self
                        .generate_simulated_key(key_size, &dest_id, Some(key_id))
                        .await;
                } else {
                    // Simple case: destination-size-uuid
                    let key_size = parts[1].parse::<usize>().unwrap_or(32);
                    return self
                        .generate_simulated_key(key_size, &dest_id, Some(key_id))
                        .await;
                }
            } else {
                // Fallback for malformed key_ids
                warn!(
                    "Malformed key_id format: {}, using as destination with default size",
                    key_id
                );
                return self.generate_simulated_key(32, key_id, Some(key_id)).await;
            }
        }

        // Prepare request based on device type
        let endpoint = match self.device_type {
            DeviceType::Toshiba => format!("{}/keys/{}", self.base_url, key_id),
            DeviceType::IDQ => format!("{}/sae/keys/{}", self.base_url, key_id),
            DeviceType::Basejump => format!("{}/key-management/keys/{}", self.base_url, key_id),
            DeviceType::Simulated => format!("{}/keys/{}", self.base_url, key_id),
        };

        // Build request with authentication if provided
        let mut req_builder = self.client.get(&endpoint);
        if let Some(token) = &self.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }

        // Send request
        let response = req_builder.send().await?;

        // Handle response
        match response.status() {
            StatusCode::OK => {
                let key_response: KeyResponse = response.json().await?;

                if let Some(key_b64) = key_response.key {
                    let key_bytes = base64::decode(&key_b64)?;
                    let key_size = key_bytes.len();

                    let qkd_key = QKDKey {
                        key_id: key_response.key_id,
                        key_bytes,
                        timestamp: key_response.metadata.timestamp,
                        metadata: KeyMetadata {
                            source: key_response.metadata.source_id,
                            qber: key_response.metadata.qber,
                            key_size,
                            status: KeyStatus::Available,
                        },
                    };

                    // Add to cache
                    {
                        let mut cache = self.key_cache.lock().await;
                        cache.push(qkd_key.clone());

                        // Limit cache size
                        if cache.len() > 50 {
                            cache.remove(0);
                        }
                    }

                    info!(
                        "Successfully retrieved Bob's key: {}, size: {}",
                        qkd_key.key_id, qkd_key.metadata.key_size
                    );
                    Ok(qkd_key)
                } else {
                    Err(format!(
                        "No key material in response for key_id: {}",
                        key_response.key_id
                    )
                    .into())
                }
            }
            StatusCode::NOT_FOUND => Err(format!("Key not found: {}", key_id).into()),
            status => {
                let error_text = response.text().await?;
                error!("Error retrieving key: {}", error_text);
                Err(format!("Error retrieving key: {} - {}", status, error_text).into())
            }
        }
    }

    /// Check the status of a key
    ///
    /// # Arguments
    /// * `key_id` - ID of the key to check
    pub async fn check_key_status(&self, key_id: &str) -> Result<KeyStatus, Box<dyn Error>> {
        debug!("Checking status for key: {}", key_id);

        // For simulated device, check our cache
        if matches!(self.device_type, DeviceType::Simulated) {
            let cache = self.key_cache.lock().await;
            for key in cache.iter() {
                if key.key_id == key_id {
                    return Ok(key.metadata.status.clone());
                }
            }
            return Err(format!("Simulated key not found: {}", key_id).into());
        }

        // Prepare request based on device type
        let endpoint = match self.device_type {
            DeviceType::Toshiba => format!("{}/keys/{}/status", self.base_url, key_id),
            DeviceType::IDQ => format!("{}/sae/keys/{}/status", self.base_url, key_id),
            DeviceType::Basejump => {
                format!("{}/key-management/keys/{}/status", self.base_url, key_id)
            }
            DeviceType::Simulated => format!("{}/keys/{}/status", self.base_url, key_id),
        };

        // Build request with authentication if provided
        let mut req_builder = self.client.get(&endpoint);
        if let Some(token) = &self.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }

        // Send request
        let response = req_builder.send().await?;

        // Handle response
        match response.status() {
            StatusCode::OK => {
                let status_response: KeyStatusResponse = response.json().await?;

                // Map API status to our enum
                let key_status = match status_response.status.as_str() {
                    "available" => KeyStatus::Available,
                    "pending" => KeyStatus::Pending,
                    "consumed" => KeyStatus::Consumed,
                    "expired" => KeyStatus::Expired,
                    s => KeyStatus::Error(s.to_string()),
                };

                // Update cache if needed
                {
                    let mut cache = self.key_cache.lock().await;
                    for key in cache.iter_mut() {
                        if key.key_id == key_id {
                            key.metadata.status = key_status.clone();
                            break;
                        }
                    }
                }

                info!("Key status for {}: {:?}", key_id, key_status);
                Ok(key_status)
            }
            StatusCode::NOT_FOUND => Err(format!("Key not found: {}", key_id).into()),
            status => {
                let error_text = response.text().await?;
                error!("Error checking key status: {}", error_text);
                Err(format!("Error checking key status: {} - {}", status, error_text).into())
            }
        }
    }

    /// Delete a key from the QKD device
    /// This is important for security to ensure keys are only used once
    ///
    /// # Arguments
    /// * `key_id` - ID of the key to delete
    pub async fn delete_key(&self, key_id: &str) -> Result<bool, Box<dyn Error>> {
        debug!("Deleting key: {}", key_id);

        // For simulated device, just remove from cache
        if matches!(self.device_type, DeviceType::Simulated) {
            // Update cache
            {
                let mut cache = self.key_cache.lock().await;
                let initial_len = cache.len();
                cache.retain(|k| k.key_id != key_id);
                let removed = initial_len - cache.len();
                if removed > 0 {
                    info!("Successfully deleted simulated key: {}", key_id);
                    return Ok(true);
                } else {
                    warn!("Simulated key not found for deletion: {}", key_id);
                    return Ok(false);
                }
            }
        }

        // Prepare request based on device type
        let endpoint = match self.device_type {
            DeviceType::Toshiba => format!("{}/keys/{}", self.base_url, key_id),
            DeviceType::IDQ => format!("{}/sae/keys/{}", self.base_url, key_id),
            DeviceType::Basejump => format!("{}/key-management/keys/{}", self.base_url, key_id),
            DeviceType::Simulated => format!("{}/keys/{}", self.base_url, key_id),
        };

        // Build request with authentication if provided
        let mut req_builder = self.client.delete(&endpoint);
        if let Some(token) = &self.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }

        // Send request
        let response = req_builder.send().await?;

        // Handle response
        match response.status() {
            StatusCode::OK | StatusCode::NO_CONTENT => {
                // Update cache
                {
                    let mut cache = self.key_cache.lock().await;
                    cache.retain(|k| k.key_id != key_id);
                }

                info!("Successfully deleted key: {}", key_id);
                Ok(true)
            }
            StatusCode::NOT_FOUND => {
                warn!("Key not found for deletion: {}", key_id);
                Ok(false)
            }
            status => {
                let error_text = response.text().await?;
                error!("Error deleting key: {}", error_text);
                Err(format!("Error deleting key: {} - {}", status, error_text).into())
            }
        }
    }

    /// Poll for key status until it becomes available or times out
    ///
    /// # Arguments
    /// * `key_id` - ID of the key to poll
    /// * `max_attempts` - Maximum number of polling attempts
    /// * `delay_ms` - Delay between polling attempts in milliseconds
    async fn poll_key_status(
        &self,
        key_id: &str,
        max_attempts: u32,
        delay_ms: u64,
    ) -> Result<QKDKey, Box<dyn Error>> {
        for attempt in 1..=max_attempts {
            debug!("Polling key status, attempt {}/{}", attempt, max_attempts);

            // Check key status
            let status = self.check_key_status(key_id).await?;

            match status {
                KeyStatus::Available => {
                    // Key is ready, retrieve it
                    return self.get_key_bob(key_id).await;
                }
                KeyStatus::Pending => {
                    // Key is still being generated, wait and retry
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                    continue;
                }
                KeyStatus::Consumed | KeyStatus::Expired => {
                    return Err(
                        format!("Key {} is no longer available: {:?}", key_id, status).into(),
                    );
                }
                KeyStatus::Error(e) => {
                    return Err(format!("Key error: {}", e).into());
                }
            }
        }

        Err(format!("Timed out waiting for key {} to become available", key_id).into())
    }

    /// Get available key size from the QKD device
    /// This method queries the QKD device for the amount of key material available
    pub async fn get_available_key_size(&self) -> Result<usize, Box<dyn Error>> {
        debug!("Checking available key size");

        // For simulated device, just return a standard value
        if matches!(self.device_type, DeviceType::Simulated) {
            info!("Simulated device returning default available key size of 1024 bytes");
            return Ok(1024); // Return a default value for simulated devices
        }

        // Prepare request based on device type
        let endpoint = match self.device_type {
            DeviceType::Toshiba => format!("{}/keys/available", self.base_url),
            DeviceType::IDQ => format!("{}/sae/status", self.base_url),
            DeviceType::Basejump => format!("{}/key-management/status", self.base_url),
            DeviceType::Simulated => format!("{}/status", self.base_url),
        };

        // Build request with authentication if provided
        let mut req_builder = self.client.get(&endpoint);
        if let Some(token) = &self.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }

        // Send request
        let response = req_builder.send().await?;

        // Handle response
        match response.status() {
            StatusCode::OK => {
                let status: serde_json::Value = response.json().await?;

                // Extract available key size from response (format varies by device)
                let available_size = match self.device_type {
                    DeviceType::Toshiba => status["available_bytes"].as_u64().unwrap_or(0) as usize,
                    DeviceType::IDQ => {
                        status["key_pool"]["available_bytes"].as_u64().unwrap_or(0) as usize
                    }
                    DeviceType::Basejump => {
                        status["available_key_bytes"].as_u64().unwrap_or(0) as usize
                    }
                    DeviceType::Simulated => {
                        status["available_bytes"].as_u64().unwrap_or(1024) as usize
                    }
                };

                info!("Available key material: {} bytes", available_size);
                Ok(available_size)
            }
            status => {
                let error_text = response.text().await?;
                error!("Error checking available key size: {}", error_text);
                Err(format!(
                    "Error checking available key size: {} - {}",
                    status, error_text
                )
                .into())
            }
        }
    }

    /// Clear the key cache
    pub async fn clear_cache(&self) {
        let mut cache = self.key_cache.lock().await;
        cache.clear();
        debug!("Key cache cleared");
    }

    /// Generate a simulated QKD key for testing
    ///
    /// # Arguments
    /// * `key_size` - Size of the requested key in bytes
    /// * `dest_id` - Destination ID
    /// * `specific_key_id` - If provided, use this exact key ID instead of generating a new one
    async fn generate_simulated_key(
        &self,
        key_size: usize,
        dest_id: &str,
        specific_key_id: Option<&str>,
    ) -> Result<QKDKey, Box<dyn Error>> {
        // Create key ID
        let key_id = if let Some(id) = specific_key_id {
            id.to_string()
        } else {
            let unique_id = format!("{}-{}", dest_id, key_size);
            format!("{}-{}", unique_id, uuid::Uuid::new_v4())
        };

        // Generate key bytes using a FULLY deterministic algorithm based on the key_id
        // This ensures that both Alice and Bob will get the same key for the same key_id
        let seed = if let Some(id) = specific_key_id {
            // If a specific key ID is provided, use it as the seed to ensure consistency
            id.as_bytes()
                .iter()
                .fold(0u64, |acc, &x| acc.wrapping_add(x as u64))
        } else {
            // Otherwise use key_id which contains the UUID
            key_id
                .as_bytes()
                .iter()
                .fold(0u64, |acc, &x| acc.wrapping_add(x as u64))
        };

        // Generate deterministic key bytes using the seed
        let mut key_bytes = vec![0u8; key_size];
        for i in 0..key_size {
            // Use a simple deterministic algorithm based on the seed
            let value = ((seed.wrapping_add(i as u64))
                .wrapping_mul(0x5DEECE66Du64)
                .wrapping_add(0xBu64))
                % 256;
            key_bytes[i] = value as u8;
        }

        // Create simulated key
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let qkd_key = QKDKey {
            key_id: key_id.clone(),
            key_bytes,
            timestamp: now,
            metadata: KeyMetadata {
                source: "simulated".to_string(),
                qber: 0.01, // Simulated QBER of 1%
                key_size,
                status: KeyStatus::Available,
            },
        };

        // Add to cache
        {
            let mut cache = self.key_cache.lock().await;
            cache.push(qkd_key.clone());

            // Limit cache size
            if cache.len() > 50 {
                cache.remove(0);
            }
        }

        info!("Generated simulated key: {}, size: {}", key_id, key_size);
        Ok(qkd_key)
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_simulated_device() -> Result<(), Box<dyn Error>> {
        // Create client with simulated device
        let client = ETSIClient::new(
            DeviceType::Simulated,
            Side::Alice,
            &PathBuf::from("nonexistent-cert.pem"),
            None,
            None,
        )?;

        // Just test that we can create the client
        assert_eq!(client.base_url, "http://localhost:8000/api/v1");

        Ok(())
    }

    #[tokio::test]
    async fn test_key_cache() -> Result<(), Box<dyn Error>> {
        // Create client
        let client = ETSIClient::new(
            DeviceType::Simulated,
            Side::Bob,
            &PathBuf::from("nonexistent-cert.pem"),
            None,
            None,
        )?;

        // Add a test key to the cache
        let test_key = QKDKey {
            key_id: "test-key-id".to_string(),
            key_bytes: vec![1, 2, 3, 4, 5],
            timestamp: 12345,
            metadata: KeyMetadata {
                source: "test".to_string(),
                qber: 0.0,
                key_size: 5,
                status: KeyStatus::Available,
            },
        };

        {
            let mut cache = client.key_cache.lock().await;
            cache.push(test_key.clone());
        }

        // Clear the cache
        client.clear_cache().await;

        // Verify cache is empty
        {
            let cache = client.key_cache.lock().await;
            assert_eq!(cache.len(), 0);
        }

        Ok(())
    }

    #[test]
    fn test_key_status_enum() {
        // Test equality
        assert_eq!(KeyStatus::Available, KeyStatus::Available);
        assert_ne!(KeyStatus::Available, KeyStatus::Pending);

        // Test error variant
        let error_status = KeyStatus::Error("test error".to_string());
        if let KeyStatus::Error(msg) = error_status {
            assert_eq!(msg, "test error");
        } else {
            panic!("Expected Error variant");
        }
    }

    #[tokio::test]
    async fn test_simulated_key_generation() -> Result<(), Box<dyn Error>> {
        // Create simulated client
        let client = ETSIClient::new(
            DeviceType::Simulated,
            Side::Alice,
            &PathBuf::from("nonexistent-cert.pem"),
            None,
            None,
        )?;

        // Generate a simulated key
        let key = client.get_key_alice(32, "test-destination", None).await?;

        // Verify it has the right size
        assert_eq!(key.metadata.key_size, 32);

        // Delete the key
        let result = client.delete_key(&key.key_id).await?;
        assert!(result, "Key deletion should return true");

        Ok(())
    }

    #[tokio::test]
    async fn test_key_consistency() -> Result<(), Box<dyn Error>> {
        // Create two clients for Alice and Bob
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

        // Alice generates a key
        let alice_key = alice_client.get_key_alice(32, "test-dest", None).await?;

        // Bob retrieves the same key
        let bob_key = bob_client.get_key_bob(&alice_key.key_id).await?;

        // Verify the keys are identical
        assert_eq!(
            alice_key.key_bytes, bob_key.key_bytes,
            "Key bytes should be identical between Alice and Bob"
        );
        assert_eq!(alice_key.key_id, bob_key.key_id, "Key IDs should match");

        Ok(())
    }
    // Add this new method below your existing ETSIClient::new() method

    /// Create a new ETSI QKD client with separate certificate and key data
    ///
    /// # Arguments
    /// * `device_type` - Type of QKD device (Toshiba, IDQ, etc.)
    /// * `side` - The side of the QKD device (Alice or Bob)
    /// * `cert_data` - Certificate data in PEM format
    /// * `key_data` - Private key data in PEM format
    /// * `root_data` - Optional root CA certificate data in PEM format
    /// * `auth_token` - Optional authentication token for API access
    pub fn with_cert_and_key(
        device_type: DeviceType,
        side: Side,
        cert_data: Vec<u8>,
        key_data: Vec<u8>,
        root_data: Option<Vec<u8>>,
        auth_token: Option<String>,
    ) -> Result<ETSIClient, Box<dyn Error>> {
        use reqwest::{Certificate, ClientBuilder, Identity};

        let base_url = match device_type {
            DeviceType::Toshiba => match side {
                Side::Alice => "https://192.168.0.4/api/v1",
                Side::Bob => "https://192.168.0.2/api/v1",
            },
            DeviceType::IDQ => match side {
                Side::Alice => "https://192.168.101.202/api/v1",
                Side::Bob => "https://192.168.101.207/api/v1",
            },
            DeviceType::Basejump => match side {
                Side::Alice => "https://192.168.0.101/api/v1",
                Side::Bob => "https://192.168.101.102/api/v1",
            },
            DeviceType::Simulated => "http://localhost:8000/api/v1",
        };

        let mut client_builder = ClientBuilder::new();

        // Load certificate if needed
        if matches!(device_type, DeviceType::Simulated) {
            debug!("Using simulated device, skipping certificate loading");
            // For simulated devices, we can also disable certificate verification
            client_builder = client_builder.danger_accept_invalid_certs(true);
        } else {
            // Process certificate and key data
            debug!("Processing certificate and key data");

            // The key and cert need to be combined into a PEM identity
            // First, ensure both are in PEM format
            let cert_str = String::from_utf8_lossy(&cert_data);
            let key_str = String::from_utf8_lossy(&key_data);

            // Check if they look like PEM data
            if !cert_str.contains("-----BEGIN CERTIFICATE-----") {
                return Err("Invalid certificate data, does not contain PEM markers".into());
            }

            if !key_str.contains("-----BEGIN PRIVATE KEY-----")
                && !key_str.contains("-----BEGIN RSA PRIVATE KEY-----")
            {
                return Err("Invalid key data, does not contain PEM markers".into());
            }

            // Create a combined PEM file containing both cert and key
            let identity_pem = format!("{}\n{}", cert_str, key_str);

            // Create identity from the combined PEM
            debug!("Creating identity from combined PEM data");
            let identity = Identity::from_pkcs12_der(identity_pem.as_bytes(), "MySecret")?;
            client_builder = client_builder.identity(identity);

            // Add root CA if provided
            if let Some(data) = root_data {
                debug!("Adding root certificate");
                let root_cert = Certificate::from_pem(&data)?;
                client_builder = client_builder.add_root_certificate(root_cert);
            }

            // For real devices, we often need to disable strict verification
            client_builder = client_builder.danger_accept_invalid_certs(true);
            client_builder = client_builder.danger_accept_invalid_hostnames(true);
        }

        // Create client with certificate
        let client = client_builder.build()?;

        Ok(ETSIClient {
            base_url: base_url.to_string(),
            client,
            device_type,
            auth_token,
            key_cache: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
        })
    }
}
