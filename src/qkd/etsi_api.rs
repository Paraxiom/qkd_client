// src/qkd/etsi_api.rs
use reqwest::{Client, Certificate, StatusCode};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QKDKey {
    pub key_id: String,
    pub key_bytes: Vec<u8>,
    pub timestamp: u64,
    pub metadata: KeyMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub source: String,  // "toshiba", "idq", etc.
    pub qber: f32,       // Quantum Bit Error Rate
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
    /// * `cert_path` - Path to TLS certificate for secure communication
    /// * `auth_token` - Optional authentication token for API access
    pub fn new(device_type: DeviceType, cert_path: &Path, auth_token: Option<String>) -> Result<Self, Box<dyn Error>> {
        let base_url = match device_type {
            DeviceType::Toshiba => "https://toshiba-qkd.example.com/api/v1",
            DeviceType::IDQ => "https://idq-qkd.example.com/api/v1",
            DeviceType::Basejump => "https://basejump-qkd.example.com/api/v1",
            DeviceType::Simulated => "http://localhost:8000/api/v1",
        };
        
        let mut client_builder = Client::builder();
        
        // Load certificate if the path exists
        if cert_path.exists() {
            debug!("Loading certificate from {:?}", cert_path);
            let cert_data = fs::read(cert_path)?;
            let cert = Certificate::from_pem(&cert_data)?;
            client_builder = client_builder.add_root_certificate(cert);
        } else {
            warn!("Certificate path {:?} does not exist, proceeding without certificate", cert_path);
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
    pub async fn get_key_alice(&self, key_size: usize, dest_id: &str, sae_id: Option<&str>) -> Result<QKDKey, Box<dyn Error>> {
        debug!("Requesting key from Alice's side, size: {} bytes, destination: {}", key_size, dest_id);
        
        // Check key cache first
        {
            let cache = self.key_cache.lock().await;
            for key in cache.iter() {
                if key.metadata.key_size >= key_size && key.metadata.status == KeyStatus::Available {
                    debug!("Found suitable key in cache: {}", key.key_id);
                    return Ok(key.clone());
                }
            }
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
                    
                    info!("Successfully retrieved key: {}, size: {}", qkd_key.key_id, qkd_key.metadata.key_size);
                    Ok(qkd_key)
                } else {
                    Err(format!("No key material in response for key_id: {}", key_response.key_id).into())
                }
            },
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
                    
                    info!("Successfully retrieved Bob's key: {}, size: {}", qkd_key.key_id, qkd_key.metadata.key_size);
                    Ok(qkd_key)
                } else {
                    Err(format!("No key material in response for key_id: {}", key_response.key_id).into())
                }
            },
            StatusCode::NOT_FOUND => {
                Err(format!("Key not found: {}", key_id).into())
            },
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
        
        // Prepare request based on device type
        let endpoint = match self.device_type {
            DeviceType::Toshiba => format!("{}/keys/{}/status", self.base_url, key_id),
            DeviceType::IDQ => format!("{}/sae/keys/{}/status", self.base_url, key_id),
            DeviceType::Basejump => format!("{}/key-management/keys/{}/status", self.base_url, key_id),
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
            },
            StatusCode::NOT_FOUND => {
                Err(format!("Key not found: {}", key_id).into())
            },
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
            },
            StatusCode::NOT_FOUND => {
                warn!("Key not found for deletion: {}", key_id);
                Ok(false)
            },
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
    async fn poll_key_status(&self, key_id: &str, max_attempts: u32, delay_ms: u64) -> Result<QKDKey, Box<dyn Error>> {
        for attempt in 1..=max_attempts {
            debug!("Polling key status, attempt {}/{}", attempt, max_attempts);
            
            // Check key status
            let status = self.check_key_status(key_id).await?;
            
            match status {
                KeyStatus::Available => {
                    // Key is ready, retrieve it
                    return self.get_key_bob(key_id).await;
                },
                KeyStatus::Pending => {
                    // Key is still being generated, wait and retry
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                    continue;
                },
                KeyStatus::Consumed | KeyStatus::Expired => {
                    return Err(format!("Key {} is no longer available: {:?}", key_id, status).into());
                },
                KeyStatus::Error(e) => {
                    return Err(format!("Key error: {}", e).into());
                },
            }
        }
        
        Err(format!("Timed out waiting for key {} to become available", key_id).into())
    }
    
    /// Get available key size from the QKD device
    /// This method queries the QKD device for the amount of key material available
    pub async fn get_available_key_size(&self) -> Result<usize, Box<dyn Error>> {
        debug!("Checking available key size");
        
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
                    DeviceType::IDQ => status["key_pool"]["available_bytes"].as_u64().unwrap_or(0) as usize,
                    DeviceType::Basejump => status["available_key_bytes"].as_u64().unwrap_or(0) as usize,
                    DeviceType::Simulated => status["available_bytes"].as_u64().unwrap_or(1024) as usize,
                };
                
                info!("Available key material: {} bytes", available_size);
                Ok(available_size)
            },
            status => {
                let error_text = response.text().await?;
                error!("Error checking available key size: {}", error_text);
                Err(format!("Error checking available key size: {} - {}", status, error_text).into())
            }
        }
    }
    
    /// Clear the key cache
    pub async fn clear_cache(&self) {
        let mut cache = self.key_cache.lock().await;
        cache.clear();
        debug!("Key cache cleared");
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{mock, server_address};
    use std::path::PathBuf;
    
    #[tokio::test]
    async fn test_get_key_alice() -> Result<(), Box<dyn Error>> {
        let mock_server = server_address();
        
        // Mock the key request endpoint
        let _m = mock("POST", "/api/v1/keys")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{
                "key_id": "test-key-123",
                "key": "dGVzdC1rZXktY29udGVudA==",
                "status": "available",
                "metadata": {
                    "qber": 0.01,
                    "timestamp": 1636729998,
                    "source_id": "alice",
                    "destination_id": "bob"
                }
            }"#)
            .create();
        
        // Create client with mock server
        let client = ETSIClient::new(
            DeviceType::Simulated,
            &PathBuf::from("nonexistent-cert.pem"),
            None
        )?;
        
        // Override base URL to use mock server
        let client = ETSIClient {
            base_url: format!("http://{}/api/v1", mock_server),
            ..client
        };
        
        // Request a key
        let key = client.get_key_alice(32, "bob", None).await?;
        
        // Verify the response
        assert_eq!(key.key_id, "test-key-123");
        assert_eq!(key.key_bytes, b"test-key-content");
        assert_eq!(key.metadata.qber, 0.01);
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_get_key_bob() -> Result<(), Box<dyn Error>> {
        let mock_server = server_address();
        
        // Mock the key retrieval endpoint
        let _m = mock("GET", "/api/v1/keys/test-key-123")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{
                "key_id": "test-key-123",
                "key": "dGVzdC1rZXktY29udGVudA==",
                "status": "available",
                "metadata": {
                    "qber": 0.01,
                    "timestamp": 1636729998,
                    "source_id": "alice",
                    "destination_id": "bob"
                }
            }"#)
            .create();
        
        // Create client with mock server
        let client = ETSIClient::new(
            DeviceType::Simulated,
            &PathBuf::from("nonexistent-cert.pem"),
            None
        )?;
        
        // Override base URL to use mock server
        let client = ETSIClient {
            base_url: format!("http://{}/api/v1", mock_server),
            ..client
        };
        
        // Retrieve a key
        let key = client.get_key_bob("test-key-123").await?;
        
        // Verify the response
        assert_eq!(key.key_id, "test-key-123");
        assert_eq!(key.key_bytes, b"test-key-content");
        assert_eq!(key.metadata.qber, 0.01);
        
        Ok(())
    }
}