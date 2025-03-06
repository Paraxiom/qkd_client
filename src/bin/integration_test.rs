//! Simplified QKD Client Integration Test
//! 
//! This test uses the QKDClient implementation that we know works
//! with your existing certificates and QKD device setup

use qkd_client::vrf::integrated_vrf::IntegratedVRF;
use qkd_client::quantum_auth::hybrid::HybridAuth;
use std::error::Error;
use tracing::{debug, error, info, Level};
use tracing_subscriber::FmtSubscriber;
use std::path::Path;
use std::fs::File;
use std::io::Read;
use reqwest::{Certificate, Client, Identity};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// Helper function to read file contents
fn read_file(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    debug!("📂 Reading file: {}", path.display());
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    debug!("✅ Successfully read {} bytes", contents.len());
    Ok(contents)
}

// This struct is copied from your working code
#[derive(Debug, Serialize)]
struct KeyRequest {
    sae_id: String,
    key_size: u32,
    number_of_keys: u32,
}

// This struct is copied from your working code
#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<Key>,
}

// This struct is copied from your working code
#[derive(Debug, Deserialize)]
struct Key {
    #[serde(rename = "key_ID")]
    key_id: String,
    key: String,
}

// This is a simplified version of your working QKDClient
struct QKDClient {
    client: Client,
    base_url: String,
}

impl QKDClient {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        // Load certificates - using exact same paths as your working code
        let p12_path = Path::new("/home/paraxiom/qkd_client/certificate/Toshiba/certs/client_alice.p12");
        let ca_path = Path::new("/home/paraxiom/qkd_client/certificate/Toshiba/certs/ca_crt.pem");
        
        debug!("Loading PKCS#12 and CA certificates...");
        let pkcs12_bytes = read_file(p12_path)?;
        let ca_contents = read_file(ca_path)?;
        let ca_cert = Certificate::from_pem(&ca_contents)?;
        
        // Build client with certificates
        let client = Client::builder()
            .add_root_certificate(ca_cert)
            .identity(Identity::from_pkcs12_der(&pkcs12_bytes, "MySecret")?)
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .timeout(Duration::from_secs(5))
            .build()?;
            
        Ok(Self {
            client,
            base_url: "https://192.168.0.4".to_string(),
        })
    }
    
    pub async fn get_key(&self) -> Result<(String, Vec<u8>), Box<dyn Error>> {
        let url = format!("{}/api/v1/keys/bobsae/enc_keys", self.base_url);
        debug!("Retrieving key from {}", url);
        
        // Build request
        let request = KeyRequest {
            sae_id: "bobsae".to_string(),
            key_size: 256,
            number_of_keys: 1,
        };
        
        // Send request
        debug!("Sending request: {:?}", request);
        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await?;
            
        let status = response.status();
        debug!("Response status: {}", status);
        if !status.is_success() {
            return Err(format!("Request failed with status: {}", status).into());
        }
        
        // Parse response
        let response_text = response.text().await?;
        let key_response: KeyResponse = serde_json::from_str(&response_text)?;
        if key_response.keys.is_empty() {
            return Err("No keys returned from server".into());
        }
        
        // Decode key from base64
        let key = base64::decode(&key_response.keys[0].key)?;
        let key_id = key_response.keys[0].key_id.clone();
        info!("Successfully retrieved key with ID: {}", key_id);
        
        Ok((key_id, key))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");
    
    info!("Starting simplified QKD client integration test");
    
    // Initialize QKD client
    let qkd_client = QKDClient::new()?;
    
    // Get quantum key
    info!("Retrieving quantum key from QKD device");
    let (key_id, key_bytes) = qkd_client.get_key().await?;
    info!("Retrieved key: {} ({} bytes)", key_id, key_bytes.len());
    
    // Test VRF with quantum key
    info!("Initializing quantum-resistant VRF");
    let hybrid_auth = HybridAuth::new()?;
    let vrf = IntegratedVRF::new(hybrid_auth);
    
    // Generate randomness
    info!("Generating randomness using VRF with quantum key");
    let input = b"VRF test input for integration test";
    let response = vrf.generate_with_proof(input, &key_bytes)?;
    
    info!("Generated randomness: {} bytes of output, {} bytes of proof", 
        response.output.len(), response.vrf_proof.len());
    
    // Verify VRF output
    let valid = vrf.verify_with_proof(input, &response, &key_bytes)?;
    
    if valid {
        info!("✅ VRF verification successful");
        Ok(())
    } else {
        error!("❌ VRF verification failed");
        Err("VRF verification failed".into())
    }
}