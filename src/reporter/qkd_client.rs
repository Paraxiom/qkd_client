// src/reporter/qkd_client.rs
use crate::quantum_auth::QuantumAuthenticator;
use reqwest::{Certificate, Client, Identity};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use tracing::{debug, info};

#[derive(Debug, Serialize)]
struct KeyRequest {
    sae_id: String,
    key_size: u32,
    number_of_keys: u32,
}

#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<Key>,
}

#[derive(Debug, Deserialize)]
struct Key {
    #[serde(rename = "key_ID")]
    key_id: String,
    key: String,
}

pub struct QKDClient {
    client: Client,
    auth: QuantumAuthenticator,
    base_url: String,
}

fn read_file(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    debug!("📂 Reading file: {}", path.display());
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    debug!("✅ Successfully read {} bytes", contents.len());
    Ok(contents)
}

impl QKDClient {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        // Load certificates
        let p12_path =
            Path::new("/home/paraxiom/qkd_client/certificate/Toshiba/certs/client_alice.p12");
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
            auth: QuantumAuthenticator::new()?,
            base_url: "https://192.168.0.4".to_string(),
        })
    }

    pub async fn get_key(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let url = format!("{}/api/v1/keys/bobsae/enc_keys", self.base_url);
        debug!("Retrieving key from {}", url);

        // Generate quantum auth proof
        let auth_proof = self.auth.authenticate()?;

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
            .header("X-Quantum-Auth", base64::encode(&auth_proof))
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
        let key_id = &key_response.keys[0].key_id;

        info!("Successfully retrieved key with ID: {}", key_id);

        Ok(key)
    }
}
