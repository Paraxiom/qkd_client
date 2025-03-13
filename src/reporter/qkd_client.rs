use crate::quantum_auth::QuantumAuthenticator;
use reqwest::{Certificate, Client, Identity};
use serde::{Deserialize, Serialize};
use std::{error::Error, fs, path::Path, time::Duration};
use tracing::{debug, info, warn};

#[derive(Debug, Serialize)]
struct KeyRequest {
    sae_id: String,
    key_size: u32,
    number_of_keys: u32,
}

#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<QKDKey>,
}

#[derive(Debug, Deserialize)]
struct QKDKey {
    #[serde(rename = "key_ID")]
    key_id: String,
    key: String,
}

pub struct QKDClient {
    client: Client,
    authenticator: QuantumAuthenticator,
    base_url: String,
}

impl QKDClient {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        // Certificate paths
        let pkcs12_path =
            Path::new("/home/paraxiom/qkd_client/certificate/Toshiba/certs/client_alice.p12");
        let ca_cert_path =
            Path::new("/home/paraxiom/qkd_client/certificate/Toshiba/certs/ca_crt.pem");

        // Load certificates securely
        let identity = Self::load_identity(pkcs12_path, "MySecret")?;
        let ca_cert = Self::load_ca_certificate(ca_cert_path)?;

        // Build secure HTTP client
        let client = Client::builder()
            .add_root_certificate(ca_cert)
            .identity(identity)
            .danger_accept_invalid_certs(true) // 🚨 For testing only; disable in production
            .danger_accept_invalid_hostnames(true) // 🚨 For testing only; disable in production
            .timeout(Duration::from_secs(5))
            .build()?;

        debug!("✅ HTTP client configured successfully");

        Ok(Self {
            client,
            authenticator: QuantumAuthenticator::new()?,
            base_url: "https://192.168.0.4".into(),
        })
    }

    /// Retrieve a quantum-generated encryption key from the QKD server
    pub async fn get_key(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let url = format!("{}/api/v1/keys/bobsae/enc_keys", self.base_url);
        debug!("Requesting quantum key from URL: {}", url);

        // Generate quantum authentication proof
        let auth_proof = self.authenticator.authenticate()?;

        // Prepare key request payload
        let key_request = KeyRequest {
            sae_id: "bobsae".into(),
            key_size: 256,
            number_of_keys: 1,
        };

        // Send POST request to QKD server
        let response = self
            .client
            .post(&url)
            .json(&key_request)
            .header("X-Quantum-Auth", base64::encode(auth_proof))
            .send()
            .await?;

        debug!("Received response status: {}", response.status());

        let status = response.status();
        let response_text = response.text().await?;

        if !status.is_success() {
            warn!("QKD server returned error: {}", response_text);
            return Err(format!("QKD request failed ({}): {}", status, response_text).into());
        }

        // Deserialize response
        let key_response: KeyResponse = serde_json::from_str(&response_text)?;

        // Ensure at least one key is present
        let qkd_key = key_response
            .keys
            .get(0)
            .ok_or("No keys returned by QKD server")?;

        // Decode key from base64
        let key_bytes = base64::decode(&qkd_key.key)?;
        info!("🔑 Successfully retrieved quantum key (ID: {})", qkd_key.key_id);

        Ok(key_bytes)
    }

    /// Load identity certificate from PKCS#12 file
    fn load_identity(path: &Path, password: &str) -> Result<Identity, Box<dyn Error>> {
        debug!("Loading identity certificate from {}", path.display());
        let pkcs12_data = fs::read(path)?;
        let identity = Identity::from_pkcs12_der(&pkcs12_data, password)?;
        debug!("✅ Identity certificate loaded");
        Ok(identity)
    }

    /// Load CA certificate from PEM file
    fn load_ca_certificate(path: &Path) -> Result<Certificate, Box<dyn Error>> {
        debug!("Loading CA certificate from {}", path.display());
        let ca_cert_data = fs::read(path)?;
        let ca_cert = Certificate::from_pem(&ca_cert_data)?;
        debug!("✅ CA certificate loaded");
        Ok(ca_cert)
    }
}
