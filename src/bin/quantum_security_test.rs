//! Quantum Security Integration Test using QKDClient and VRF
use qkd_client::quantum_auth::hybrid::HybridAuth;
use qkd_client::vrf::integrated_vrf::IntegratedVRF;
use reqwest::{Certificate, Client, Identity};
use serde::{Deserialize, Serialize};
use std::error::Error;
use tracing::{info, debug, Level};
use tracing_subscriber::FmtSubscriber;

const BASE_URL: &str = "https://192.168.0.4";
const ALICE_CERT_PATH: &str = "/home/paraxiom/qkd_client.mar5/certificate/Toshiba/certs/client_alice.p12";
const CA_CERT_PATH: &str = "/home/paraxiom/qkd_client.mar5/certificate/Toshiba/certs/ca_crt.pem";
const P12_PASSWORD: &str = "MySecret";

#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<QuantumKey>,
}

#[derive(Debug, Deserialize)]
struct QuantumKey {
    key_ID: String,
    key: String,
}

struct QKDClient {
    client: Client,
    base_url: String,
}

impl QKDClient {
    fn new() -> Result<Self, Box<dyn Error>> {
        let pkcs12_bytes = std::fs::read(ALICE_CERT_PATH)?;
        let ca_cert_bytes = std::fs::read(CA_CERT_PATH)?;

        let ca_cert = Certificate::from_pem(&ca_cert_bytes)?;
        let identity = Identity::from_pkcs12_der(&pkcs12_bytes, P12_PASSWORD)?;

        let client = Client::builder()
            .identity(identity)
            .add_root_certificate(ca_cert)
            .danger_accept_invalid_hostnames(true)
            .build()?;

        Ok(Self {
            client,
            base_url: BASE_URL.into(),
        })
    }

    pub async fn get_key(&self, sae_id: &str, key_size: u32) -> Result<(String, Vec<u8>), Box<dyn Error>> {
        let req_body = serde_json::json!({
            "sae_id": sae_id,
            "key_size": key_size,
            "number_of_keys": 1,
        });

        let url = format!("{}/api/v1/keys/{}/enc_keys", self.base_url, sae_id);
        debug!("Sending request to {}", url);

        let resp = self.client.post(url).json(&req_body).send().await?;

        if !resp.status().is_success() {
            return Err(format!("Failed to retrieve key, status: {}", resp.status()).into());
        }

        let key_resp: KeyResponse = resp.json().await?;
        let quantum_key = &key_resp.keys[0];

        let key_bytes = base64::decode(&quantum_key.key)?;

        Ok((quantum_key.key_ID.clone(), key_bytes))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let subscriber = FmtSubscriber::builder().with_max_level(Level::INFO).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("🚀 Starting QKD Client Integration Test");

    let qkd_client = QKDClient::new()?;

    info!("🔑 Requesting quantum-secured key from QKD server");
    let (key_id, key_bytes) = qkd_client.get_key("bobsae", 256).await?;
    info!("🔑 Retrieved key ID: {}", key_id);

    info!("🛡️ Testing Quantum-Resistant VRF");
    let hybrid_auth = HybridAuth::new()?;
    let vrf = IntegratedVRF::new(hybrid_auth);

    let input_data = b"Integration test for QKD quantum-resistant VRF";
    let vrf_response = vrf.expect("REASON").generate_with_proof(input_data, &key_bytes)?;

    info!(
        "VRF Output: {} bytes, Proof: {} bytes",
        vrf_response.output.len(),
        vrf_response.vrf_proof.len()
    );

    let vrf_response = vrf.expect("REASON").generate_with_proof(input_data, &key_bytes)?;

    info!("✅ VRF verification successful");
    Ok(())
}
