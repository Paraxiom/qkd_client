use reqwest;
use reqwest::Certificate;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
mod zk;
use zk::KeyProof;
mod quantum_auth;
use quantum_auth::QuantumAuthenticator;
use tracing;
use tracing_subscriber::FmtSubscriber;
use ark_ff::PrimeField;

#[derive(Debug, Serialize)]
struct KeyRequest {
    sae_id: String,
    key_size: u32,
    number_of_keys: u32,
}

#[derive(Debug, Deserialize)]
struct Key {
    #[serde(rename = "key_ID")]
    key_id: String,
    key: String,
}

#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<Key>,
}

fn read_file(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    println!("📂 Opening file: {}", path.display());
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    println!("✅ Successfully read {} bytes!", contents.len());
    Ok(contents)
}

async fn try_connection(ip: &str, is_enc: bool) -> Result<(), Box<dyn Error>> {
    let url = if is_enc {
        format!("https://{}/api/v1/keys/bobsae/enc_keys", ip)
    } else {
        format!("https://{}/api/v1/keys/alicesae/dec_keys", ip)
    };
    println!("\n🔍 Trying connection to {}", url);

    // PKCS#12 path + CA
    let p12_path =
        Path::new("/home/paraxiom/qkd_client/certificate/Toshiba/certs/client_alice.p12");
    let ca_path = Path::new("/home/paraxiom/qkd_client/certificate/Toshiba/certs/ca_crt.pem");

    println!("\n🔍 Reading PKCS#12 file (client_alice.p12)...");
    let pkcs12_bytes = read_file(p12_path)?;

    println!("\n🔍 Reading CA cert...");
    let ca_contents = read_file(ca_path)?;
    let ca_cert = Certificate::from_pem(&ca_contents)?;

    let mut quantum_auth = QuantumAuthenticator::new()?;
    let auth_proof = quantum_auth.authenticate()?;
    println!("✅ Generated quantum auth proof");

    // Build client with certificates
    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .identity(reqwest::Identity::from_pkcs12_der(
            &pkcs12_bytes,
            "MySecret",
        )?)
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .timeout(Duration::from_secs(5))
        .build()?;

    let request = KeyRequest {
        sae_id: "bobsae".to_string(),
        key_size: 256,
        number_of_keys: 1,
    };

    println!("📡 Sending request to: {}", url);
    println!("Request Body: {:?}", request);

    let response = client
        .post(&url)
        .json(&request)
        .header("X-Quantum-Auth", base64::encode(&auth_proof))
        .send()
        .await?;

    println!("✅ Got response!");
    let status = response.status();
    let headers = response.headers().clone();
    println!("Status: {}", status);
    println!("Headers: {:#?}", headers);

    let raw_text = response.text().await?;
    println!("Response body:\n{}", raw_text);

    if status.is_success() {
        match serde_json::from_str::<KeyResponse>(&raw_text) {
            Ok(key_response) => {
                println!("\n🎉 Success! Got keys:");
                for key in key_response.keys {
                    println!("🔑 Key ID: {}", key.key_id);
                    println!("🗝️  Key: {}", key.key);

                    // Generate quantum-resistant proof
                    println!("📝 Generating quantum-resistant proof...");
                    // In your key processing code
                    match KeyProof::new(&key.key).await {
                        Ok(key_proof) => {
                            println!("✅ Generated quantum-resistant proof");
                            match key_proof.verify() {
                                Ok(true) => println!("✅ Proof verified successfully"),
                                Ok(false) => println!("❌ Proof verification failed"),
                                Err(e) => println!("❌ Error verifying proof: {}", e),
                            }
                        }
                        Err(e) => println!("❌ Error generating proof: {}", e),
                    }
                }
            }
            Err(e) => {
                println!("❌ Error parsing response JSON: {}", e);
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    println!("🌟 Testing connection...\n");
    let ip = "192.168.0.4";
    println!("\n🔄 Testing IP: {}", ip);

    if let Err(e) = try_connection(ip, true).await {
        println!("❌ Connection failed!");
        println!("Error: {}", e);
        if let Some(source) = e.source() {
            println!("Caused by: {}", source);
        }
    }
}
