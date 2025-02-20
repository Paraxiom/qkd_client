use reqwest;
use reqwest::{Certificate, Identity};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Serialize)]
struct KeyRequest {
    sae_id: String,
    key_size: u32,
    number_of_keys: u32,
}

#[derive(Debug, Deserialize)]
struct Key {
    // The JSON field is actually "key_ID"
    #[serde(rename = "key_ID")]
    key_id: String,

    // The JSON field is "key"
    key: String,
}

#[derive(Debug, Deserialize)]
struct KeyResponse {
    // The JSON is {"keys": [ { "key_ID":..., "key":... } ] }
    keys: Vec<Key>,
}

/// Reads entire file into a Vec<u8>
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
    let p12_path = Path::new("/home/paraxiom/qkd_client/certificate/Toshiba/certs/client_alice.p12");
    let ca_path  = Path::new("/home/paraxiom/qkd_client/certificate/Toshiba/certs/ca_crt.pem");

    println!("\n🔍 Reading PKCS#12 file (client_alice.p12)...");
    let pkcs12_bytes = read_file(p12_path)?;
    println!("Creating Identity from PKCS#12...");

    // Must match the password used with -passout pass:MySecret
    let identity = Identity::from_pkcs12_der(&pkcs12_bytes, "MySecret")?;
    println!("✅ Successfully created identity from P12");

    println!("\n🔍 Reading CA cert...");
    let ca_contents = read_file(ca_path)?;
    println!("Creating CA certificate from ca_crt.pem...");
    let ca_cert = Certificate::from_pem(&ca_contents)?;
    println!("✅ Successfully created CA certificate");

    // Build the client
    println!("🛠️ Building reqwest client...");
    let client = reqwest::Client::builder()
        .identity(identity)
        .add_root_certificate(ca_cert)
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .timeout(Duration::from_secs(5))
        .build()?;

    // Prepare JSON body
    let request = KeyRequest {
        sae_id: "bobsae".to_string(),
        key_size: 256,
        number_of_keys: 1,
    };

    println!("📡 Sending request to: {}", url);
    println!("Request Body: {:?}", request);

    // Post the request
    let response = client.post(&url).json(&request).send().await?;

    println!("✅ Got response!");
    let status = response.status();
    let headers = response.headers().clone();
    println!("Status: {}", status);
    println!("Headers: {:#?}", headers);

    // Read the raw body
    let raw_text = response.text().await?;
    println!("Response body:\n{}", raw_text);

    // If success, parse JSON
    if status.is_success() {
        // We'll parse from the raw_text now
        match serde_json::from_str::<KeyResponse>(&raw_text) {
            Ok(key_response) => {
                println!("\n🎉 Success! Got keys:");
                for key in key_response.keys {
                    println!("🔑 Key ID: {}", key.key_id);
                    println!("🗝️  Key: {}", key.key);
                }
            },
            Err(e) => {
                println!("❌ Error parsing response JSON: {}", e);
            }
        }
    } else {
        // We printed the body above
        println!("❌ Non-200 status code => see above body for error details.");
    }

    Ok(())
}

#[tokio::main]
async fn main() {
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

