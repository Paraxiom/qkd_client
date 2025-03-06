// standalone_integration_test.rs
// Compile with: rustc -o standalone_test standalone_integration_test.rs

use reqwest::{Certificate, Client, Identity};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

// Very simplified version that only tests certificate loading
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Starting QKD client certificate test");
    
    // Use absolute paths exactly as in your working reporter code
    let p12_path = Path::new("/home/paraxiom/qkd_client.mar5/certificate/Toshiba/certs/client_alice.p12");
    let ca_path = Path::new("/home/paraxiom/qkd_client.mar5/certificate/Toshiba/certs/ca_crt.pem");
    
    println!("Loading certificates...");
    
    // Read the PKCS#12
    let mut pkcs12_file = File::open(p12_path)?;
    let mut pkcs12_data = Vec::new();
    pkcs12_file.read_to_end(&mut pkcs12_data)?;
    println!("PKCS#12 file read: {} bytes", pkcs12_data.len());
    
    // Read the CA certificate
    let mut ca_file = File::open(ca_path)?;
    let mut ca_data = Vec::new();
    ca_file.read_to_end(&mut ca_data)?;
    println!("CA certificate file read: {} bytes", ca_data.len());
    
    // Parse the PKCS#12 data
    let identity = Identity::from_pkcs12_der(&pkcs12_data, "MySecret")?;
    println!("Successfully created Identity from PKCS#12");
    
    // Parse the CA certificate 
    let ca_cert = match Certificate::from_pem(&ca_data) {
        Ok(cert) => {
            println!("Successfully created Certificate from PEM");
            cert
        },
        Err(e) => {
            println!("Failed to parse certificate as PEM: {}", e);
            println!("Trying DER format...");
            match Certificate::from_der(&ca_data) {
                Ok(cert) => {
                    println!("Successfully created Certificate from DER");
                    cert
                },
                Err(e) => {
                    println!("Failed to parse certificate as DER: {}", e);
                    return Err("Failed to parse CA certificate".into());
                }
            }
        }
    };
    
    // Create the client
    println!("Building HTTP client...");
    let client = Client::builder()
        .identity(identity)
        .add_root_certificate(ca_cert)
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .timeout(Duration::from_secs(5))
        .build()?;
    
    println!("Successfully built client with certificates");
    
    // Try a simple GET request to test the client
    println!("Testing client with a request...");
    let url = "https://192.168.0.4/api/v1/status";
    let response = client.get(url).send().await;
    
    match response {
        Ok(resp) => {
            println!("Request successful! Status: {}", resp.status());
            if resp.status().is_success() {
                println!("Response body: {}", resp.text().await?);
            }
        },
        Err(e) => {
            println!("Request failed: {}", e);
        }
    }
    
    println!("Certificate test complete");
    Ok(())
}
