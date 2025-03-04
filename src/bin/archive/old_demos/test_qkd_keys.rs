// src/bin/test_qkd_keys.rs
use std::error::Error;
use std::path::Path;
use qkd_client::qkd::etsi_api::{DeviceType, ETSIClient, QKDKey};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("QKD Key Test - Connecting to multiple QKD devices");

    // Toshiba client
    {
        info!("Testing Toshiba QKD device...");
        let toshiba_cert_path = Path::new("certificate/Toshiba/certs/ca_crt.pem");
        let toshiba_client = ETSIClient::new(DeviceType::Toshiba, toshiba_cert_path, None)?;

        test_keys(&toshiba_client, "toshiba-node").await?;
    }

    // IDQ client
    {
        info!("Testing IDQ QKD device...");
        let idq_cert_path = Path::new("certificate/IDQ/ETSIA.pem");
        let idq_client = ETSIClient::new(DeviceType::IDQ, idq_cert_path, None)?;

        test_keys(&idq_client, "idq-node").await?;
    }

    // Simulated client (for development/testing without actual QKD hardware)
    {
        info!("Testing simulated QKD device...");
        let sim_client = ETSIClient::new(
            DeviceType::Simulated, 
            Path::new("dummy-path.pem"), // Path doesn't matter for simulation
            None,
        )?;

        test_keys(&sim_client, "sim-node").await?;
    }

    info!("All tests completed!");
    Ok(())
}

async fn test_keys(client: &ETSIClient, node_id: &str) -> Result<(), Box<dyn Error>> {
    info!("Testing key generation/retrieval for {}", node_id);

    // Check available key size
    let available = client.get_available_key_size().await?;
    info!("Available key material: {} bytes", available);

    // Alice requesting a key
    info!("Alice requesting key...");
    let key_alice = match client.get_key_alice(32, node_id, None).await {
        Ok(key) => {
            info!("✅ Alice got key ID: {}", key.key_id);
            key
        },
        Err(e) => {
            info!("❌ Alice failed to get key: {}", e);
            return Ok(());
        }
    };

    // Bob retrieving the same key
    info!("Bob retrieving key {}...", key_alice.key_id);
    match client.get_key_bob(&key_alice.key_id).await {
        Ok(key_bob) => {
            info!("✅ Bob got key with same ID: {}", key_bob.key_id);
            
            // Check if keys match (they should)
            if key_alice.key_bytes == key_bob.key_bytes {
                info!("✅ Keys match! Successful key distribution.");
            } else {
                info!("❌ Keys don't match! This should not happen.");
            }
            
            // Delete key after use
            if let Ok(deleted) = client.delete_key(&key_alice.key_id).await {
                if deleted {
                    info!("✅ Key deleted successfully");
                } else {
                    info!("❓ Key not found for deletion");
                }
            }
        },
        Err(e) => {
            info!("❌ Bob failed to get key: {}", e);
        }
    }

    Ok(())
}