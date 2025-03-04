// src/bin/qkd_client_demo.rs
use std::error::Error;
use std::path::PathBuf;
use clap::{Parser, ValueEnum};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use qkd_client::qkd::etsi_api::{DeviceType, ETSIClient, KeyStatus};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// QKD device type
    #[arg(value_enum, short, long, default_value = "simulated")]
    device: Device,

    /// Path to certificate file
    #[arg(short, long, default_value = "certificate/default_cert.pem")]
    cert_path: PathBuf,

    /// Operation to perform
    #[arg(value_enum, short, long, default_value = "status")]
    operation: Operation,

    /// Key ID (required for retrieve/status/delete operations)
    #[arg(short, long)]
    key_id: Option<String>,

    /// Destination ID (required for request operation)
    #[arg(short, long)]
    dest_id: Option<String>,

    /// Key size in bytes (for request operation)
    #[arg(short, long, default_value = "32")]
    key_size: usize,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Device {
    Toshiba,
    Idq,
    Basejump,
    Simulated,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Operation {
    Status,
    Request,
    Retrieve,
    Delete,
}

impl From<Device> for DeviceType {
    fn from(device: Device) -> Self {
        match device {
            Device::Toshiba => DeviceType::Toshiba,
            Device::Idq => DeviceType::IDQ,
            Device::Basejump => DeviceType::Basejump,
            Device::Simulated => DeviceType::Simulated,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Parse command-line arguments
    let cli = Cli::parse();

    // Create ETSI client
    let client = ETSIClient::new(
        cli.device.into(),
        &cli.cert_path,
        None, // No auth token for demo
    )?;

    // Perform requested operation
    match cli.operation {
        Operation::Status => {
            if let Some(key_id) = &cli.key_id {
                // Check status of specific key
                let status = client.check_key_status(key_id).await?;
                info!("Status of key {}: {:?}", key_id, status);
            } else {
                // Check overall available key size
                let available = client.get_available_key_size().await?;
                info!("Available key material: {} bytes", available);
            }
        },
        Operation::Request => {
            // Ensure destination ID is provided
            let dest_id = cli.dest_id.ok_or("Destination ID is required for key request")?;
            
            // Request new key
            let key = client.get_key_alice(cli.key_size, &dest_id, None).await?;
            
            info!("Requested key:");
            info!("  Key ID: {}", key.key_id);
            info!("  Size: {} bytes", key.key_bytes.len());
            info!("  QBER: {}", key.metadata.qber);
            
            // Print first few bytes of the key (careful with this in production!)
            let preview: Vec<u8> = key.key_bytes.iter().take(4).copied().collect();
            info!("  Key preview (first 4 bytes): {:?}", preview);
        },
        Operation::Retrieve => {
            // Ensure key ID is provided
            let key_id = cli.key_id.ok_or("Key ID is required for key retrieval")?;
            
            // Retrieve key
            let key = client.get_key_bob(&key_id).await?;
            
            info!("Retrieved key:");
            info!("  Key ID: {}", key.key_id);
            info!("  Size: {} bytes", key.key_bytes.len());
            info!("  QBER: {}", key.metadata.qber);
            
            // Print first few bytes of the key (careful with this in production!)
            let preview: Vec<u8> = key.key_bytes.iter().take(4).copied().collect();
            info!("  Key preview (first 4 bytes): {:?}", preview);
        },
        Operation::Delete => {
            // Ensure key ID is provided
            let key_id = cli.key_id.ok_or("Key ID is required for key deletion")?;
            
            // Delete key
            let success = client.delete_key(&key_id).await?;
            
            if success {
                info!("Successfully deleted key: {}", key_id);
            } else {
                info!("Key not found or already deleted: {}", key_id);
            }
        },
    }

    Ok(())
}