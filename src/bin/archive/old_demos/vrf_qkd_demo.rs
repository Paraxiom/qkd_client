// src/bin/vrf_qkd_demo.rs
use std::error::Error;
use std::path::PathBuf;
use clap::{Parser, ValueEnum};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use qkd_client::qkd::etsi_api::{DeviceType, ETSIClient};
use qkd_client::vrf::core::QuantumVRF;
use qkd_client::vrf::qkd_vrf::QKDVerifiableRandomFunction;
use qkd_client::quantum_auth::hybrid::HybridAuth;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// QKD device type
    #[arg(value_enum, short, long, default_value = "simulated")]
    device: Device,

    /// Path to certificate file
    #[arg(short, long, default_value = "certificate/default_cert.pem")]
    cert_path: PathBuf,

    /// Role (Alice generates, Bob verifies)
    #[arg(value_enum, short, long, default_value = "alice")]
    role: Role,

    /// Destination node ID
    #[arg(short, long, default_value = "bob")]
    dest_id: String,

    /// Input data for VRF (arbitrary string)
    #[arg(short, long, default_value = "default-input")]
    input: String,
    
    /// Key ID (required for Bob to verify)
    #[arg(short, long)]
    key_id: Option<String>,
    
    /// VRF output (required for Bob to verify, hex-encoded)
    #[arg(long)]
    output: Option<String>,
    
    /// VRF proof (required for Bob to verify, hex-encoded)
    #[arg(long)]
    proof: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Device {
    Toshiba,
    Idq,
    Basejump,
    Simulated,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Role {
    Alice,
    Bob,
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

    // Create HybridAuth for VRF
    info!("Initializing hybrid authentication system...");
    let auth = HybridAuth::new()?;
    
    // Create QuantumVRF
    let vrf = QuantumVRF::new(auth);
    
    // Create QKD VRF
    let qkd_vrf = QKDVerifiableRandomFunction::new(
        vrf,
        cli.device.into(),
        &cli.cert_path,
    )?;
    
    // Input data for VRF
    let input_data = cli.input.as_bytes();
    
    // Perform role-specific operations
    match cli.role {
        Role::Alice => {
            // Alice generates VRF output using QKD
            info!("🔑 Generating VRF output using quantum key...");
            info!("- Input: {}", cli.input);
            info!("- Destination: {}", cli.dest_id);
            
            // Check available key material
            let available = qkd_vrf.get_available_key_size().await?;
            info!("Available quantum key material: {} bytes", available);
            
            // Generate VRF output
            let (output, proof, key_id) = qkd_vrf.generate_with_qkd(input_data, &cli.dest_id).await?;
            
            // Display results
            info!("✅ VRF output generated successfully!");
            info!("Key ID: {}", key_id);
            info!("VRF Output: {}", hex::encode(&output));
            info!("VRF Proof: {}", hex::encode(&proof));
            info!("");
            info!("For Bob to verify this output, run:");
            info!("./vrf_qkd_demo --role bob --key-id {} --output {} --proof {}", 
                  key_id, hex::encode(&output), hex::encode(&proof));
        },
        Role::Bob => {
            // Bob verifies VRF output using QKD
            let key_id = cli.key_id.ok_or("Key ID is required for verification")?;
            let output_hex = cli.output.ok_or("Output is required for verification")?;
            let proof_hex = cli.proof.ok_or("Proof is required for verification")?;
            
            // Decode hex strings
            let output = hex::decode(output_hex)?;
            let proof = hex::decode(proof_hex)?;
            
            info!("🔍 Verifying VRF output using quantum key...");
            info!("- Input: {}", cli.input);
            info!("- Key ID: {}", key_id);
            
            // Verify VRF output
            let valid = qkd_vrf.verify_with_qkd(input_data, &output, &proof, &key_id).await?;
            
            if valid {
                info!("✅ VRF output verified successfully!");
            } else {
                info!("❌ VRF verification failed!");
            }
        }
    }
    
    Ok(())
}