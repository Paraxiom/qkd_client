//! Simplified QKD Client Integration Test
//! 
//! This test retrieves a quantum-secured key, uses it with a hybrid VRF to
//! generate an output and proof, writes a JSON input for a Circom circuit, and
//! then calls external commands (via snarkJS) to generate and verify a ZK proof.
//!
//! Note: The ZK proof generation currently uses a placeholder since a real
//! implementation is not available yet.

use qkd_client::reporter::QKDClient; // Adjust the import according to your project structure.
use qkd_client::vrf::integrated_vrf::IntegratedVRF;
use qkd_client::quantum_auth::hybrid::HybridAuth;
use serde_json::json;
use std::{error::Error, fs, path::PathBuf, process::Command};
use tracing::{debug, info, Level};
use tracing_subscriber::FmtSubscriber;

const CIRCUITS_DIR: &str = "/home/paraxiom/qkd_client.mar5/circuits";

// Helper function to convert a byte slice to a hexadecimal string.
fn bytes_to_hex_str(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Ensure the verification key exists; if not, export it using snarkjs.
fn ensure_verification_key(circuits_dir: &str) -> Result<(), Box<dyn Error>> {
    let vkey_path = PathBuf::from(circuits_dir).join("vrf_seed_proof_verification_key.json");
    if !vkey_path.exists() {
        info!("Verification key not found. Exporting from proving key...");
        let status = Command::new("snarkjs")
            .current_dir(circuits_dir)
            .args(&[
                "zkey", "export", "verificationkey",
                "vrf_seed_proof_final.zkey",
                "vrf_seed_proof_verification_key.json",
            ])
            .status()?;
        if !status.success() {
            return Err("Failed to export verification key".into());
        }
        info!("Verification key exported successfully.");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging.
    let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("🚀 Starting simplified QKD Client Integration Test");

    // Initialize QKD client and retrieve the quantum key.
    let qkd_client = QKDClient::new()?;
    info!("🔑 Retrieving quantum-secured key from QKD server");
    let key_bytes = qkd_client.get_key().await?; // Now returns Vec<u8>
    info!("🔑 Quantum key retrieved ({} bytes)", key_bytes.len());

    // Initialize the hybrid VRF.
    let hybrid_auth = HybridAuth::new()?;
    let vrf = IntegratedVRF::new(hybrid_auth)?;

    // Prepare input for VRF.
    let input = b"VRF test input for integration test";
    let mut input_padded = input.to_vec();
    // Adjust the padding size as expected by your circuit (here using 16 bytes)
    input_padded.resize(16, 0);
    let mut quantum_key_padded = key_bytes.clone();
    quantum_key_padded.resize(16, 0);

    // Generate VRF output and proof.
    let vrf_response = vrf.generate_with_proof(&input_padded, &quantum_key_padded)?;

    let mut vrf_seed_padded = vrf_response.output.clone();
    vrf_seed_padded.resize(16, 0);

    // Build JSON input for the Circom circuit using hexadecimal strings.
    let circuit_input_json = json!({
        "inputData": bytes_to_hex_str(&input_padded),
        "quantumKey": bytes_to_hex_str(&quantum_key_padded),
        "vrfSeed": bytes_to_hex_str(&vrf_seed_padded)
    });

    let circuit_input_path = PathBuf::from(CIRCUITS_DIR).join("vrf_seed_proof_input.json");
    fs::write(&circuit_input_path, serde_json::to_string_pretty(&circuit_input_json)?)?;
    info!("Wrote circuit input JSON to {:?}", circuit_input_path);

    // Ensure that the verification key file exists.
    ensure_verification_key(CIRCUITS_DIR)?;

    // Run witness generation using Node.js.
    let witness_status = Command::new("node")
        .current_dir(CIRCUITS_DIR)
        .args(&[
            "vrf_seed_proof_js/generate_witness.js",
            "vrf_seed_proof_js/vrf_seed_proof.wasm",
            "vrf_seed_proof_input.json",
            "vrf_seed_proof_witness.wtns",
        ])
        .status()?;
    if !witness_status.success() {
        return Err("❌ Witness generation failed".into());
    }

    // Run proof generation using snarkJS.
    let proof_status = Command::new("snarkjs")
        .current_dir(CIRCUITS_DIR)
        .args(&[
            "groth16", "prove", "vrf_seed_proof_final.zkey",
            "vrf_seed_proof_witness.wtns",
            "vrf_seed_proof_proof.json",
            "vrf_seed_proof_public.json",
        ])
        .status()?;
    if !proof_status.success() {
        return Err("❌ ZK Proof generation failed".into());
    }

    // Verify the proof using snarkJS.
    let verify_status = Command::new("snarkjs")
        .current_dir(CIRCUITS_DIR)
        .args(&[
            "groth16", "verify", "vrf_seed_proof_verification_key.json",
            "vrf_seed_proof_public.json",
            "vrf_seed_proof_proof.json",
        ])
        .status()?;
    if !verify_status.success() {
        return Err("❌ ZK Proof verification failed".into());
    }
    info!("✅ ZK Proof verified successfully");

    // Finally, verify the VRF output using our integrated VRF.
    let valid = vrf.verify_with_proof(&input_padded, &vrf_response, &quantum_key_padded)?;
    if valid {
        info!("✅ VRF verification successful");
        Ok(())
    } else {
        Err("❌ VRF verification failed".into())
    }
}
