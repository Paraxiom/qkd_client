//! Simplified QKD Client Integration Test
//!
//! This test retrieves a quantum-secured key, uses it with a hybrid VRF to
//! generate an output and proof, writes a JSON input for a Circom circuit, and
//! then calls external commands (via snarkJS) to generate and verify a ZK proof.
//!
//! Note: The ZK proof generation currently uses a placeholder since a real
//! implementation is not available yet.
use qkd_client::quantum_auth::hybrid::HybridAuth;
use qkd_client::reporter::QKDClient; // Adjust the import according to your project structure.
use qkd_client::vrf::integrated_vrf::IntegratedVRF;
use serde_json::json;
use std::{error::Error, fs, path::PathBuf, process::Command};
use tracing::{debug, info, Level};
use tracing_subscriber::FmtSubscriber;

// Make sure this path exists and is correct
const CIRCUITS_DIR: &str = "/home/paraxiom/qkd_client/circuits";

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
                "zkey",
                "export",
                "verificationkey",
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
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    info!("🚀 Starting simplified QKD Client Integration Test");

    // Verify the circuits directory exists first
    let circuits_dir_path = PathBuf::from(CIRCUITS_DIR);
    if !circuits_dir_path.exists() || !circuits_dir_path.is_dir() {
        return Err(format!("Circuits directory not found: {}", CIRCUITS_DIR).into());
    }

    // Initialize QKD client and retrieve the quantum key.
    let qkd_client = QKDClient::new()?;
    info!("🔑 Retrieving quantum-secured key from QKD server");
    let key_bytes = qkd_client.get_key().await?; // Now returns Vec<u8>
    info!("🔑 Quantum key retrieved ({} bytes)", key_bytes.len());

    // Initialize the hybrid VRF.
    let hybrid_auth = HybridAuth::new()?;
    // Use expect() to handle the Result properly
    let vrf = IntegratedVRF::new(hybrid_auth).expect("Failed to create IntegratedVRF");

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

    // Ensure the circuits directory is properly set up
    let circuit_input_path = circuits_dir_path.join("vrf_seed_proof_input.json");
    fs::write(
        &circuit_input_path,
        serde_json::to_string_pretty(&circuit_input_json)?,
    )?;
    info!("Wrote circuit input JSON to {:?}", circuit_input_path);

    // Check if the required files exist
    let wasm_path = circuits_dir_path.join("vrf_seed_proof_js/vrf_seed_proof.wasm");
    let js_path = circuits_dir_path.join("vrf_seed_proof_js/generate_witness.js");
    let zkey_path = circuits_dir_path.join("vrf_seed_proof_final.zkey");

    if !wasm_path.exists() {
        return Err(format!("Required WASM file not found: {:?}", wasm_path).into());
    }
    if !js_path.exists() {
        return Err(format!("Required JS file not found: {:?}", js_path).into());
    }
    if !zkey_path.exists() {
        return Err(format!("Required zkey file not found: {:?}", zkey_path).into());
    }

    // Ensure that the verification key file exists.
    ensure_verification_key(CIRCUITS_DIR)?;

    // Run witness generation using Node.js.
    info!("Running witness generation...");
    let witness_status = Command::new("node")
        .current_dir(&circuits_dir_path)
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
    info!("✅ Witness generation successful");

    // Run proof generation using snarkJS.
    info!("Running proof generation...");
    let proof_status = Command::new("snarkjs")
        .current_dir(&circuits_dir_path)
        .args(&[
            "groth16",
            "prove",
            "vrf_seed_proof_final.zkey",
            "vrf_seed_proof_witness.wtns",
            "vrf_seed_proof_proof.json",
            "vrf_seed_proof_public.json",
        ])
        .status()?;

    if !proof_status.success() {
        return Err("❌ ZK Proof generation failed".into());
    }
    info!("✅ Proof generation successful");

    // Verify the proof using snarkJS.
    info!("Running proof verification...");
    let verify_status = Command::new("snarkjs")
        .current_dir(&circuits_dir_path)
        .args(&[
            "groth16",
            "verify",
            "vrf_seed_proof_verification_key.json",
            "vrf_seed_proof_public.json",
            "vrf_seed_proof_proof.json",
        ])
        .status()?;

    if !verify_status.success() {
        return Err("❌ ZK Proof verification failed".into());
    }
    info!("✅ ZK Proof verified successfully");

    // Finally, verify the VRF output using our integrated VRF.
    info!("Verifying VRF output...");
    let valid = vrf.verify_with_proof(&input_padded, &vrf_response, &quantum_key_padded)?;
    if valid {
        info!("✅ VRF verification successful");
        Ok(())
    } else {
        Err("❌ VRF verification failed".into())
    }
}
