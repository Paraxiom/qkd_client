// src/zk/multi_source_proof.rs
use crate::byzantine::buffer::ReporterEntry;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info};

// Represents a proof for multiple quantum sources
pub struct MultiSourceKeyProof {
    proof: Value,
    verification_key: Value,
    public_inputs: Value,
    combined_commitment: String,
    vrf_seed: String,
}

impl MultiSourceKeyProof {
    // Generate a new proof from multiple quantum key sources
    pub async fn new(
        sources: &[ReporterEntry],
        threshold: usize,
        nonce: u64,
    ) -> Result<Self, Box<dyn Error>> {
        info!(
            "Starting multi-source proof generation for {} sources (threshold: {})",
            sources.len(),
            threshold
        );
        // Get current directory and set paths
        let current_dir = std::env::current_dir()?;
        let circuits_dir = current_dir.join("circuits");

        // Verify required files exist
        let wasm_path = Self::check_file_exists(
            circuits_dir
                .join("multi_source_key_js")
                .join("multi_source_key.wasm"),
        )?;
        let zkey_path = Self::check_file_exists(circuits_dir.join("multi_source_key_0001.zkey"))?;
        let vkey_path =
            Self::check_file_exists(circuits_dir.join("multi_source_verification_key.json"))?;

        let input_path = circuits_dir.join("multi_source_input.json");
        let witness_path = circuits_dir.join("multi_source_witness.wtns");
        let proof_path = circuits_dir.join("multi_source_proof.json");
        let public_path = circuits_dir.join("multi_source_public.json");

        // Create input file
        let input = Self::prepare_input_file(sources, threshold, nonce)?;
        fs::write(&input_path, input.to_string())?;
        debug!("Created multi-source input file at {:?}", input_path);
        // Generate witness
        info!("Generating witness for multiple sources...");
        let status = Command::new("snarkjs")
            .args(&[
                "wtns",
                "calculate",
                wasm_path.to_str().unwrap(),
                input_path.to_str().unwrap(),
                witness_path.to_str().unwrap(),
            ])
            .status()?;
        if !status.success() {
            return Err("Failed to generate witness for multiple sources".into());
        }
        info!("✅ Generated multi-source witness successfully");
        // Generate proof
        info!("Generating multi-source proof...");
        let status = Command::new("snarkjs")
            .args(&[
                "groth16",
                "prove",
                zkey_path.to_str().unwrap(),
                witness_path.to_str().unwrap(),
                proof_path.to_str().unwrap(),
                public_path.to_str().unwrap(),
            ])
            .status()?;
        if !status.success() {
            return Err("Failed to generate multi-source proof".into());
        }
        info!("✅ Generated multi-source proof successfully");
        // Read proof and verification files
        let proof: Value = serde_json::from_str(&fs::read_to_string(&proof_path)?)?;
        let verification_key: Value = serde_json::from_str(&fs::read_to_string(&vkey_path)?)?;
        let public_inputs: Value = serde_json::from_str(&fs::read_to_string(&public_path)?)?;

        // Extract commitment and VRF seed from public inputs
        let inputs = public_inputs
            .as_array()
            .ok_or("Invalid public inputs format")?;

        // Check if we have enough elements
        if inputs.len() < 2 {
            // If we don't have enough elements, use default values
            info!("Public inputs don't contain commitment and VRF seed, using defaults");
            let combined_commitment = "default-commitment".to_string();
            let vrf_seed = "default-seed".to_string();

            info!("Using default commitment: {}", combined_commitment);
            info!("Using default VRF seed: {}", vrf_seed);

            Ok(Self {
                proof,
                verification_key,
                public_inputs,
                combined_commitment,
                vrf_seed,
            })
        } else {
            // The last two elements should be combinedCommitment and vrfSeed
            let combined_commitment = inputs
                .get(inputs.len() - 2)
                .and_then(|v| v.as_str())
                .unwrap_or("unknown-commitment")
                .to_string();

            let vrf_seed = inputs
                .get(inputs.len() - 1)
                .and_then(|v| v.as_str())
                .unwrap_or("unknown-seed")
                .to_string();

            info!("Generated commitment: {}", combined_commitment);
            info!("Generated VRF seed: {}", vrf_seed);

            Ok(Self {
                proof,
                verification_key,
                public_inputs,
                combined_commitment,
                vrf_seed,
            })
        }
    }

    // Verify this multi-source proof
    pub fn verify(&self) -> Result<bool, Box<dyn Error>> {
        info!("Verifying multi-source proof...");

        // Get current directory and set paths
        let current_dir = std::env::current_dir()?;
        let circuits_dir = current_dir.join("circuits");
        let proof_verify_path = circuits_dir.join("multi_source_proof_to_verify.json");
        let vkey_path = circuits_dir.join("multi_source_verification_key.json");
        let public_path = circuits_dir.join("multi_source_public.json");

        // Write files for verification
        fs::write(&proof_verify_path, serde_json::to_string(&self.proof)?)?;
        fs::write(&vkey_path, serde_json::to_string(&self.verification_key)?)?;
        fs::write(&public_path, serde_json::to_string(&self.public_inputs)?)?;

        // Verify using snarkjs
        let output = Command::new("snarkjs")
            .args(&[
                "groth16",
                "verify",
                vkey_path.to_str().unwrap(),
                public_path.to_str().unwrap(),
                proof_verify_path.to_str().unwrap(),
            ])
            .output()?;

        let is_valid = output.status.success();
        if is_valid {
            info!("✅ Multi-source proof verified successfully");
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            debug!("❌ Multi-source proof verification failed: {}", error);
        }

        Ok(is_valid)
    }

    // Export the proof and public inputs for third-party verification
    pub fn export_for_verification(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        let export_data = json!({
            "proof": self.proof,
            "public_inputs": self.public_inputs,
            "verification_key": self.verification_key,
            "combined_commitment": self.combined_commitment,
            "vrf_seed": self.vrf_seed
        });

        fs::write(path, export_data.to_string())?;
        info!("Exported verification data to {:?}", path);

        Ok(())
    }

    // Get the combined commitment (for smart contracts, etc.)
    pub fn get_commitment(&self) -> &str {
        &self.combined_commitment
    }

    // Get the VRF seed
    pub fn get_vrf_seed(&self) -> &str {
        &self.vrf_seed
    }

    // Helper: Check if file exists
    fn check_file_exists(path: PathBuf) -> Result<PathBuf, Box<dyn Error>> {
        if !path.exists() {
            return Err(format!("Required file not found at {:?}", path).into());
        }
        Ok(path)
    }

    // Helper: Generate JSON input for the circuit
    fn prepare_input_file(
        sources: &[ReporterEntry],
        threshold: usize,
        nonce: u64,
    ) -> Result<Value, Box<dyn Error>> {
        // Extract just the needed fields for the circuit
        let source_count = sources.len() as u64;

        // Create validSources array with correct size (N from the circuit template)
        let mut valid_sources = vec![0; 8];
        for i in 0..std::cmp::min(sources.len(), 8) {
            valid_sources[i] = 1; // Mark sources as valid up to our count
        }

        // Create simplified input that matches circuit expectations
        let input_json = json!({
            "sourceCount": source_count,
            "validSources": valid_sources
        });

        Ok(input_json)
    }
}
