// src/zk/multi_source_proof.rs
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::collections::HashMap;
use serde_json::{json, Value};
use tracing::{debug, info};

use crate::byzantine::buffer::ReporterEntry;

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
        nonce: u64
    ) -> Result<Self, Box<dyn Error>> {
        info!("Starting multi-source proof generation for {} sources (threshold: {})",
            sources.len(), threshold);

        // Get current directory and set paths
        let current_dir = std::env::current_dir()?;
        let circuits_dir = current_dir.join("circuits");
        
        // Verify required files exist
        let wasm_path = Self::check_file_exists(
            circuits_dir.join("multi_source_key_js").join("multi_source_key.wasm"))?;
        let zkey_path = Self::check_file_exists(
            circuits_dir.join("multi_source_key_0001.zkey"))?;
        let vkey_path = Self::check_file_exists(
            circuits_dir.join("multi_source_verification_key.json"))?;
            
        let input_path = circuits_dir.join("multi_source_input.json");
        let witness_path = circuits_dir.join("multi_source_witness.wtns");
        let proof_path = circuits_dir.join("multi_source_proof.json");
        let public_path = circuits_dir.join("multi_source_public.json");
        
        // Create input file
        let input = self::prepare_input_file(sources, threshold, nonce)?;
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
        let inputs = public_inputs.as_array()
            .ok_or("Invalid public inputs format")?;
        
        // The last two elements should be combinedCommitment and vrfSeed
        let combined_commitment = inputs
            .get(inputs.len() - 2)
            .ok_or("Missing combinedCommitment in public inputs")?
            .as_str()
            .ok_or("Invalid combinedCommitment format")?
            .to_string();
            
        let vrf_seed = inputs
            .get(inputs.len() - 1)
            .ok_or("Missing vrfSeed in public inputs")?
            .as_str()
            .ok_or("Invalid vrfSeed format")?
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
        nonce: u64
    ) -> Result<Value, Box<dyn Error>> {
        // Limit to MAX_SOURCES
        const MAX_SOURCES: usize = 5;
        let source_count = sources.len().min(MAX_SOURCES);
        
        // Initialize arrays
        let mut keys: Vec<Vec<u64>> = Vec::with_capacity(MAX_SOURCES);
        let mut source_ids: Vec<u64> = Vec::with_capacity(MAX_SOURCES);
        let mut valid_sources: Vec<u64> = Vec::with_capacity(MAX_SOURCES);
        
        // Process each source
        for i in 0..MAX_SOURCES {
            if i < source_count {
                // Extract key bytes
                let key_bytes = &sources[i].key_hash;
                let mut key_values = Vec::with_capacity(32);
                
                // Convert bytes to field elements
                // Ensure we have at least 32 bytes (pad if necessary)
                for j in 0..32 {
                    let value = if j < key_bytes.len() {
                        key_bytes[j] as u64
                    } else {
                        0u64
                    };
                    key_values.push(value);
                }
                
                // Add to arrays
                keys.push(key_values);
                source_ids.push(i as u64); // Use index as ID for simplicity
                valid_sources.push(1u64);  // All sources are considered valid
            } else {
                // Add empty padding
                keys.push(vec![0u64; 32]);
                source_ids.push(0u64);
                valid_sources.push(0u64);
            }
        }
        
        // Create input object
        let input = json!({
            "sourceCount": source_count,
            "threshold": threshold,
            "nonce": nonce,
            "keys": keys,
            "sourceIds": source_ids,
            "validSources": valid_sources
        });
        
        Ok(input)
    }
}
