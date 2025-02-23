// src/zk/proof.rs
use std::error::Error;
use std::process::Command;
use serde_json::{json, Value};
use base64;
use std::fs;
use std::path::PathBuf;

pub struct KeyProof {
    proof: Value,
    verification_key: Value,
}

impl KeyProof {
    pub async fn new(key_b64: &str) -> Result<Self, Box<dyn Error>> {
        println!("Starting proof generation for key...");
        
        // Decode base64 key
        let key_bytes = base64::decode(key_b64)?;
        println!("Key bytes length: {}", key_bytes.len());

        // Get current directory and set paths
        let current_dir = std::env::current_dir()?;
        let circuits_dir = current_dir.join("circuits");
        let wasm_path = circuits_dir.join("key_verification_js").join("key_verification.wasm");
        let input_path = circuits_dir.join("input.json");
        let witness_path = circuits_dir.join("witness.wtns");
        let zkey_path = circuits_dir.join("key_verification_0001.zkey");
        let proof_path = circuits_dir.join("proof.json");
        let public_path = circuits_dir.join("public.json");
        let vkey_path = circuits_dir.join("verification_key.json");

        // Verify all required files exist
        println!("Verifying circuit files...");
        if !wasm_path.exists() {
            return Err(format!("WASM file not found at {:?}", wasm_path).into());
        }
        if !zkey_path.exists() {
            return Err(format!("zkey file not found at {:?}", zkey_path).into());
        }
        if !vkey_path.exists() {
            return Err(format!("Verification key not found at {:?}", vkey_path).into());
        }

        // Create input file
        let input = json!({
            "key": key_bytes.iter().map(|&b| b as u64).collect::<Vec<_>>()
        });
        fs::write(&input_path, input.to_string())?;
        println!("Created input file at {:?}", input_path);

        // Generate witness using snarkjs
        println!("Generating witness...");
        let status = Command::new("snarkjs")
            .args(&[
                "wtns",
                "calculate",
                wasm_path.to_str().unwrap(),
                input_path.to_str().unwrap(),
                witness_path.to_str().unwrap()
            ])
            .status()?;

        if !status.success() {
            return Err("Failed to generate witness".into());
        }
        println!("✅ Generated witness successfully");

        // Generate proof
        println!("Generating proof...");
        let status = Command::new("snarkjs")
            .args(&[
                "groth16",
                "prove",
                zkey_path.to_str().unwrap(),
                witness_path.to_str().unwrap(),
                proof_path.to_str().unwrap(),
                public_path.to_str().unwrap()
            ])
            .status()?;

        if !status.success() {
            return Err("Failed to generate proof".into());
        }
        println!("✅ Generated proof successfully");

        // Read proof and verification key
        println!("Reading proof and verification key...");
        let proof = serde_json::from_str(&fs::read_to_string(&proof_path)?)?;
        let verification_key = serde_json::from_str(&fs::read_to_string(&vkey_path)?)?;
        println!("✅ Read proof and verification key successfully");

        Ok(Self {
            proof,
            verification_key,
        })
    }

    pub fn verify(&self) -> Result<bool, Box<dyn Error>> {
        println!("Starting proof verification...");
        
        // Get paths
        let current_dir = std::env::current_dir()?;
        let circuits_dir = current_dir.join("circuits");
        let proof_verify_path = circuits_dir.join("proof_to_verify.json");
        let vkey_path = circuits_dir.join("verification_key.json");
        let public_path = circuits_dir.join("public.json");

        // Write files for verification
        fs::write(&proof_verify_path, serde_json::to_string(&self.proof)?)?;
        fs::write(&vkey_path, serde_json::to_string(&self.verification_key)?)?;
        println!("Wrote verification files");

        // Verify using snarkjs
        println!("Verifying proof...");
        let output = Command::new("snarkjs")
            .args(&[
                "groth16",
                "verify",
                vkey_path.to_str().unwrap(),
                public_path.to_str().unwrap(),
                proof_verify_path.to_str().unwrap()
            ])
            .output()?;

        let is_valid = output.status.success();
        if is_valid {
            println!("✅ Proof verified successfully");
        } else {
            println!("❌ Proof verification failed");
            println!("Error: {}", String::from_utf8_lossy(&output.stderr));
        }

        Ok(is_valid)
    }
}
