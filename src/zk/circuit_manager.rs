use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tracing::{debug, error, info};

pub struct CircuitManager {
    pub circuits_dir: PathBuf,
}

impl CircuitManager {
    /// Create a new CircuitManager.
    /// It expects the current directory joined with "circuits" (adjust if needed).
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let circuits_dir = std::env::current_dir()?.join("circuits");
        if !circuits_dir.exists() {
            return Err(format!("Circuits directory not found: {:?}", circuits_dir).into());
        }
        Ok(Self { circuits_dir })
    }

    /// Generate a proof for a circuit given its base name and JSON input.
    pub fn generate_proof(
        &self,
        circuit_name: &str,
        input: Value,
    ) -> Result<(Value, Value), Box<dyn Error>> {
        info!("Generating proof for circuit: {}", circuit_name);

        // Set up file paths based on your folder structure.
        let wasm_path = self.circuits_dir.join(format!("{}_js/{}.wasm", circuit_name, circuit_name));
        let zkey_path = self.circuits_dir.join(format!("{}_final.zkey", circuit_name));
        let input_path = self.circuits_dir.join(format!("{}_input.json", circuit_name));
        let witness_path = self.circuits_dir.join(format!("{}_witness.wtns", circuit_name));
        let proof_path = self.circuits_dir.join(format!("{}_proof.json", circuit_name));
        let public_path = self.circuits_dir.join(format!("{}_public.json", circuit_name));

        // Write the JSON input to file.
        fs::write(&input_path, serde_json::to_string_pretty(&input)?)?;
        debug!("Created input file at {:?}", input_path);

        // Generate the witness.
        info!("Generating witness...");
        let status = Command::new("snarkjs")
            .args(&[
                "wtns", "calculate",
                wasm_path.to_str().unwrap(),
                input_path.to_str().unwrap(),
                witness_path.to_str().unwrap(),
            ])
            .status()?;
        if !status.success() {
            error!("Failed to generate witness for circuit: {}", circuit_name);
            return Err(format!("Failed to generate witness for circuit: {}", circuit_name).into());
        }
        info!("✅ Generated witness successfully");

        // Generate the proof.
        info!("Generating proof...");
        let status = Command::new("snarkjs")
            .args(&[
                "groth16", "prove",
                zkey_path.to_str().unwrap(),
                witness_path.to_str().unwrap(),
                proof_path.to_str().unwrap(),
                public_path.to_str().unwrap(),
            ])
            .status()?;
        if !status.success() {
            error!("Failed to generate proof for circuit: {}", circuit_name);
            return Err(format!("Failed to generate proof for circuit: {}", circuit_name).into());
        }
        info!("✅ Generated proof successfully");

        // Read and parse the proof and public inputs.
        let proof: Value = serde_json::from_str(&fs::read_to_string(&proof_path)?)?;
        let public_inputs: Value = serde_json::from_str(&fs::read_to_string(&public_path)?)?;
        Ok((proof, public_inputs))
    }
}
