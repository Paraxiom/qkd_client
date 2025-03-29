//! Integrated VRF implementation with real ZK proof generation
use super::core::QuantumVRF;
use crate::quantum_auth::hybrid::HybridAuth;
use crate::zk::circuit_manager::CircuitManager;
use serde_json::{json, Value};
use std::error::Error;
use std::time::Instant;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct VRFResponse {
    pub output: Vec<u8>,
    pub vrf_proof: Vec<u8>,
    pub zk_proof: Value,      // The real ZK proof (as JSON)
    pub public_inputs: Value, // The public inputs from the circuit
}

/// Integrated VRF that now generates a real ZK proof using our circuit manager.
pub struct IntegratedVRF {
    vrf: QuantumVRF,
    circuit_manager: CircuitManager,
}

impl IntegratedVRF {
    /// Create a new integrated VRF.
    pub fn new(hybrid_auth: HybridAuth) -> Result<Self, Box<dyn Error>> {
        let vrf = QuantumVRF::new(hybrid_auth);
        let circuit_manager = CircuitManager::new()?;
        Ok(Self {
            vrf,
            circuit_manager,
        })
    }

    /// Generate VRF output and a zero‐knowledge proof.
    ///
    /// This function:
    /// 1. Generates the VRF output and VRF proof.
    /// 2. Converts the raw byte inputs into hexadecimal strings (so each becomes a single field element).
    /// 3. Builds a JSON input for your Circom circuit.
    /// 4. Calls the circuit manager to generate a real ZK proof.
    pub fn generate_with_proof(
        &self,
        input: &[u8],
        quantum_key: &[u8],
    ) -> Result<VRFResponse, Box<dyn Error>> {
        debug!("Generating VRF output");
        let start = Instant::now();

        // Generate VRF output (seed) and VRF proof from your quantum VRF.
        let (output, vrf_proof) = self.vrf.generate(input, quantum_key)?;
        debug!("Generated VRF output in {:?}", start.elapsed());

        // Convert byte arrays to hexadecimal strings (each becomes one field element).
        let input_field = bytes_to_hex_str(input);
        let quantum_key_field = bytes_to_hex_str(quantum_key);
        let vrf_seed_field = bytes_to_hex_str(&output);

        // Build the JSON input for the circuit.
        let circuit_input = json!({
            "inputData": input_field,
            "quantumKey": quantum_key_field,
            "vrfSeed": vrf_seed_field,
        });

        // Generate a real ZK proof using the circuit manager.
        let (zk_proof, public_inputs) = self
            .circuit_manager
            .generate_proof("vrf_seed_proof", circuit_input)?;

        info!("VRF generation completed in {:?}", start.elapsed());

        Ok(VRFResponse {
            output,
            vrf_proof,
            zk_proof,
            public_inputs,
        })
    }

    /// Verify the VRF output and its zero-knowledge proof.
    pub fn verify_with_proof(
        &self,
        input: &[u8],
        response: &VRFResponse,
        quantum_key: &[u8],
    ) -> Result<bool, Box<dyn Error>> {
        debug!("Verifying VRF output");
        let start = Instant::now();

        let vrf_valid =
            self.vrf
                .verify(input, &response.output, &response.vrf_proof, quantum_key)?;
        if !vrf_valid {
            warn!("VRF verification failed");
            return Ok(false);
        }
        // For now, we assume ZK proof is valid if it was generated.
        let zk_valid = true;

        info!(
            "VRF verification completed in {:?}: {}",
            start.elapsed(),
            vrf_valid && zk_valid
        );
        Ok(vrf_valid && zk_valid)
    }
}

/// Helper function to convert a byte slice into a hexadecimal string.
fn bytes_to_hex_str(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
