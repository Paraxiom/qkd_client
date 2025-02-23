use ark_bn254::Fr;
use ark_circom::{CircomBuilder, CircomCircuit, CircomConfig};
use std::error::Error;
use std::path::PathBuf;

pub async fn build_test_circuit() -> Result<CircomCircuit<Fr>, Box<dyn Error>> {
    let circuit_path = PathBuf::from("circuits/key_proof.r1cs");
    let wasm_path = PathBuf::from("circuits/key_proof_js/key_proof.wasm");

    let cfg = CircomConfig::<Fr>::new(wasm_path, circuit_path)?;
    let builder = CircomBuilder::new(cfg);
    Ok(builder.build()?)
}
