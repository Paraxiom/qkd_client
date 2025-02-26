use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use qkd_client::zk::circuit::build_test_circuit;
use rand::thread_rng;

#[tokio::main]
async fn main() {
    println!("🔧 Generating proving and verifying keys...");

    // Build test circuit
    let circuit = build_test_circuit().await.expect("Failed to build circuit");

    // Generate keys
    let rng = &mut thread_rng();

    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(circuit, rng).expect("Failed to generate keys");

    println!("✅ Keys generated successfully!");
}
