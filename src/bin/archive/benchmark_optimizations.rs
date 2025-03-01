use qkd_client::byzantine::vrf_consensus::VRFBasedConsensus;
use qkd_client::quantum_auth::hybrid::HybridAuth;
use qkd_client::vrf::core::QuantumVRF;
use qkd_client::vrf::integrated::IntegratedVRF;
use std::error::Error;
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn Error>> {
    println!("�� QKD VRF Performance Benchmark");
    println!("===============================");

    // Test data
    let inputs = vec![
        b"Input 1: Leader selection for round 1".to_vec(),
        b"Input 2: Leader selection for round 2".to_vec(),
        b"Input 3: Leader selection for round 3".to_vec(),
        b"Input 4: Leader selection for round 4".to_vec(),
        b"Input 5: Leader selection for round 5".to_vec(),
    ];

    let quantum_key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    // Initialize auth for VRF
    println!("\n📊 Initializing authentication system...");
    let start = Instant::now();
    let auth = HybridAuth::new()?;
    let auth_init_time = start.elapsed();
    println!("  Auth initialization time: {:?}", auth_init_time);

    // Benchmark core VRF implementation
    println!("\n📊 Benchmarking Core VRF...");
    // Create a new HybridAuth instance instead of cloning
    let vrf = QuantumVRF::new(HybridAuth::new()?);

    let mut generation_times = Vec::new();
    let mut verification_times = Vec::new();
    let mut proofs = Vec::new();
    let mut outputs = Vec::new();

    for input in &inputs {
        // Generate
        let start = Instant::now();
        let (output, proof) = vrf.generate(input, &quantum_key)?;
        let gen_time = start.elapsed();
        generation_times.push(gen_time);
        proofs.push(proof);
        outputs.push(output);

        println!(
            "  Generated VRF for input {} in {:?}",
            String::from_utf8_lossy(&input[0..20]),
            gen_time
        );
    }

    // Verify
    for (i, input) in inputs.iter().enumerate() {
        let start = Instant::now();
        let valid = vrf.verify(input, &outputs[i], &proofs[i], &quantum_key)?;
        let verify_time = start.elapsed();
        verification_times.push(verify_time);

        println!(
            "  Verified VRF for input {} in {:?} - Result: {}",
            String::from_utf8_lossy(&input[0..20]),
            verify_time,
            if valid { "✅" } else { "❌" }
        );
    }

    // Summarize
    let avg_gen = generation_times.iter().sum::<Duration>() / generation_times.len() as u32;
    let avg_verify = verification_times.iter().sum::<Duration>() / verification_times.len() as u32;
    let avg_proof_size = proofs.iter().map(|p| p.len()).sum::<usize>() / proofs.len();

    println!("\n📈 Core VRF Performance Summary:");
    println!("  Average generation time: {:?}", avg_gen);
    println!("  Average verification time: {:?}", avg_verify);
    println!("  Average proof size: {} bytes", avg_proof_size);

    // Benchmark Byzantine VRF Consensus
    println!("\n📊 Benchmarking Byzantine VRF Consensus...");

    // Setup participants
    let participants = vec![10, 20, 30, 40, 50];
    let node_id = 1;

    // Create the consensus
    let integrated_vrf = IntegratedVRF::new(auth);
    let consensus = VRFBasedConsensus::new(integrated_vrf, node_id, quantum_key.clone());

    // Benchmark leader selection
    let mut selection_times = Vec::new();
    let mut leaders = Vec::new();

    for round in 1..6 {
        let start = Instant::now();
        let leader = consensus.select_leader(round, &participants)?;
        let selection_time = start.elapsed();
        selection_times.push(selection_time);
        leaders.push(leader);

        println!(
            "  Selected leader {} for round {} in {:?}",
            leader, round, selection_time
        );
    }

    let avg_selection = selection_times.iter().sum::<Duration>() / selection_times.len() as u32;
    println!("\n📈 Byzantine VRF Consensus Performance Summary:");
    println!("  Average leader selection time: {:?}", avg_selection);

    Ok(())
}
