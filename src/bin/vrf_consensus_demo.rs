// Save this as src/bin/vrf_consensus_demo.rs (completely replacing the existing file)
use qkd_client::byzantine::vrf_consensus::VRFBasedConsensus;
use qkd_client::quantum_auth::hybrid::HybridAuth;
use qkd_client::vrf::integrated::IntegratedVRF;
use std::error::Error;
use std::time::Instant;

fn main() -> Result<(), Box<dyn Error>> {
    println!("🔐 VRF-based Byzantine Consensus Demo");
    println!("===================================");

    // Setup participants
    let participants = vec![1, 2, 3, 4];
    let mut consensuses = Vec::new();
    let mut quantum_keys = Vec::new();

    // Initialize VRF for each node
    for &node_id in &participants {
        // Initialize HybridAuth
        let hybrid_auth = HybridAuth::new()?;

        // Generate a quantum key (in a real system, this would come from your QKD source)
        let quantum_key = vec![node_id as u8; 16]; // Simplified key for demo
        quantum_keys.push(quantum_key.clone());

        let vrf = IntegratedVRF::new(hybrid_auth);
        let consensus = VRFBasedConsensus::new(vrf, node_id, quantum_key);
        consensuses.push(consensus);
    }

    // Simulate multiple rounds of consensus
    for round in 1..=3 {
        println!("\n🔄 Round {}", round);

        // Each node proposes a leader
        println!("Leader selection:");
        for (i, consensus) in consensuses.iter().enumerate() {
            let leader = consensus.select_leader(round, &participants)?;
            println!(
                "  Node {} proposes node {} as leader",
                participants[i], leader
            );
        }
    }

    Ok(())
}
