// src/bin/multi_source_demo.rs
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use qkd_client::byzantine::buffer::{ReporterEntry, SharedBuffer};
use qkd_client::zk::multi_source_generator::MultiSourceProofGenerator;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("🌟 Multi-Source Quantum Key Proof Demo");
    info!("======================================");

    // Create shared buffer
    let buffer = SharedBuffer::new(100);

    // Setup proof generator with threshold of 3
    let generator = MultiSourceProofGenerator::new(Arc::clone(&buffer), 3);

    // Simulate 5 reporter nodes
    info!("Creating simulated reporter entries...");
    let reporter_count = 5;

    for i in 0..reporter_count {
        // Create a simulated quantum key (32 bytes)
        let mut key_hash = Vec::with_capacity(32);
        for j in 0..32 {
            key_hash.push(((i * j) % 256) as u8);
        }

        // Create a reporter entry
        let reporter = ReporterEntry {
            reporter_id: format!("reporter-{}", i),
            key_id: format!("key-{}", i),
            key_hash,
            signature: Vec::new(), // No signature needed for demo
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };

        // Add to buffer
        generator.add_report(reporter.clone());
        info!("Added reporter: {}", reporter.reporter_id);
    }

    // Generate multi-source proof
    info!("\nGenerating multi-source proof...");
    let start = Instant::now();

    match generator.generate_proof().await {
        Ok(result) => {
            let generation_time = start.elapsed();
            info!("✅ Multi-source proof generated in {:?}", generation_time);
            info!("  Source count: {}", result.source_count);
            info!("  Commitment: {}", result.proof.get_commitment());
            info!("  VRF seed: {}", result.proof.get_vrf_seed());

            // Verify the proof
            info!("\nVerifying multi-source proof...");
            let verify_start = Instant::now();
            match result.proof.verify() {
                Ok(valid) => {
                    if valid {
                        info!(
                            "✅ Proof verified successfully in {:?}",
                            verify_start.elapsed()
                        );
                    } else {
                        info!("❌ Proof verification failed");
                    }
                }
                Err(e) => info!("❌ Error during verification: {}", e),
            }

            // Generate VRF output
            info!("\nGenerating VRF outputs from proof...");
            if let Ok(vrf_output) = result.vrf.prove(b"multi-source-vrf-input") {
                info!("✅ VRF output generated");
                info!("  Random bytes: {:?}", &vrf_output.0[..8]);

                // Use VRF for leader election
                if let Ok(leader) = result.vrf.elect_leader(reporter_count as u64) {
                    info!("  Elected leader: reporter-{}", leader);
                }

                // Use VRF for committee selection
                if let Ok(committee) = result.vrf.select_committee(3, reporter_count as u64) {
                    info!(
                        "  Selected committee: {:?}",
                        committee
                            .iter()
                            .map(|&id| format!("reporter-{}", id))
                            .collect::<Vec<_>>()
                    );
                }
            }

            // Export proof for third-party verification
            let export_path = std::env::current_dir()?.join("proof_export.json");
            if let Err(e) = result.proof.export_for_verification(&export_path) {
                info!("❌ Error exporting proof: {}", e);
            } else {
                info!("\n✅ Exported proof to {:?}", export_path);
            }
        }
        Err(e) => info!("❌ Error generating proof: {}", e),
    }

    info!("\n📋 Next Steps:");
    info!("1. Generate circuit files using the 'compile_circuit.sh' script");
    info!("2. Integrate with your existing reporter nodes");
    info!("3. Connect to Byzantine consensus for production use");

    Ok(())
}
