// src/bin/byzantine_simulator.rs
use qkd_client::byzantine::buffer::SharedBuffer;
use qkd_client::byzantine::consensus::{ByzantineConsensus, ConsensusConfig};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::time::Duration;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("🌟 Byzantine Consensus Simulator");
    info!("===============================");

    // Configuration
    let node_count = 4; // 3f+1 where f=1 (can tolerate 1 faulty node)
    let rounds = 3;

    // Create shared buffer
    let buffer = SharedBuffer::new(1000);

    // Create consensus config
    let config = ConsensusConfig {
        node_count,
        fault_tolerance: 1,
        view_timeout: Duration::from_secs(5),
        round_timeout: Duration::from_secs(20),
        max_rounds: 5,
    };

    info!("Byzantine Consensus Configuration:");
    info!("  Nodes: {}", node_count);
    info!("  Fault Tolerance: {}", config.fault_tolerance);
    info!("  View Timeout: {:?}", config.view_timeout);
    info!("  Round Timeout: {:?}", config.round_timeout);
    info!("");

    // Create consensus instances
    let mut nodes = HashMap::new();
    for i in 0..node_count {
        let node_id = format!("node{}", i);
        match ByzantineConsensus::new(&node_id, Arc::clone(&buffer), config.clone()) {
            Ok(consensus) => {
                nodes.insert(node_id.clone(), consensus);
                info!("Created node: {}", node_id);
            }
            Err(e) => {
                error!("Failed to create node {}: {}", node_id, e);
                return Err(e);
            }
        }
    }

    // Run consensus rounds
    for round in 1..=rounds {
        info!("\n=== Starting Consensus Round {} ===", round);
        let start = Instant::now();

        // Determine primary for current round
        let primary_id = format!("node{}", (round - 1) % node_count);
        info!("Primary node for round {}: {}", round, primary_id);

        // Primary proposes a value
        let value = format!("Value for round {}", round).into_bytes();
        if let Some(primary) = nodes.get(&primary_id) {
            match primary.start_consensus(value.clone()) {
                Ok(_) => info!(
                    "Primary proposed value: {:?}",
                    String::from_utf8_lossy(&value)
                ),
                Err(e) => {
                    error!("Primary failed to propose: {}", e);
                    continue;
                }
            }
        }

        // Each node runs consensus
        let mut join_handles = Vec::new();
        for (node_id, consensus) in &nodes {
            let node_id = node_id.clone();
            let consensus = consensus.clone();

            // Skip primary (it started the consensus)
            if node_id == primary_id {
                continue;
            }

            // Run consensus in a separate thread
            let handle = tokio::spawn(async move {
                info!("Node {} starting consensus", node_id);
                match consensus.run_consensus_round() {
                    Ok(result) => {
                        if result.success {
                            let value_str = String::from_utf8_lossy(result.value.as_ref().unwrap());
                            info!("✅ Node {} reached consensus: {}", node_id, value_str);
                            info!("   Round duration: {:?}", result.round_duration);
                            info!("   Total messages: {}", result.total_messages);
                            (node_id, true, result.round_duration)
                        } else {
                            warn!("❌ Node {} failed to reach consensus", node_id);
                            (node_id, false, result.round_duration)
                        }
                    }
                    Err(e) => {
                        error!("❌ Node {} error: {}", node_id, e);
                        (node_id, false, Duration::from_secs(0))
                    }
                }
            });

            join_handles.push(handle);
        }

        // Wait for all nodes to complete
        let mut successful_nodes = 0;
        let mut total_duration = Duration::from_secs(0);

        for handle in join_handles {
            if let Ok((node_id, success, duration)) = handle.await {
                if success {
                    successful_nodes += 1;
                    total_duration += duration;
                }
            }
        }

        // Round summary
        let round_time = start.elapsed();
        info!("\n=== Round {} Summary ===", round);
        info!("Total time: {:?}", round_time);
        info!("Successful nodes: {}/{}", successful_nodes, node_count - 1); // Exclude primary

        let required_nodes = 2 * config.fault_tolerance + 1;
        if successful_nodes >= required_nodes - 1 {
            // -1 because primary isn't counted
            info!("✅ Round {} achieved consensus", round);
        } else {
            warn!("❌ Round {} failed to achieve consensus", round);
        }

        // Average consensus time
        if successful_nodes > 0 {
            let avg_duration = total_duration / successful_nodes as u32;
            info!("Average consensus time: {:?}", avg_duration);
        }

        // Wait between rounds
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // Final statistics
    let stats = buffer.get_stats();
    info!("\n=== Final Statistics ===");
    info!("Total messages: {}", stats.total_messages);
    info!("Message types:");
    for (msg_type, count) in &stats.messages_by_type {
        info!("  {:?}: {}", msg_type, count);
    }

    // Buffer message age
    if let Some(oldest) = stats.oldest_message_age {
        info!("Oldest message: {:?}", oldest);
    }
    if let Some(newest) = stats.newest_message_age {
        info!("Newest message: {:?}", newest);
    }

    Ok(())
}
