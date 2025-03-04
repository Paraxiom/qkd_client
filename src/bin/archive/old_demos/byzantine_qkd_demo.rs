// src/bin/byzantine_qkd_demo.rs
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use qkd_client::qkd::etsi_api::{DeviceType, ETSIClient};
use qkd_client::vrf::core::QuantumVRF;
use qkd_client::vrf::qkd_vrf::QKDVerifiableRandomFunction;
use qkd_client::quantum_auth::hybrid::HybridAuth;
use qkd_client::byzantine::buffer::SharedBuffer;
use qkd_client::byzantine::consensus::{ByzantineConsensus, ConsensusConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Byzantine Consensus with QKD-VRF Demo");
    
    // Create simulated QKD client for demo
    let client = ETSIClient::new(
        DeviceType::Simulated,
        Path::new("dummy-path.pem"),
        None,
    )?;
    
    // Create QKD key for initialization
    let qkd_key = client.get_key_alice(32, "consensus-demo", None).await?;
    info!("Retrieved QKD key for consensus: {} ({}B)", qkd_key.key_id, qkd_key.key_bytes.len());
    
    // Initialize VRF with hybrid authentication
    let auth = HybridAuth::new()?;
    let vrf = QuantumVRF::new(auth);
    
    // Initialize QKD-VRF
    let qkd_vrf = QKDVerifiableRandomFunction::new(
        vrf,
        DeviceType::Simulated,
        Path::new("dummy-path.pem"),
    )?;

    // Setup Byzantine consensus configuration
    let config = ConsensusConfig {
        node_count: 4,
        fault_tolerance: 1, // Can tolerate 1 faulty node (out of 4)
        view_timeout: Duration::from_secs(5),
        round_timeout: Duration::from_secs(15),
        max_rounds: 3,
    };
    
    // Create shared buffer for consensus messages
    let buffer = SharedBuffer::new(100);
    
    // Create consensus nodes
    let mut nodes = Vec::new();
    for i in 0..config.node_count {
        let node_id = format!("node{}", i);
        // Create an Arc<SharedBuffer> for each node - this is important to match the expected type
        let node_buffer = Arc::new(buffer.clone());
        let consensus = ByzantineConsensus::new(&node_id, node_buffer, config.clone())?;
        nodes.push((node_id, consensus));
    }
    
    // Simulate multiple consensus rounds
    for round in 1..=3 {
        info!("============= ROUND {} =============", round);
        
        // Use QKD-VRF to select leader for this round
        let (output, _, _) = qkd_vrf.generate_with_qkd(
            format!("round-{}", round).as_bytes(), 
            "consensus-demo",
        ).await?;
        
        // Map VRF output to leader index
        let leader_idx = output[0] as usize % nodes.len();
        let leader_id = &nodes[leader_idx].0;
        info!("QKD-VRF selected leader: {}", leader_id);
        
        // Primary node initiates consensus
        let value = format!("Consensus value for round {}", round).into_bytes();
        if let Err(e) = nodes[leader_idx].1.start_consensus(value) {
            info!("Leader failed to start consensus: {}", e);
            continue;
        }
        
        // Run consensus on all nodes
        let mut handles = Vec::new();
        for (node_id, consensus) in &nodes {
            let node_id = node_id.clone();
            let consensus = consensus.clone();
            
            let handle = tokio::spawn(async move {
                info!("Node {} participating in consensus", node_id);
                match consensus.run_consensus_round() {
                    Ok(result) => {
                        if result.success {
                            let value = String::from_utf8_lossy(&result.value.unwrap_or_default());
                            info!("✅ Node {} reached consensus: {}", node_id, value);
                        } else {
                            info!("❌ Node {} failed to reach consensus", node_id);
                        }
                        result.success
                    }
                    Err(e) => {
                        info!("❌ Node {} encountered error: {}", node_id, e);
                        false
                    }
                }
            });
            
            handles.push(handle);
        }
        
        // Wait for consensus round to complete
        let mut success_count = 0;
        for handle in handles {
            if handle.await.unwrap_or(false) {
                success_count += 1;
            }
        }
        
        info!("Round {} results: {}/{} nodes reached consensus", 
             round, success_count, nodes.len());
             
        // Wait before next round
        sleep(Duration::from_secs(2)).await;
    }
    
    info!("Byzantine consensus with QKD-VRF demo completed");
    Ok(())
}