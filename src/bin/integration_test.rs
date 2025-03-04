// src/bin/integration_test.rs
//! Integration test for the QKD client system
//! This demonstrates the full workflow:
//! 1. QKD key retrieval
//! 2. VRF randomness generation
//! 3. Byzantine consensus with quantum resistance
//! 4. End-to-end verification

use qkd_client::qkd::etsi_api::{DeviceType, ETSIClient, Side};
use qkd_client::vrf::integrated_vrf::IntegratedVRF;
use qkd_client::quantum_auth::hybrid::HybridAuth;
use qkd_client::byzantine::{SharedBuffer, ConsensusConfig};
// Using the regular Byzantine consensus
use qkd_client::byzantine::consensus::ByzantineConsensus;

use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{info, debug, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    info!("Starting QKD client integration test");
    let start = Instant::now();

    // Step 1: Initialize QKD client with simulated device
    info!("Initializing QKD client with simulated device");
    
    // Using a path that doesn't need to exist for simulated devices
    let cert_path = PathBuf::from("dummy.pem");
    
    let alice_client = ETSIClient::new(
        DeviceType::Simulated,
        Side::Alice,
        &cert_path,
        None,
    )?;
    
    let bob_client = ETSIClient::new(
        DeviceType::Simulated,
        Side::Bob,
        &cert_path,
        None,
    )?;

    // Step 2: Retrieve quantum keys
    info!("Retrieving quantum keys from QKD device");
    let key_size = 32; // 256 bits
    let dest_id = "integration-test";
    let alice_key = alice_client.get_key_alice(key_size, dest_id, None).await?;
    
    info!("Retrieved key: {} ({} bytes)", alice_key.key_id, alice_key.metadata.key_size);
    debug!("Key metadata: QBER = {}", alice_key.metadata.qber);
    
    // Step 3: Initialize VRF with the quantum key
    info!("Initializing quantum-resistant VRF");
    let hybrid_auth = HybridAuth::new()?;
    let vrf = IntegratedVRF::new(hybrid_auth);
    
    // Step 4: Generate randomness using VRF and quantum key
    info!("Generating randomness using VRF with quantum key");
    let input = b"integration-test-input";
    let vrf_response = vrf.generate_with_proof(input, &alice_key.key_bytes)?;
    
    info!("Generated randomness: {} bytes of output, {} bytes of proof",
        vrf_response.output.len(),
        vrf_response.vrf_proof.len());
    
    // Step 5: Verify the VRF output
    info!("Verifying VRF output");
    let bob_key = bob_client.get_key_bob(&alice_key.key_id).await?;
    let vrf_valid = vrf.verify_with_proof(input, &vrf_response, &bob_key.key_bytes)?;
    
    if vrf_valid {
        info!("✅ VRF verification successful");
    } else {
        error!("❌ VRF verification failed");
        return Err("VRF verification failed".into());
    }
    
    // Step 6: Setup Byzantine consensus
    info!("Setting up Byzantine consensus");
    let buffer = Arc::new(SharedBuffer::new(100));
    
    let config = ConsensusConfig {
        node_count: 4,
        fault_tolerance: 1, // can tolerate 1 faulty node
        view_timeout: Duration::from_secs(5),
        round_timeout: Duration::from_secs(10),
        max_rounds: 3,
    };
    
    // Create consensus nodes
    let mut nodes = Vec::new();
    let consensus_value = b"Consensus test value".to_vec();
    
    for i in 0..config.node_count {
        let node_id = format!("node{}", i);
        
        // Use regular ByzantineConsensus
        let consensus = ByzantineConsensus::new(
            &node_id,
            Arc::clone(&buffer),
            config.clone(),
        )?;
        
        nodes.push((node_id, consensus));
    }
    
    // Step 7: Run consensus round
    info!("Starting consensus round with {} nodes", nodes.len());
    
    // Primary node starts the consensus
    let primary_node = &nodes[0].1;
    if !primary_node.is_primary() {
        warn!("Expected node0 to be primary, but it's not");
    }
    primary_node.start_consensus(consensus_value.clone())?;
    
    // src/bin/integration_test.rs (continued)
    // Other nodes participate in consensus
    for (node_id, node) in nodes.iter().skip(1) {
        info!("Node {} participating in consensus", node_id);
        let result = node.run_consensus_round()?;
        
        if result.success {
            info!("✅ Node {} reached consensus", node_id);
            assert_eq!(result.value.unwrap(), consensus_value);
        } else {
            error!("❌ Node {} failed to reach consensus", node_id);
            return Err(format!("Node {} failed to reach consensus", node_id).into());
        }
    }
    
    // Step 8: Clean up - mark the key as consumed
    info!("Cleaning up - marking key as consumed");
    alice_client.delete_key(&alice_key.key_id).await?;
    
    info!("✅ Integration test completed successfully in {:?}", start.elapsed());
    Ok(())
}
    