use crate::vrf::integrated::IntegratedVRF;
use crate::vrf::integrated::VRFResponse;
use std::error::Error;
use tracing::{debug, info, warn};

/// Byzantine consensus implementation that uses VRF for leader selection
///
/// This implementation provides unpredictable but verifiable leader selection
/// for Byzantine fault-tolerant systems using quantum-resistant VRF.
pub struct VRFBasedConsensus {
    vrf: IntegratedVRF,
    node_id: u64,
    quantum_key: Vec<u8>,
}

impl VRFBasedConsensus {
    /// Create a new VRF-based consensus node
    pub fn new(vrf: IntegratedVRF, node_id: u64, quantum_key: Vec<u8>) -> Self {
        Self {
            vrf,
            node_id,
            quantum_key,
        }
    }

    /// Select a leader for the current round
    ///
    /// This uses the VRF to generate an unpredictable but verifiable leader selection
    pub fn select_leader(&self, round: u64, participants: &[u64]) -> Result<u64, Box<dyn Error>> {
        debug!("Node {} selecting leader for round {}", self.node_id, round);

        if participants.is_empty() {
            return Err("Cannot select leader: participant list is empty".into());
        }

        // Combine round number with protocol context to prevent replay
        let input = format!("leader-selection-round-{}", round)
            .as_bytes()
            .to_vec();

        // Generate VRF output using the node's quantum key
        let start = std::time::Instant::now();
        let response = self.vrf.generate_with_proof(&input, &self.quantum_key)?;
        debug!("Generated VRF output in {:?}", start.elapsed());

        // Use the VRF output to select a leader from participants
        let leader_index = self.output_to_index(&response.output, participants.len())?;
        let selected_leader = participants[leader_index];

        info!(
            "Node {} selected leader {} for round {}",
            self.node_id, selected_leader, round
        );

        Ok(selected_leader)
    }

    /// Verify another node's leader selection
    pub fn verify_leader_selection(
        &self,
        round: u64,
        participants: &[u64],
        claimed_leader: u64,
        vrf_output: &[u8],
        vrf_proof: &[u8],
        public_key: &[u8],
    ) -> Result<bool, Box<dyn Error>> {
        debug!("Verifying leader selection for round {}", round);

        if participants.is_empty() {
            return Err("Cannot verify: participant list is empty".into());
        }

        // Recreate the input
        let input = format!("leader-selection-round-{}", round)
            .as_bytes()
            .to_vec();

        // Verify the VRF output
        let response = VRFResponse {
            output: vrf_output.to_vec(),
            vrf_proof: vrf_proof.to_vec(),
            zk_proof: serde_json::Value::String(String::new()),
            public_inputs: serde_json::json!({}), // Empty JSON object for public inputs
        };
        let start = std::time::Instant::now();
        let vrf_valid = self.vrf.verify_with_proof(&input, &response, public_key)?;

        if !vrf_valid {
            warn!(
                "VRF verification failed for leader selection in round {}",
                round
            );
            return Ok(false);
        }
        debug!("VRF output verified in {:?}", start.elapsed());

        // Check if the leader computation matches
        let leader_index = self.output_to_index(vrf_output, participants.len())?;
        let expected_leader = participants[leader_index];

        let valid = expected_leader == claimed_leader;
        if !valid {
            warn!(
                "Leader mismatch: expected {}, claimed {}",
                expected_leader, claimed_leader
            );
        }

        info!(
            "Leader selection verification result: {}",
            if valid { "valid" } else { "invalid" }
        );
        Ok(valid)
    }

    /// Convert VRF output bytes to an index in the participants array
    fn output_to_index(
        &self,
        output: &[u8],
        participant_count: usize,
    ) -> Result<usize, Box<dyn Error>> {
        if output.len() < 8 {
            return Err("VRF output too short, need at least 8 bytes".into());
        }

        // Take first 8 bytes and interpret as u64
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&output[0..8]);
        let random_value = u64::from_le_bytes(bytes);

        // Map random value to participant index
        let index = (random_value % participant_count as u64) as usize;
        debug!(
            "Mapped VRF output to index {} (from random value {})",
            index, random_value
        );

        Ok(index)
    }

    /// Get the node's ID
    pub fn get_node_id(&self) -> u64 {
        self.node_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quantum_auth::hybrid::HybridAuth;

    #[test]
    fn test_leader_selection() -> Result<(), Box<dyn Error>> {
        // Initialize components
        let auth = HybridAuth::new()?;
        let vrf = IntegratedVRF::new(auth);
        let quantum_key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let consensus = VRFBasedConsensus::new(vrf.expect("Failed to create IntegratedVRF"), 1, quantum_key);

        // Test participants
        let participants = vec![10, 20, 30, 40, 50];

        // Select leader for a round
        let leader = consensus.select_leader(1, &participants)?;

        // Verify the leader is one of the participants
        assert!(
            participants.contains(&leader),
            "Selected leader should be in participants list"
        );

        Ok(())
    }
}
