// src/byzantine/vrf_consensus.rs
use crate::vrf::integrated::IntegratedVRF;
use crate::vrf::integrated::VRFResponse;
use std::error::Error;

pub struct VRFBasedConsensus {
    pub(crate) vrf: IntegratedVRF, // Make accessible to methods but private externally
    node_id: u64,
    quantum_key: Vec<u8>,
}

impl VRFBasedConsensus {
    pub fn new(vrf: IntegratedVRF, node_id: u64, quantum_key: Vec<u8>) -> Self {
        Self { vrf, node_id, quantum_key }
    }
    
    pub fn select_leader(&self, round: u64, participants: &[u64]) -> Result<u64, Box<dyn Error>> {
        // Use VRF to generate unpredictable but verifiable randomness
        let input = format!("leader-{}", round).as_bytes().to_vec();
        let response = self.vrf.generate_with_proof(&input, &self.quantum_key)?;
        
        // Use the VRF output to select a leader from participants
        if participants.is_empty() {
            return Err("Participants list cannot be empty".into());
        }
        
        // Take the first 8 bytes of the output and convert to a u64
        let random_bytes = if response.output.len() >= 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&response.output[0..8]);
            bytes
        } else {
            return Err("VRF output too short".into());
        };
        
        let random_value = u64::from_le_bytes(random_bytes);
        let leader_index = random_value % participants.len() as u64;
        
        Ok(participants[leader_index as usize])
    }
}
