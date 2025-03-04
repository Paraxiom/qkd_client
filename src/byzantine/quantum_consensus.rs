// src/byzantine/quantum_consensus.rs
use crate::byzantine::buffer::{ConsensusMessage, MessageType, SharedBuffer};
use crate::byzantine::consensus::{ConsensusConfig, ConsensusResult};
use crate::quantum_auth::pq::{SphincsAuth, SphincsVariant};
use crate::quantum_auth::hybrid::HybridAuth;
use crate::vrf::core::QuantumVRF;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Byzantine consensus implementation with quantum resistance
/// - Uses SPHINCS+ for message authentication
/// - Uses quantum VRF for randomness and leader selection
/// - Supports post-quantum cryptographic upgrade
pub struct QuantumByzantineConsensus {
    node_id: String,
    buffer: Arc<SharedBuffer>,
    config: ConsensusConfig,
    state: Mutex<ConsensusState>,
    
    // Quantum-resistant authentication
    sphincs_auth: SphincsAuth,
    hybrid_auth: HybridAuth,
    
    // VRF for randomness
    vrf: Option<QuantumVRF>,
    
    // Protocol state
    view: Mutex<u64>,
    sequence: Mutex<u64>,
    prepared_msgs: Mutex<HashMap<u64, HashSet<String>>>,
    commit_msgs: Mutex<HashMap<u64, HashSet<String>>>,
    
    // Quantum key material
    quantum_key: Mutex<Vec<u8>>,
}

/// Byzantine agreement protocol state
#[derive(Debug)]
enum ConsensusState {
    Idle,
    PrePrepared(Vec<u8>),
    Prepared(Vec<u8>),
    Committed(Vec<u8>),
    ViewChange(u64),
}

impl QuantumByzantineConsensus {
    /// Create a new quantum-resistant Byzantine consensus instance
    pub fn new(
        node_id: &str,
        buffer: Arc<SharedBuffer>,
        config: ConsensusConfig,
        quantum_key: Vec<u8>,
    ) -> Result<Self, Box<dyn Error>> {
        // Initialize SPHINCS+ with 256-bit security for long-term quantum resistance
        let sphincs_auth = SphincsAuth::with_variant(SphincsVariant::Sha2256f)?;
        
        // Initialize hybrid authentication (classical + quantum)
        let hybrid_auth = HybridAuth::new()?;
        
        // Initialize VRF if quantum key is provided
        let vrf = if !quantum_key.is_empty() {
            Some(QuantumVRF::new(hybrid_auth.clone())?)
        } else {
            None
        };
        
        Ok(Self {
            node_id: node_id.to_string(),
            buffer,
            config,
            state: Mutex::new(ConsensusState::Idle),
            sphincs_auth,
            hybrid_auth,
            vrf,
            view: Mutex::new(0),
            sequence: Mutex::new(0),
            prepared_msgs: Mutex::new(HashMap::new()),
            commit_msgs: Mutex::new(HashMap::new()),
            quantum_key: Mutex::new(quantum_key),
        })
    }
    
    /// Start a consensus round as the primary node
    pub fn start_consensus(&self, value: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let view = *self.view.lock().unwrap();
        let mut sequence = self.sequence.lock().unwrap();
        *sequence += 1;
        let seq = *sequence;
        
        // Create pre-prepare message with quantum-resistant signature
        let pre_prepare = self.create_message(MessageType::PrePrepare, view, seq, value.clone())?;
        self.buffer.push_message(pre_prepare);
        
        // Update state
        let mut state = self.state.lock().unwrap();
        *state = ConsensusState::PrePrepared(value);
        
        Ok(())
    }
    
    /// Check if this node is the primary for the current view
    pub fn is_primary(&self) -> bool {
        let view = *self.view.lock().unwrap();
        self.get_primary_for_view(view) == self.node_id
    }
    
    /// Run a complete consensus round (for non-primary nodes)
    pub fn run_consensus_round(&self) -> Result<ConsensusResult, Box<dyn Error>> {
        let start_time = Instant::now();
        let mut result = ConsensusResult {
            success: false,
            value: None,
            reporter_ids: Vec::new(),
            round_duration: Duration::from_secs(0),
            round_number: *self.sequence.lock().unwrap(),
            total_messages: 0,
        };
        
        // Set initial state to Idle
        {
            let mut state = self.state.lock().unwrap();
            *state = ConsensusState::Idle;
        }
        
        // Current view
        let view = *self.view.lock().unwrap();
        
        // Process loop
        let round_start = Instant::now();
        while round_start.elapsed() < self.config.round_timeout {
            // Process all messages in the buffer
            self.process_messages()?;
            
            // Check if we've reached consensus
            {
                let state = self.state.lock().unwrap();
                if let ConsensusState::Committed(value) = &*state {
                    result.success = true;
                    result.value = Some(value.clone());
                    break;
                }
            }
            
            // Sleep to avoid busy waiting
            std::thread::sleep(Duration::from_millis(50));
        }
        
        // If consensus failed, trigger view change
        if !result.success {
            warn!("Consensus timed out, triggering quantum-secure view change");
            self.trigger_view_change(view)?;
        }
        
        // Collect final statistics
        result.round_duration = start_time.elapsed();
        result.total_messages = self.buffer.get_all_messages().len();
        
        // Add reporter IDs that participated
        let all_msgs = self.buffer.get_all_messages();
        let mut reporter_set = HashSet::new();
        for msg in all_msgs {
            reporter_set.insert(msg.sender_id.clone());
        }
        result.reporter_ids = reporter_set.into_iter().collect();
        
        Ok(result)
    }
    
    /// Process all messages in the buffer
    fn process_messages(&self) -> Result<(), Box<dyn Error>> {
        let view = *self.view.lock().unwrap();
        let sequence = *self.sequence.lock().unwrap();
        
        // Get all messages for current view and sequence
        let messages = self.buffer.get_all_messages();
        let relevant_msgs: Vec<_> = messages
            .iter()
            .filter(|m| m.view == view && m.sequence == sequence)
            .collect();
        
        // Verify quantum-resistant signatures before processing
        let valid_msgs: Vec<_> = relevant_msgs
            .iter()
            .filter(|m| self.verify_message_signature(m).unwrap_or(false))
            .collect();
        
        // Process by message type in order
        self.process_pre_prepare_messages(&valid_msgs)?;
        self.process_prepare_messages(&valid_msgs)?;
        self.process_commit_messages(&valid_msgs)?;
        
        Ok(())
    }
    
    /// Process PRE-PREPARE messages
    fn process_pre_prepare_messages(
        &self,
        messages: &[&&ConsensusMessage],
    ) -> Result<(), Box<dyn Error>> {
        let pre_prepare_msgs: Vec<_> = messages
            .iter()
            .filter(|m| m.msg_type == MessageType::PrePrepare)
            .collect();
        
        if pre_prepare_msgs.is_empty() {
            return Ok(());
        }
        
        // In Byzantine consensus, we should only accept one pre-prepare per view/sequence
        let primary = self.get_primary_for_view(pre_prepare_msgs[0].view);
        
        // Verify the pre-prepare is from the primary
        if pre_prepare_msgs[0].sender_id != primary {
            warn!("Received pre-prepare from non-primary node, ignoring");
            return Ok(());
        }
        
        let view = pre_prepare_msgs[0].view;
        let sequence = pre_prepare_msgs[0].sequence;
        let value = pre_prepare_msgs[0].content.clone();
        
        // Update state
        {
            let mut state = self.state.lock().unwrap();
            // Only move to pre-prepared state if we're idle
            if let ConsensusState::Idle = *state {
                *state = ConsensusState::PrePrepared(value.clone());
                
                // Send PREPARE message with quantum-resistant signature
                let prepare_msg =
                    self.create_message(MessageType::Prepare, view, sequence, value)?;
                self.buffer.push_message(prepare_msg);
            }
        }
        
        Ok(())
    }
    
    /// Process PREPARE messages
    fn process_prepare_messages(
        &self,
        messages: &[&&ConsensusMessage],
    ) -> Result<(), Box<dyn Error>> {
        let prepare_msgs: Vec<_> = messages
            .iter()
            .filter(|m| m.msg_type == MessageType::Prepare)
            .collect();
        
        if prepare_msgs.is_empty() {
            return Ok(());
        }
        
        // Group by content (value)
        let mut prepare_groups: HashMap<Vec<u8>, Vec<&&ConsensusMessage>> = HashMap::new();
        for msg in prepare_msgs {
            prepare_groups
                .entry(msg.content.clone())
                .or_insert_with(Vec::new)
                .push(msg);
        }
        
        // Check if we have enough prepare messages for any value
        for (value, msgs) in prepare_groups {
            // Track unique senders
            let mut senders = HashSet::new();
            for msg in msgs {
                senders.insert(msg.sender_id.clone());
            }
            
            // Check if we have 2f+1 prepare messages (including our own)
            let required_prepares = 2 * self.config.fault_tolerance + 1;
            
            // Update prepared count for this value
            {
                let mut prepared_msgs = self.prepared_msgs.lock().unwrap();
                let seq = messages[0].sequence;
                let entry = prepared_msgs.entry(seq).or_insert_with(HashSet::new);
                
                for sender in &senders {
                    entry.insert(sender.clone());
                }
                
                debug!(
                    "Prepare count for sequence {}: {}/{}",
                    seq,
                    entry.len(),
                    required_prepares
                );
                
                // If we have enough, move to prepared state
                if entry.len() >= required_prepares {
                    let mut state = self.state.lock().unwrap();
                    
                    // Only move to prepared if we're in pre-prepared or equivalent
                    if let ConsensusState::PrePrepared(_) = *state {
                        *state = ConsensusState::Prepared(value.clone());
                        
                        // Send COMMIT message with quantum-resistant signature
                        let view = messages[0].view;
                        let commit_msg =
                            self.create_message(MessageType::Commit, view, seq, value)?;
                        self.buffer.push_message(commit_msg);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Process COMMIT messages
    fn process_commit_messages(
        &self,
        messages: &[&&ConsensusMessage],
    ) -> Result<(), Box<dyn Error>> {
        let commit_msgs: Vec<_> = messages
            .iter()
            .filter(|m| m.msg_type == MessageType::Commit)
            .collect();
        
        if commit_msgs.is_empty() {
            return Ok(());
        }
        
        // Group by content (value)
        let mut commit_groups: HashMap<Vec<u8>, Vec<&&ConsensusMessage>> = HashMap::new();
        for msg in commit_msgs {
            commit_groups
                .entry(msg.content.clone())
                .or_insert_with(Vec::new)
                .push(msg);
        }
        
        // Check if we have enough commit messages for any value
        for (value, msgs) in commit_groups {
            // Track unique senders
            let mut senders = HashSet::new();
            for msg in msgs {
                senders.insert(msg.sender_id.clone());
            }
            
            // Check if we have 2f+1 commit messages (including our own)
            let required_commits = 2 * self.config.fault_tolerance + 1;
            
            // Update commit count for this value
            {
                let mut commit_msgs = self.commit_msgs.lock().unwrap();
                let seq = messages[0].sequence;
                let entry = commit_msgs.entry(seq).or_insert_with(HashSet::new);
                
                for sender in &senders {
                    entry.insert(sender.clone());
                }
                
                debug!(
                    "Commit count for sequence {}: {}/{}",
                    seq,
                    entry.len(),
                    required_commits
                );
                
                // If we have enough, move to committed state
                if entry.len() >= required_commits {
                    let mut state = self.state.lock().unwrap();
                    
                    // Only move to committed if we're prepared or equivalent
                    if let ConsensusState::Prepared(_) = *state {
                        *state = ConsensusState::Committed(value.clone());
                        info!("Quantum-resistant consensus achieved for sequence {}", seq);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Trigger a view change due to timeout or failure
    fn trigger_view_change(&self, old_view: u64) -> Result<(), Box<dyn Error>> {
        // Use VRF for unpredictable but verifiable view number generation
        let new_view = if let Some(vrf) = &self.vrf {
            // Generate new view using quantum VRF
            let input = format!("view-change-{}", old_view).as_bytes().to_vec();
            let quantum_key = self.quantum_key.lock().unwrap().clone();
            
            let (output, _) = vrf.generate(&input, &quantum_key)?;
            
            // Extract a u64 from the VRF output
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&output[0..8]);
            let random_value = u64::from_le_bytes(bytes);
            
            // Ensure new view is greater than old view
            old_view + 1 + (random_value % 10) // Add random offset of 1-10
        } else {
            // Fallback to simple increment if VRF is not available
            old_view + 1
        };
        
        // Update view number
        {
            let mut view = self.view.lock().unwrap();
            *view = new_view;
            info!("Quantum-secure view change: {} -> {}", old_view, new_view);
        }
        
        // Create view change message with quantum-resistant signature
        let sequence = *self.sequence.lock().unwrap();
        let view_change_msg =
            self.create_message(MessageType::ViewChange, new_view, sequence, Vec::new())?;
        self.buffer.push_message(view_change_msg);
        
        // Update state
        {
            let mut state = self.state.lock().unwrap();
            *state = ConsensusState::ViewChange(new_view);
        }
        
        Ok(())
    }
    
    /// Create a signed consensus message using quantum-resistant signature
    fn create_message(
        &self,
        msg_type: MessageType,
        view: u64,
        sequence: u64,
        content: Vec<u8>,
    ) -> Result<ConsensusMessage, Box<dyn Error>> {
        // Create message without signature
        let msg = ConsensusMessage {
            sender_id: self.node_id.clone(),
            msg_type,
            view,
            sequence,
            content,
            signature: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        
        // Convert message to bytes for signing
        let msg_bytes = bincode::serialize(&msg)?;
        
        // Sign message using SPHINCS+ for quantum resistance
        let signature = self.sphincs_auth.sign(&msg_bytes)?;
        
        // Create final message with quantum-resistant signature
        Ok(ConsensusMessage {
            sender_id: self.node_id.clone(),
            msg_type: msg.msg_type,
            view,
            sequence,
            content: msg.content,
            signature,
            timestamp: msg.timestamp,
        })
    }
    
    /// Verify a message signature using quantum-resistant verification
    fn verify_message_signature(&self, message: &ConsensusMessage) -> Result<bool, Box<dyn Error>> {
        // Create a copy of the message without signature for verification
        let message_to_verify = ConsensusMessage {
            sender_id: message.sender_id.clone(),
            msg_type: message.msg_type,
            view: message.view,
            sequence: message.sequence,
            content: message.content.clone(),
            signature: Vec::new(),
            timestamp: message.timestamp,
        };
        
        // Serialize the message without signature
        let msg_bytes = bincode::serialize(&message_to_verify)?;
        
        // Verify the signature using SPHINCS+
        // In a real system, you would need to retrieve the sender's public key
        // For simplicity, we're using our own key here
        self.sphincs_auth.verify(&msg_bytes, &message.signature)
    }
    
    /// Get the primary node ID for a given view
    fn get_primary_for_view(&self, view: u64) -> String {
        // If we have VRF, use it for deterministic but unpredictable selection
        if let Some(vrf) = &self.vrf {
            let input = format!("primary-selection-view-{}", view).as_bytes().to_vec();
            
            // Use a protocol-wide shared secret as the quantum key for this operation
            // to ensure all nodes get the same result
            let quantum_key = self.quantum_key.lock().unwrap().clone();
            
            match vrf.generate(&input, &quantum_key) {
                Ok((output, _)) => {
                    // Extract a value from the output for selection
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&output[0..8]);
                    let random_value = u64::from_le_bytes(bytes);
                    
                    // Use random value to select a node
                    let primary_idx = (random_value as usize) % self.config.node_count;
                    format!("node{}", primary_idx)
                }
                Err(_) => {
                    // Fallback to simple round-robin on VRF failure
                    let primary_idx = (view as usize) % self.config.node_count;
                    format!("node{}", primary_idx)
                }
            }
        } else {
            // Simple round-robin primary selection if VRF is not available
            let primary_idx = (view as usize) % self.config.node_count;
            format!("node{}", primary_idx)
        }
    }
    
    /// Update the quantum key material (e.g., when new QKD key is available)
    pub fn update_quantum_key(&self, new_key: Vec<u8>) {
        let mut key = self.quantum_key.lock().unwrap();
        *key = new_key;
        debug!("Updated quantum key material ({} bytes)", key.len());
    }
    
    /// Get consensus statistics
    pub fn get_statistics(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        
        // Add current protocol state
        {
            let view = *self.view.lock().unwrap();
            let sequence = *self.sequence.lock().unwrap();
            stats.insert("current_view".to_string(), view as usize);
            stats.insert("current_sequence".to_string(), sequence as usize);
        }
        
        // Add message counts
        let messages = self.buffer.get_all_messages();
        stats.insert("total_messages".to_string(), messages.len());
        
        let prepare_count = messages.iter().filter(|m| m.msg_type == MessageType::Prepare).count();
        let commit_count = messages.iter().filter(|m| m.msg_type == MessageType::Commit).count();
        let view_change_count = messages.iter().filter(|m| m.msg_type == MessageType::ViewChange).count();
        
        stats.insert("prepare_messages".to_string(), prepare_count);
        stats.insert("commit_messages".to_string(), commit_count);
        stats.insert("view_change_messages".to_string(), view_change_count);
        
        stats
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_quantum_primary_selection() -> Result<(), Box<dyn Error>> {
        // Create a hybrid auth for testing
        let hybrid_auth = HybridAuth::new()?;
        
        // Create VRF
        let vrf = QuantumVRF::new(hybrid_auth)?;
        
        // Create a shared buffer
        let buffer = Arc::new(SharedBuffer::new(100));
        
        // Create consensus config
        let config = ConsensusConfig {
            node_count: 4,
            fault_tolerance: 1, // f=1, so 3f+1=4 nodes
            ..Default::default()
        };
        
        // Create quantum key for testing
        let quantum_key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        
        // Create the quantum consensus
        let consensus = QuantumByzantineConsensus::new(
            "node0",
            buffer,
            config,
            quantum_key,
        )?;
        
        // Test primary selection for different views
        let primary1 = consensus.get_primary_for_view(0);
        let primary2 = consensus.get_primary_for_view(1);
        
        // Primaries should be determined by the VRF in a deterministic but unpredictable way
        assert!(primary1.starts_with("node"));
        assert!(primary2.starts_with("node"));
        
        // Primary should not always be the same for different views
        // (There's a small chance they could be the same by random selection)
        
        Ok(())
    }
}