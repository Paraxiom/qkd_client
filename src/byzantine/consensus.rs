// src/byzantine/consensus.rs
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::byzantine::buffer::{ConsensusMessage, MessageType, ReporterEntry, SharedBuffer};
use crate::quantum_auth::hybrid::HybridAuth;
use crate::quantum_auth::pq::SphincsAuth;

/// Result of a Byzantine consensus round
#[derive(Debug, Clone)]
pub struct ConsensusResult {
    pub success: bool,
    pub value: Option<Vec<u8>>,
    pub reporter_ids: Vec<String>,
    pub round_duration: Duration,
    pub round_number: u64,
    pub total_messages: usize,
}

/// Configuration for Byzantine consensus
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    pub node_count: usize,
    pub fault_tolerance: usize,
    pub view_timeout: Duration,
    pub round_timeout: Duration,
    pub max_rounds: usize,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            node_count: 4,
            fault_tolerance: 1, // Can tolerate 1 faulty node (3f+1 = 4)
            view_timeout: Duration::from_secs(10),
            round_timeout: Duration::from_secs(30),
            max_rounds: 5,
        }
    }
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

/// Byzantine consensus protocol implementation
pub struct ByzantineConsensus {
    node_id: String,
    buffer: Arc<SharedBuffer>,
    config: ConsensusConfig,
    state: Mutex<ConsensusState>,
    auth: HybridAuth,
    view: Mutex<u64>,
    sequence: Mutex<u64>,
    prepared_msgs: Mutex<HashMap<u64, HashSet<String>>>,
    commit_msgs: Mutex<HashMap<u64, HashSet<String>>>,
}

// src/byzantine/consensus.rs
// Add this impl block near the end of the file, before the tests

// Make ByzantineConsensus cloneable for the simulator
impl Clone for ByzantineConsensus {
    fn clone(&self) -> Self {
        // This is a simplified clone implementation for the simulator
        // In a real implementation, you would properly clone all fields
        let view = *self.view.lock().unwrap();
        let sequence = *self.sequence.lock().unwrap();

        // Create a new instance with the same configuration
        let consensus = Self::new(&self.node_id, Arc::clone(&self.buffer), self.config.clone())
            .unwrap_or_else(|_| panic!("Failed to clone consensus instance"));

        // Set the view and sequence to match the original
        *consensus.view.lock().unwrap() = view;
        *consensus.sequence.lock().unwrap() = sequence;

        consensus
    }
}

impl ByzantineConsensus {
    /// Create a new Byzantine consensus instance
    pub fn new(
        node_id: &str,
        buffer: Arc<SharedBuffer>,
        config: ConsensusConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Create hybrid authentication for message signing
        let auth = HybridAuth::new()?;

        Ok(Self {
            node_id: node_id.to_string(),
            buffer,
            config,
            state: Mutex::new(ConsensusState::Idle),
            auth,
            view: Mutex::new(0),
            sequence: Mutex::new(0),
            prepared_msgs: Mutex::new(HashMap::new()),
            commit_msgs: Mutex::new(HashMap::new()),
        })
    }

    /// Start a consensus round as the primary node
    pub fn start_consensus(&self, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let view = *self.view.lock().unwrap();
        let mut sequence = self.sequence.lock().unwrap();
        *sequence += 1;
        let seq = *sequence;

        // Create pre-prepare message
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
    pub fn run_consensus_round(&self) -> Result<ConsensusResult, Box<dyn std::error::Error>> {
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
            warn!("Consensus timed out, triggering view change");
            self.trigger_view_change(view)?;
        }

        // Collect final statistics
        result.round_duration = start_time.elapsed();
        result.total_messages = self.buffer.get_all_messages().len();

        // Add reporter IDs that participated
        let all_msgs = self.buffer.get_all_messages();
        let mut reporter_set = HashSet::new();
        for msg in all_msgs {
            reporter_set.insert(msg.sender_id);
        }
        result.reporter_ids = reporter_set.into_iter().collect();

        Ok(result)
    }

    /// Process all messages in the buffer
    fn process_messages(&self) -> Result<(), Box<dyn std::error::Error>> {
        let view = *self.view.lock().unwrap();
        let sequence = *self.sequence.lock().unwrap();

        // Get all messages for current view and sequence
        let messages = self.buffer.get_all_messages();
        let relevant_msgs: Vec<_> = messages
            .iter()
            .filter(|m| m.view == view && m.sequence == sequence)
            .collect();

        // Process by message type in order
        self.process_pre_prepare_messages(&relevant_msgs)?;
        self.process_prepare_messages(&relevant_msgs)?;
        self.process_commit_messages(&relevant_msgs)?;

        Ok(())
    }

    /// Process PRE-PREPARE messages
    fn process_pre_prepare_messages(
        &self,
        messages: &[&ConsensusMessage],
    ) -> Result<(), Box<dyn std::error::Error>> {
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

                // Send PREPARE message
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
        messages: &[&ConsensusMessage],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let prepare_msgs: Vec<_> = messages
            .iter()
            .filter(|m| m.msg_type == MessageType::Prepare)
            .collect();

        if prepare_msgs.is_empty() {
            return Ok(());
        }

        // Group by content (value)
        let mut prepare_groups: HashMap<Vec<u8>, Vec<&ConsensusMessage>> = HashMap::new();
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

                        // Send COMMIT message
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
        messages: &[&ConsensusMessage],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let commit_msgs: Vec<_> = messages
            .iter()
            .filter(|m| m.msg_type == MessageType::Commit)
            .collect();

        if commit_msgs.is_empty() {
            return Ok(());
        }

        // Group by content (value)
        let mut commit_groups: HashMap<Vec<u8>, Vec<&ConsensusMessage>> = HashMap::new();
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
                        info!("Consensus achieved for sequence {}", seq);
                    }
                }
            }
        }

        Ok(())
    }

    /// Trigger a view change due to timeout or failure
    fn trigger_view_change(&self, old_view: u64) -> Result<(), Box<dyn std::error::Error>> {
        // Increment view number
        {
            let mut view = self.view.lock().unwrap();
            *view = old_view + 1;
            info!("View change: {} -> {}", old_view, *view);
        }

        // Create view change message
        let new_view = old_view + 1;
        let sequence = *self.sequence.lock().unwrap();

        // Send VIEW-CHANGE message
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

    /// Create a signed consensus message
    fn create_message(
        &self,
        msg_type: MessageType,
        view: u64,
        sequence: u64,
        content: Vec<u8>,
    ) -> Result<ConsensusMessage, Box<dyn std::error::Error>> {
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

        // Sign message using hybrid authentication
        let signature = self.auth.sign(&msg_bytes)?;

        // Create final message with signature
        Ok(ConsensusMessage {
            sender_id: self.node_id.clone(),
            msg_type: msg.msg_type,
            view,
            sequence,
            content: msg.content,
            signature: bincode::serialize(&signature)?,
            timestamp: msg.timestamp,
        })
    }

    /// Get the primary node ID for a given view
    fn get_primary_for_view(&self, view: u64) -> String {
        // Simple round-robin primary selection
        let primary_idx = (view as usize) % self.config.node_count;
        format!("node{}", primary_idx)
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primary_selection() {
        let buffer = SharedBuffer::new(100);
        let config = ConsensusConfig {
            node_count: 4,
            fault_tolerance: 1,
            ..Default::default()
        };

        let consensus = ByzantineConsensus::new("node0", buffer, config).unwrap();

        // Check primary for different views
        assert_eq!(consensus.get_primary_for_view(0), "node0");
        assert_eq!(consensus.get_primary_for_view(1), "node1");
        assert_eq!(consensus.get_primary_for_view(2), "node2");
        assert_eq!(consensus.get_primary_for_view(3), "node3");
        assert_eq!(consensus.get_primary_for_view(4), "node0"); // wraps around
    }

    // Additional tests would be added to verify consensus protocol
    // These would typically be integration tests with multiple nodes
}
