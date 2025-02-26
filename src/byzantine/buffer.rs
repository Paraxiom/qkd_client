// src/byzantine/buffer.rs
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Message types for Byzantine consensus
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MessageType {
    Proposal,
    PrePrepare,
    Prepare,
    Commit,
    ViewChange,
}

/// A message in the Byzantine consensus protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusMessage {
    pub sender_id: String,
    pub msg_type: MessageType,
    pub view: u64,
    pub sequence: u64,
    pub content: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

/// A report from a reporter node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReporterEntry {
    pub reporter_id: String,
    pub key_id: String,
    pub key_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

/// Statistics about the shared buffer
#[derive(Debug, Clone, Default)]
pub struct BufferStats {
    pub total_messages: usize,
    pub messages_by_type: HashMap<MessageType, usize>,
    pub oldest_message_age: Option<Duration>,
    pub newest_message_age: Option<Duration>,
}

/// Thread-safe shared buffer for Byzantine consensus communication
pub struct SharedBuffer {
    // Buffer of consensus messages with read-write lock for concurrent access
    messages: RwLock<VecDeque<ConsensusMessage>>,

    // Collection of reporter entries (the actual quantum key reports)
    reports: RwLock<Vec<ReporterEntry>>,

    // Capacity limit for the message buffer
    capacity: usize,

    // Creation time for age calculations
    created_at: Instant,
}

impl SharedBuffer {
    /// Create a new shared buffer with the specified capacity
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            messages: RwLock::new(VecDeque::with_capacity(capacity)),
            reports: RwLock::new(Vec::new()),
            capacity,
            created_at: Instant::now(),
        })
    }

    /// Add a consensus message to the buffer
    pub fn push_message(&self, message: ConsensusMessage) -> bool {
        let mut messages = self.messages.write().unwrap();

        // Check if buffer is full
        if messages.len() >= self.capacity {
            warn!("Message buffer full, dropping oldest message");
            messages.pop_front(); // Drop oldest message
        }

        // Add new message
        messages.push_back(message);
        debug!(
            "Added message to buffer, current size: {}/{}",
            messages.len(),
            self.capacity
        );

        true
    }

    /// Add a reporter entry to the collection
    pub fn add_report(&self, report: ReporterEntry) {
        let mut reports = self.reports.write().unwrap();
        reports.push(report);
        debug!("Added reporter entry, total reports: {}", reports.len());
    }

    /// Get all consensus messages
    pub fn get_all_messages(&self) -> Vec<ConsensusMessage> {
        let messages = self.messages.read().unwrap();
        messages.iter().cloned().collect()
    }

    /// Get messages of a specific type
    pub fn get_messages_by_type(&self, msg_type: MessageType) -> Vec<ConsensusMessage> {
        let messages = self.messages.read().unwrap();
        messages
            .iter()
            .filter(|m| m.msg_type == msg_type)
            .cloned()
            .collect()
    }

    /// Get messages from a specific view
    pub fn get_messages_by_view(&self, view: u64) -> Vec<ConsensusMessage> {
        let messages = self.messages.read().unwrap();
        messages
            .iter()
            .filter(|m| m.view == view)
            .cloned()
            .collect()
    }

    /// Get all reporter entries
    pub fn get_all_reports(&self) -> Vec<ReporterEntry> {
        let reports = self.reports.read().unwrap();
        reports.clone()
    }

    /// Get reporter entries for a specific reporter
    pub fn get_reports_by_reporter(&self, reporter_id: &str) -> Vec<ReporterEntry> {
        let reports = self.reports.read().unwrap();
        reports
            .iter()
            .filter(|r| r.reporter_id == reporter_id)
            .cloned()
            .collect()
    }

    /// Clear old messages (older than the specified duration)
    pub fn clear_old_messages(&self, max_age: Duration) -> usize {
        let now = Instant::now();
        let buffer_age = now.duration_since(self.created_at);

        let mut messages = self.messages.write().unwrap();
        let initial_count = messages.len();

        // Remove messages older than max_age
        messages.retain(|msg| {
            let msg_age = Duration::from_secs(buffer_age.as_secs().saturating_sub(msg.timestamp));
            msg_age <= max_age
        });

        let removed = initial_count - messages.len();
        if removed > 0 {
            debug!("Removed {} old messages", removed);
        }

        removed
    }

    /// Get statistics about the buffer
    pub fn get_stats(&self) -> BufferStats {
        let messages = self.messages.read().unwrap();
        let now = Instant::now();
        let buffer_age = now.duration_since(self.created_at);

        let mut stats = BufferStats::default();
        stats.total_messages = messages.len();

        let mut oldest = None;
        let mut newest = None;

        for msg in messages.iter() {
            // Count by message type
            let count = stats
                .messages_by_type
                .entry(msg.msg_type.clone())
                .or_insert(0);
            *count += 1;

            // Calculate age
            let age = Duration::from_secs(buffer_age.as_secs().saturating_sub(msg.timestamp));

            // Track oldest/newest
            if oldest.is_none() || oldest.unwrap() < age {
                oldest = Some(age);
            }
            if newest.is_none() || newest.unwrap() > age {
                newest = Some(age);
            }
        }

        stats.oldest_message_age = oldest;
        stats.newest_message_age = newest;

        stats
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn create_test_message(
        sender: &str,
        msg_type: MessageType,
        view: u64,
        seq: u64,
    ) -> ConsensusMessage {
        ConsensusMessage {
            sender_id: sender.to_string(),
            msg_type,
            view,
            sequence: seq,
            content: vec![1, 2, 3, 4],
            signature: vec![5, 6, 7, 8],
            timestamp: 100,
        }
    }

    #[test]
    fn test_push_and_get_messages() {
        let buffer = SharedBuffer::new(10);

        // Add messages
        let msg1 = create_test_message("node1", MessageType::Prepare, 1, 1);
        let msg2 = create_test_message("node2", MessageType::Commit, 1, 1);

        buffer.push_message(msg1.clone());
        buffer.push_message(msg2.clone());

        // Check all messages
        let messages = buffer.get_all_messages();
        assert_eq!(messages.len(), 2);

        // Check by type
        let prepare_msgs = buffer.get_messages_by_type(MessageType::Prepare);
        assert_eq!(prepare_msgs.len(), 1);
        assert_eq!(prepare_msgs[0].sender_id, "node1");

        let commit_msgs = buffer.get_messages_by_type(MessageType::Commit);
        assert_eq!(commit_msgs.len(), 1);
        assert_eq!(commit_msgs[0].sender_id, "node2");
    }

    #[test]
    fn test_capacity_limit() {
        let capacity = 5;
        let buffer = SharedBuffer::new(capacity);

        // Fill buffer beyond capacity
        for i in 0..capacity + 3 {
            let msg = create_test_message(&format!("node{}", i), MessageType::Prepare, 1, i as u64);
            buffer.push_message(msg);
        }

        // Check that only capacity messages remain
        let messages = buffer.get_all_messages();
        assert_eq!(messages.len(), capacity);

        // Check that oldest messages were dropped
        let first_sender = &messages[0].sender_id;
        assert_eq!(first_sender, "node3"); // node0, node1, node2 were dropped
    }

    #[test]
    fn test_concurrent_access() {
        let buffer = Arc::new(SharedBuffer::new(100));
        let mut handles = vec![];

        // Spawn 10 threads, each adding 10 messages
        for t in 0..10 {
            let buffer_clone = Arc::clone(&buffer);

            let handle = thread::spawn(move || {
                for i in 0..10 {
                    let msg = create_test_message(
                        &format!("thread{}-msg{}", t, i),
                        MessageType::Prepare,
                        1,
                        (t * 10 + i) as u64,
                    );
                    buffer_clone.push_message(msg);
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to finish
        for handle in handles {
            handle.join().unwrap();
        }

        // Check that all 100 messages were added
        let messages = buffer.get_all_messages();
        assert_eq!(messages.len(), 100);
    }
}
