use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

#[derive(Clone, Debug)]
pub struct ProofEntry {
    pub reporter_id: String,
    pub key_id: String, 
    pub proof: Vec<u8>,
    pub timestamp: u64,
}

pub struct SharedBuffer {
    buffer: Mutex<VecDeque<ProofEntry>>,
}

impl SharedBuffer {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            buffer: Mutex::new(VecDeque::new()),
        })
    }
    
    pub fn push(&self, entry: ProofEntry) {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.push_back(entry);
    }
    
    pub fn get_all(&self) -> Vec<ProofEntry> {
        let buffer = self.buffer.lock().unwrap();
        buffer.iter().cloned().collect()
    }
}
