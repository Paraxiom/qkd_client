// src/reporter/key_proof.rs
use crate::zk::KeyProof;
use std::error::Error;

pub struct ProofGenerator {}

impl ProofGenerator {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self {})
    }

    pub async fn generate_proof(&self, key: &[u8]) -> Result<KeyProof, Box<dyn Error>> {
        KeyProof::new(&base64::encode(key)).await
    }
}
