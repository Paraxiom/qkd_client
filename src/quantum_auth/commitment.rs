use ark_bn254::Fr;
use rand::RngCore;
use std::error::Error;
#[allow(dead_code)]
pub struct QuantumCommitment {
    value: [u8; 32],
    nonce: [u8; 32],
}

impl QuantumCommitment {
    #[allow(dead_code)]
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let mut value = [0u8; 32];
        let mut nonce = [0u8; 32];

        // Generate random nonce
        rand::thread_rng().fill_bytes(&mut nonce);

        Ok(Self { value, nonce })
    }
    #[allow(dead_code)]
    pub fn commit(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // Basic commitment for now - will enhance with quantum resistance
        self.value.copy_from_slice(&data[..32]);
        Ok(self.value.to_vec())
    }
}
