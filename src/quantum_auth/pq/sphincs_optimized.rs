// src/quantum_auth/pq/sphincs_optimized.rs
use super::sphincs::SphincsAuth;
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};

pub struct CachedSphincs {
    inner: SphincsAuth,
    cache: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    max_cache_size: usize,
}

impl CachedSphincs {
    pub fn new(inner: SphincsAuth, max_cache_size: usize) -> Self {
        Self {
            inner,
            cache: Arc::new(Mutex::new(HashMap::new())),
            max_cache_size,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // Check cache first
        {
            let cache = self.cache.lock().unwrap();
            if let Some(signature) = cache.get(message) {
                return Ok(signature.clone());
            }
        }

        // Generate new signature if not in cache
        let signature = self.inner.sign(message)?;

        // Update cache
        {
            let mut cache = self.cache.lock().unwrap();
            // Implement cache eviction if needed
            if cache.len() >= self.max_cache_size {
                if let Some(oldest_key) = cache.keys().next().cloned() {
                    cache.remove(&oldest_key);
                }
            }
            cache.insert(message.to_vec(), signature.clone());
        }

        Ok(signature)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, Box<dyn Error>> {
        self.inner.verify(message, signature)
    }
}
