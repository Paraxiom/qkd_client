// src/lib.rs
pub mod byzantine;
pub mod qkd;
pub mod quantum_auth;
pub mod reporter;
pub mod vrf;
pub mod zk;

// Re-export QKDClient so it appears at crate root
pub use crate::reporter::QKDClient;

pub fn get_quantum_random_bytes(num_bytes: usize) -> Result<Vec<u8>, String> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Failed to create tokio runtime: {e}"))?;
    rt.block_on(async move {
        // now this will work:
        let client = crate::QKDClient::new()
            .map_err(|e| format!("QKDClient creation error: {e}"))?;
        // ...
        Ok(vec![])
    })
}
