// src/quantum_auth/mod.rs
mod authenticator;
mod circuit;
mod commitment;
pub mod pq;
mod pq_auth;
pub mod hybrid;   
pub use hybrid::HybridAuth;  

pub use authenticator::QuantumAuthenticator;
pub use pq::SphincsAuth; // Correct export path
