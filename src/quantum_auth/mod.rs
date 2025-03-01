// src/quantum_auth/mod.rs
mod authenticator;
mod circuit;
mod commitment;
pub mod hybrid;
pub mod pq;
mod pq_auth;
pub use hybrid::HybridAuth;

pub use authenticator::QuantumAuthenticator;
pub use pq::SphincsAuth;
