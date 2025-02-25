// src/quantum_auth/mod.rs
mod commitment;
mod authenticator;
mod circuit;
pub mod pq;
pub mod hybrid;
mod pq_auth;

pub use authenticator::QuantumAuthenticator;
pub use pq::SphincsAuth;  // Correct export path
