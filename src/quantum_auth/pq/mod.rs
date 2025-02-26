// src/quantum_auth/pq/mod.rs
mod sphincs;

pub use sphincs::{
    SphincsAuth, SphincsError, SphincsPrivateKey, SphincsPublicKey, SphincsSignature,
    SphincsVariant,
};
