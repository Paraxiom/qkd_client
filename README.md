# QKD Client in Rust

A quantum-resistant client implementation that integrates with Quantum Key Distribution (QKD) hardware to provide secure communication channels and quantum randomness.

## Features

- Integration with ETSI QKD API
- Post-quantum signatures using SPHINCS+
- Zero-knowledge proofs for quantum key verification
- Verifiable Random Function (VRF) implementation using quantum randomness
- Byzantine fault tolerance mechanisms
- Simulation mode for testing without physical QKD hardware

## Architecture

This client connects to QKD hardware through a standardized API and provides quantum-derived keys for various cryptographic applications, with a focus on blockchain consensus mechanisms.

## Getting Started

1. Copy `config.json.example` to `config.json` and update with your QKD server settings
2. Run with `cargo build --release` and `./target/release/qkd_client`

## Testing

Run the test suite with `cargo test`
