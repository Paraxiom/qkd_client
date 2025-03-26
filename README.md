
# QKD Client in Rust

A **quantum-resistant** client and test suite that integrates with **Quantum Key Distribution (QKD)** hardware, providing secure key material and cryptographic operations.

## Features

- **ETSI QKD API**: Connects to physical or simulated quantum hardware.  
- **SPHINCS+ (Post-Quantum Signatures)**: Ensures long-term security.  
- **Zero-Knowledge Proofs (ZKPs)**: Validates quantum keys privately.  
- **Verifiable Random Functions (VRFs)**: Uses quantum randomness for unpredictability.  
- **Byzantine Fault Tolerance**: Resilient in distributed or potentially hostile environments.  
- **Simulation Mode**: Testing environment without real QKD hardware.

## Available Binaries

Several binaries are provided for different scenarios:

1. **qkd_client**  
   - The main QKD client, handles key distribution and management.
2. **hybrid_auth**  
   - Demonstrates a hybrid authentication mechanism using quantum and classical cryptography.
3. **integration_test**  
   - Tests the integration of QKD with other cryptographic components.
4. **quantum_security_test**  
   - Runs various security checks and benchmarks related to quantum randomness.
5. **stand_alone_integration**  
   - A standalone integration example (for scenarios without a broader environment).
6. **zk_integration_test**  
   - Showcases zero-knowledge proof integration with QKD keys.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourorg/qkd_client.git
   cd qkd_client
   ```
2. **Build All Binaries**:
   ```bash
   cargo build --release
   ```
   This produces executables in `./target/release`.

## Usage

1. **Configure**  
   - Duplicate `config.json.example` to `config.json`.
   - Edit `config.json` to match your QKD server settings or enable `simulationMode` for testing.

2. **Run a Specific Binary**  
   - **QKD Client** (typical usage):
     ```bash
     cargo run --release --bin qkd_client -- --config config.json
     ```
   - **Other Binaries** (example: `integration_test`):
     ```bash
     cargo run --release --bin integration_test
     ```

3. **Command-Line Arguments**  
   - Binaries may accept additional parameters. Run:
     ```bash
     cargo run --release --bin <binary_name> -- --help
     ```
     for a list of available options.

## Testing

1. **Run All Tests**:
   ```bash
   cargo test
   ```
   This executes the complete suite, including unit tests, integration tests, and doc tests across all modules.

2. **Run Tests for a Specific Binary** (if applicable):
   ```bash
   cargo test --bin <binary_name>
   ```
   Replace `<binary_name>` with the exact name (e.g., `integration_test`, `zk_integration_test`, etc.).

3. **Run Tests with Verbose Output**:
   ```bash
   cargo test -- --nocapture
   ```
   Prints detailed logs to the console for debugging.

---

## License

```
MIT License

Copyright (c) 2025 Sylvain Cormier @ Paraxiom Technologies inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights 
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
copies of the Software, and to permit persons to whom the Software is 
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included 
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```


