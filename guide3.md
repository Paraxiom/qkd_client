# ZK Enhancement Integration Guide

This guide explains how to integrate the enhanced Zero-Knowledge Proof system with your existing QKD client.

## Overview

We've enhanced your ZK system with three major components:

1. **Multi-Source Circuit**: A ZK circuit that validates keys from multiple quantum sources
2. **VRF Implementation**: A Verifiable Random Function for deterministic randomness
3. **Byzantine Integration**: Connect ZK proofs with Byzantine consensus

## Step 1: Compile the Circuit

First, compile the multi-source circuit using the provided script:

```bash
chmod +x compile_circuit.sh
./compile_circuit.sh
```

This will:
- Compile the Circom circuit
- Generate the necessary proving and verification keys
- Create placeholder files for proof generation

## Step 2: Test the Multi-Source Demo

Run the multi-source demo to verify that the circuit works correctly:

```bash
cargo run --bin multi_source_demo
```

This demo:
- Creates simulated reporter entries
- Generates a multi-source ZK proof
- Verifies the proof
- Demonstrates VRF functionality

## Step 3: Integrate with Reporter Node

To integrate with your existing reporter node:

1. Modify `src/reporter/mod.rs` to use `MultiSourceProofGenerator`:

```rust
use crate::zk::multi_source_generator::MultiSourceProofGenerator;
use crate::byzantine::buffer::SharedBuffer;
use std::sync::Arc;

// Add to ReporterNode struct:
multi_source_generator: Option<MultiSourceProofGenerator>,

// Initialize in new():
let buffer = SharedBuffer::new(100);
let multi_source_generator = Some(
    MultiSourceProofGenerator::new(Arc::clone(&buffer), 3)
);

// Add a method to generate multi-source proofs:
pub async fn generate_multi_source_proof(&self) -> Result<MultiSourceProofResult, Box<dyn Error>> {
    if let Some(generator) = &self.multi_source_generator {
        generator.generate_proof().await
    } else {
        Err("Multi-source generator not initialized".into())
    }
}
```

2. Add a method to add reports from other nodes:

```rust
pub fn add_remote_report(&self, report: ReporterEntry) {
    if let Some(generator) = &self.multi_source_generator {
        generator.add_report(report);
    }
}
```

## Step 4: Connect to Byzantine Consensus

To use the multi-source proofs with Byzantine consensus:

1. Modify your Byzantine Manager to use the VRF for leader election:

```rust
use crate::zk::vrf::VerifiableRandomFunction;

// After consensus is reached:
if consensus_result.success {
    if let Some(seed) = &consensus_result.seed_material {
        // Create VRF from seed
        let vrf = VerifiableRandomFunction::new(seed);
        
        // Elect leader for next round
        if let Ok(leader) = vrf.elect_leader(self.reporter_count as u64) {
            info!("Next round leader elected: reporter-{}", leader);
        }
    }
}
```

2. Use the multi-source proof generator with consensus:

```rust
// Inside Byzantine manager:
let proof_result = generator.generate_proof_with_consensus(&consensus).await?;

// Use the proof for verification
proof_result.proof.verify()?;
```

## Step 5: Third-Party Verification

To support third-party verification of your proofs:

1. Export the proof:

```rust
// After generating a proof:
let export_path = std::path::Path::new("proof_export.json");
proof_result.proof.export_for_verification(export_path)?;
```

2. Share the exported proof with third parties, who can verify it using:

```rust
// Third-party verification (JavaScript example):
const verifyProof = async (proofData) => {
  const { groth16 } = snarkjs;
  const verified = await groth16.verify(
    proofData.verification_key,
    proofData.public_inputs,
    proofData.proof
  );
  return verified;
};
```

## Performance Considerations

- The multi-source proof generation is computationally expensive
- Consider caching proofs when possible
- For Byzantine consensus, balance the threshold against fault tolerance needs

## Security Considerations

- The security of the system depends on the threshold parameter
- Higher thresholds increase security but reduce fault tolerance
- VRF outputs should be used immediately and not stored long-term
