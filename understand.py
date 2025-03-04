#!/bin/bash

# Create an output file
OUTPUT_FILE="code_review.txt"
echo "QKD Client Code Review" > $OUTPUT_FILE
echo "======================" >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

# Function to add a file to the output with a header
add_file() {
    echo "File: $1" >> $OUTPUT_FILE
    echo "--------------------" >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
    cat "$1" >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
}

# ETSI API implementation
echo "1. QKD ETSI API Implementation" >> $OUTPUT_FILE
echo "==============================" >> $OUTPUT_FILE
add_file "src/qkd/etsi_api.rs"
add_file "src/qkd/api.rs"
add_file "src/qkd/mod.rs"

# SPHINCS+ implementation
echo "2. Post-Quantum Cryptography (SPHINCS+)" >> $OUTPUT_FILE
echo "=======================================" >> $OUTPUT_FILE
add_file "src/quantum_auth/pq/sphincs.rs"
add_file "src/quantum_auth/pq/sphincs_optimized.rs"
add_file "src/quantum_auth/pq/mod.rs"

# Hybrid authentication system
echo "3. Hybrid Authentication System" >> $OUTPUT_FILE
echo "===============================" >> $OUTPUT_FILE
add_file "src/quantum_auth/hybrid.rs"
add_file "src/quantum_auth/mod.rs"

# VRF implementation
echo "4. VRF Implementation" >> $OUTPUT_FILE
echo "=====================" >> $OUTPUT_FILE
add_file "src/vrf/core.rs"
add_file "src/vrf/qkd_vrf.rs"
add_file "src/vrf/integrated_vrf.rs"
add_file "src/vrf/mod.rs"

# ZK circuit implementation
echo "5. Zero-Knowledge Proofs" >> $OUTPUT_FILE
echo "========================" >> $OUTPUT_FILE
add_file "src/zk/circuit.rs"
add_file "src/zk/proof.rs"
add_file "src/zk/mod.rs"
add_file "circuits/key_verification.circom"

# Byzantine consensus 
echo "6. Byzantine Consensus" >> $OUTPUT_FILE
echo "======================" >> $OUTPUT_FILE
add_file "src/byzantine/vrf_consensus.rs"
add_file "src/byzantine/consensus.rs"
add_file "src/byzantine/mod.rs"

echo "Code review file created: $OUTPUT_FILE"

