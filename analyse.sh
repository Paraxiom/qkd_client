#!/bin/bash
# Script to concatenate relevant ZK implementation files for analysis

# Create output file
output_file="zk_implementation_analysis.txt"
echo "# ZK Implementation Analysis" > $output_file
echo "Generated on $(date)" >> $output_file
echo "" >> $output_file

# Function to append a file with a header
append_file() {
    if [ -f "$1" ]; then
        echo -e "\n\n## File: $1\n" >> $output_file
        echo '```' >> $output_file
        cat "$1" >> $output_file
        echo '```' >> $output_file
        echo "Added $1 to analysis"
    else
        echo "Warning: File $1 not found"
    fi
}

# VRF implementation files (likely containing the warning)
echo "### VRF Implementation Files" >> $output_file
append_file "src/vrf/integrated_vrf.rs"
append_file "src/vrf/core.rs"

# ZK proof related files
echo "### ZK Proof Files" >> $output_file
append_file "src/zk/mod.rs"
append_file "src/zk/proof_generator.rs"
append_file "src/zk/multi_source_generator.rs"
append_file "src/zk/multi_source_proof.rs"

# Circuit definitions
echo "### Circuit Definitions" >> $output_file
append_file "circuits/vrf_seed_proof.circom"
append_file "circuits/multi_source_key.circom"

# Check for any ZK-related utilities
echo "### ZK Utilities" >> $output_file
append_file "src/utils/zk_utils.rs"
append_file "src/zk/circuit_utils.rs"

echo "Analysis file created: $output_file"
