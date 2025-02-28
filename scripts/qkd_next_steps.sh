#!/bin/bash
# QKD Development Next Steps

# Set up colored output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Make sure we're in the project root
cd "$(dirname "$0")/.."
PROJECT_ROOT=$(pwd)

echo -e "${BLUE}=== QKD Client Development Workflow ===${NC}"
echo -e "${BLUE}Working directory: ${PROJECT_ROOT}${NC}"

# Check for required commands
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}Error: $1 is not installed or not in PATH${NC}"
        echo -e "${YELLOW}Please make sure the command is available before running this script${NC}"
        return 1
    fi
    return 0
}

if ! check_command cargo || ! check_command circom || ! check_command snarkjs; then
    echo -e "${RED}Please install missing commands and try again${NC}"
    exit 1
fi

# 1. Test VRF Implementation
echo -e "\n${GREEN}Step 1: Testing VRF Implementation${NC}"
echo -e "${YELLOW}Running VRF simple demo...${NC}"
cargo run --bin vrf_simple_demo || { echo -e "${RED}VRF simple demo failed!${NC}"; }

# 2. Test Byzantine Consensus with VRF
echo -e "\n${GREEN}Step 2: Testing Byzantine Consensus with VRF${NC}"
echo -e "${YELLOW}Running VRF consensus demo...${NC}"
cargo run --bin vrf_consensus_demo || { echo -e "${RED}VRF consensus demo failed!${NC}"; }

# 3. Fix and test the ZK circuit
echo -e "\n${GREEN}Step 3: Testing ZK Circuit${NC}"
# First, let's make sure the circuit file is correct
cat > circuits/vrf_seed_proof.circom << EOL
pragma circom 2.0.8;
include "circomlib/poseidon.circom";
include "circomlib/comparators.circom";

// This circuit proves that a VRF seed incorporates a valid quantum key
template VRFSeedProof() {
    // Input: quantum key, input data, and VRF seed
    signal input quantumKey;
    signal input inputData;
    signal input vrfSeed;
    signal output isValid;
    
    // Hash the quantum key and input to get expected seed
    component hasher = Poseidon(2);
    hasher.inputs[0] <== quantumKey;
    hasher.inputs[1] <== inputData;
    
    // Compare hash output with provided VRF seed
    component comparator = IsEqual();
    comparator.in[0] <== hasher.out;
    comparator.in[1] <== vrfSeed;
    
    // Output 1 if valid, 0 if invalid
    isValid <== comparator.out;
}

component main = VRFSeedProof();
EOL

echo -e "${YELLOW}Compiling VRF seed proof circuit...${NC}"
circom circuits/vrf_seed_proof.circom --r1cs --wasm --sym --c -o circuits/ || { 
    echo -e "${RED}Circuit compilation failed!${NC}"; 
    exit 1;
}

echo -e "${YELLOW}Generating proving and verification keys...${NC}"
# These commands assume you've already generated pot12_final.ptau
if [ -f "circuits/pot12_final.ptau" ]; then
    snarkjs groth16 setup circuits/vrf_seed_proof.r1cs circuits/pot12_final.ptau circuits/vrf_seed_proof_0000.zkey
    echo "QKD VRF Contributor" | snarkjs zkey contribute circuits/vrf_seed_proof_0000.zkey circuits/vrf_seed_proof_0001.zkey --name="QKD Contributor" -v -e="QKD VRF Contributor"
    snarkjs zkey export verificationkey circuits/vrf_seed_proof_0001.zkey circuits/vrf_verification_key.json
else
    echo -e "${RED}Missing circuits/pot12_final.ptau file!${NC}"
    echo -e "${YELLOW}You need to generate the powers of tau file first.${NC}"
fi

# 4. Run multi-source key proof demo
echo -e "\n${GREEN}Step 4: Testing Multi-Source Key Proof${NC}"
echo -e "${YELLOW}Running multi-source demo...${NC}"
cargo run --bin multi_source_demo || { echo -e "${RED}Multi-source demo failed!${NC}"; }

# 5. Create test input for the VRF seed proof
echo -e "\n${GREEN}Step 5: Creating Test Input for VRF Seed Proof${NC}"
cat > circuits/vrf_input.json << EOL
{
  "quantumKey": 123456789012345678901234,
  "inputData": 7890123456789012345678,
  "vrfSeed": 9876543210987654321098
}
EOL

if [ -f "circuits/vrf_seed_proof_js/generate_witness.js" ]; then
    echo -e "${YELLOW}Generating witness for VRF seed proof...${NC}"
    node circuits/vrf_seed_proof_js/generate_witness.js circuits/vrf_seed_proof_js/vrf_seed_proof.wasm circuits/vrf_input.json circuits/vrf_witness.wtns

    echo -e "${YELLOW}Generating proof...${NC}"
    snarkjs groth16 prove circuits/vrf_seed_proof_0001.zkey circuits/vrf_witness.wtns circuits/vrf_proof.json circuits/vrf_public.json

    echo -e "${YELLOW}Verifying proof...${NC}"
    snarkjs groth16 verify circuits/vrf_verification_key.json circuits/vrf_public.json circuits/vrf_proof.json
else
    echo -e "${RED}Missing generate_witness.js file!${NC}"
    echo -e "${YELLOW}Make sure the circuit was compiled correctly.${NC}"
fi

# 6. Run a simple benchmark
echo -e "\n${GREEN}Step 6: Running Simple Performance Benchmark${NC}"
time cargo run --release --bin vrf_simple_demo > /dev/null || { echo -e "${RED}VRF benchmark failed!${NC}"; }

echo -e "\n${BLUE}=== QKD Development Workflow Complete ===${NC}"
echo -e "Next recommended steps:"
echo -e "1. Review the test results and fix any issues"
echo -e "2. Optimize circuit performance if needed"
echo -e "3. Document the ZK-VRF integration"
echo -e "4. Create more comprehensive test cases"
