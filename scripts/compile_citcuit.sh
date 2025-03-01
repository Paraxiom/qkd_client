#!/bin/bash
# compile_circuit.sh
# Compiles the multi-source ZK circuit and generates the necessary files




echo "🔧 Compiling Multi-Source Circuit..."
echo "====================================="



# Compile the circuit
echo "Compiling circuit with circom..."
/home/paraxiom/.cargo/bin/circom  circuits/multi_source_key.circom --r1cs --wasm --sym --output circuits/

# Check if compilation was successful
if [ ! -f circuits/multi_source_key_js/multi_source_key.wasm ]; then
    echo "❌ Circuit compilation failed"
    exit 1
fi

echo "✅ Circuit compiled successfully"

# Generate proving and verification keys
echo "Generating trusted setup (this may take a while)..."

# Generate powers of tau ceremony
echo "Phase 1: Powers of tau..."
snarkjs powersoftau new bn128 12 circuits/pot12_0000.ptau -v
snarkjs powersoftau contribute circuits/pot12_0000.ptau circuits/pot12_0001.ptau --name="First contribution" -v

# Phase 2
echo "Phase 2: Circuit-specific setup..."
snarkjs powersoftau prepare phase2 circuits/pot12_0001.ptau circuits/pot12_final.ptau -v
snarkjs groth16 setup circuits/multi_source_key.r1cs circuits/pot12_final.ptau circuits/multi_source_key_0000.zkey
snarkjs zkey contribute circuits/multi_source_key_0000.zkey circuits/multi_source_key_0001.zkey --name="Dev" -v
snarkjs zkey export verificationkey circuits/multi_source_key_0001.zkey circuits/multi_source_verification_key.json

echo "✅ Setup completed successfully"

# Create empty placeholders for proof generation
touch circuits/multi_source_input.json
touch circuits/multi_source_proof.json
touch circuits/multi_source_public.json
touch circuits/multi_source_witness.wtns

echo "✅ All files ready for proof generation"
echo ""
echo "📋 Next Steps:"
echo "1. Run the multi_source_demo: cargo run --bin multi_source_demo"
echo "2. Integrate with your reporter nodes"
echo "3. Use the VRF for Byzantine leader election"

# Files cleanup
echo ""
echo "Would you like to clean up temporary files? (y/n)"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
    echo "Cleaning up temporary files..."
    rm -f circuits/pot12_0000.ptau
    rm -f circuits/pot12_0001.ptau
    echo "✅ Cleanup complete"
fi
