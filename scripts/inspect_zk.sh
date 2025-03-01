#!/usr/bin/env bash
set -e

# ------------------------------------------------------------
# Inspect Zero-Knowledge circuit files and environment
# in the current directory or within qkd_client.
# ------------------------------------------------------------

echo "=== ZK Inspection Script ==="
echo ""

# 1) Check for typical ZK tools
echo "1) Checking for circom, snarkjs, and node..."

if command -v circom &> /dev/null
then
  echo "✅ circom is installed: $(which circom)"
else
  echo "⚠️ circom not found"
fi

if command -v snarkjs &> /dev/null
then
  echo "✅ snarkjs is installed: $(which snarkjs)"
else
  echo "⚠️ snarkjs not found"
fi

if command -v node &> /dev/null
then
  echo "✅ node is installed: $(which node)"
else
  echo "⚠️ node not found"
fi

echo ""

# 2) Jump into qkd_client if needed (optional):
# cd qkd_client

# 3) List relevant ZK files
echo "2) Listing known ZK circuit artifacts (.r1cs, .sym, .wasm, .zkey, .ptau, etc.)"
ls -1 **/*.r1cs **/*.sym **/*.wasm **/*.zkey **/*.ptau 2> /dev/null || echo "No recognized ZK artifacts found."

echo ""

# 4) Attempt to run snarkjs info on your .r1cs file, if snarkjs is available
R1CS_FILE="key_proof.r1cs"  # Update if your file is named differently or in subfolder
if command -v snarkjs &> /dev/null && [ -f "$R1CS_FILE" ]; then
  echo "3) Running 'snarkjs info -r $R1CS_FILE' for circuit info..."
  snarkjs info -r "$R1CS_FILE"
else
  echo "⚠️ Either snarkjs is not installed or $R1CS_FILE not found, skipping 'snarkjs info'"
fi

echo ""

# 5) Summarize what we found
echo "=== Summary ==="
echo "Check the output above for your circuit's constraints, signals, any .wasm, etc."
echo "Consider running 'circom' or 'snarkjs' commands to do proving, verification, or more advanced steps."
echo "Done."

