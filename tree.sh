#!/usr/bin/env bash
set -e

echo "=== Project Tree ==="
echo "(Ignoring node_modules, target, venv, etc.)"
echo ""

# Run tree with color (-C) and ignoring certain directories:
# -I '...' is a pattern for ignoring multiple items with a pipe (|) separator.
tree -C -I 'node_modules|target|venv|.*cache.*'

echo ""
echo "=== Potential ZK Artifacts ==="
# Look for known artifact extensions in the entire project
# e.g. .r1cs, .sym, .wasm, .zkey, .ptau
ZK_ARTIFACTS=$(find . -type f \( -name '*.r1cs' -o -name '*.sym' -o -name '*.wasm' -o -name '*.zkey' -o -name '*.ptau' \) 2>/dev/null)

if [ -n "$ZK_ARTIFACTS" ]; then
  echo "$ZK_ARTIFACTS"
else
  echo "No recognized ZK artifacts found."
fi

echo ""
echo "Done!"

