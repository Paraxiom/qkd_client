#!/bin/bash
# src/bin/explore_crate.sh
# A script to help discover the module structure of pqcrypto-sphincsplus

# First, find the crate in the cargo registry
CARGO_DIR=$(cargo locate-project --workspace | grep -o '"root":"[^"]*' | cut -d'"' -f4 | xargs dirname)
REGISTRY_DIR="$HOME/.cargo/registry/src"

echo "Looking for pqcrypto-sphincsplus in $REGISTRY_DIR..."
CRATE_DIR=$(find "$REGISTRY_DIR" -name "pqcrypto-sphincsplus-0.7.0" -type d | head -1)

if [ -z "$CRATE_DIR" ]; then
    echo "Could not find pqcrypto-sphincsplus-0.7.0 in registry."
    echo "Trying alternate versions..."
    CRATE_DIR=$(find "$REGISTRY_DIR" -name "pqcrypto-sphincsplus-*" -type d | head -1)
fi

if [ -z "$CRATE_DIR" ]; then
    echo "Could not find any pqcrypto-sphincsplus version."
    exit 1
fi

echo "Found crate at: $CRATE_DIR"
echo "======================="

# Look at the main library file to see exports
echo "Contents of lib.rs:"
echo "----------------"
if [ -f "$CRATE_DIR/src/lib.rs" ]; then
    cat "$CRATE_DIR/src/lib.rs"
else
    echo "lib.rs not found."
fi

# Look for module files
echo -e "\nAvailable .rs files in src:"
echo "----------------"
find "$CRATE_DIR/src" -name "*.rs" | sort

# Look at the Cargo.toml for details
echo -e "\nContents of Cargo.toml:"
echo "----------------"
if [ -f "$CRATE_DIR/Cargo.toml" ]; then
    cat "$CRATE_DIR/Cargo.toml"
else
    echo "Cargo.toml not found."
fi

echo -e "\nRecommendation:"
echo "Based on this information, you should be able to determine:"
echo "1. Which modules are actually exported by the crate"
echo "2. The correct naming conventions for modules"
echo "3. How to properly import and use the crate"
