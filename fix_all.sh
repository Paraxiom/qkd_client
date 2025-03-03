#!/bin/bash
# fix_all.sh - Comprehensive script to fix all issues

echo "🔧 QKD Client Project Fixer"
echo "=========================="

# Make sure we're in the project root
if [ ! -f "Cargo.toml" ]; then
  echo "Error: This script must be run from the project root directory."
  exit 1
fi

# 1. Apply fixes to ETSI API implementation
echo "📝 Fixing ETSI API implementation..."
if [ -f "fixed_etsi_api.rs" ]; then
  cp -f fixed_etsi_api.rs src/qkd/etsi_api.rs
  echo "  ✓ ETSI API updated"
else
  echo "  ✗ fixed_etsi_api.rs not found! Skipping."
fi

# 2. Create placeholders for missing files
echo "📄 Creating placeholders for missing files..."
PLACEHOLDER='// Placeholder file
fn main() {
    println!("This is a placeholder binary. Please use one of the main demo binaries.");
}
'

# Create placeholder for setup_main.rs
if [ ! -f "src/bin/setup_main.rs" ]; then
  mkdir -p src/bin
  echo "$PLACEHOLDER" > src/bin/setup_main.rs
  echo "  ✓ Created placeholder for setup_main.rs"
fi

# 3. Install the fixed demo files
echo "🚀 Installing fixed demo files..."
# QKD Client Demo
if [ -f "qkd_client_demo_fixed.rs" ]; then
  cp -f qkd_client_demo_fixed.rs src/bin/qkd_client_demo.rs
  echo "  ✓ QKD client demo updated"
fi

# Byzantine Demo
if [ -f "fixed_byzantine_demo.rs" ]; then
  cp -f fixed_byzantine_demo.rs src/bin/byzantine_qkd_demo.rs
  echo "  ✓ Byzantine demo updated"
fi

# Test QKD Keys
if [ -f "test_qkd_keys.rs" ]; then
  cp -f test_qkd_keys.rs src/bin/test_qkd_keys.rs
  echo "  ✓ QKD keys test updated"
fi

# VRF QKD Demo
if [ -f "vrf_qkd_demo_simple.rs" ]; then
  cp -f vrf_qkd_demo_simple.rs src/bin/vrf_qkd_demo_simple.rs
  echo "  ✓ VRF QKD demo updated"
fi

# 4. Create necessary directories and certificates
echo "🔒 Setting up certificates..."
mkdir -p certificate/default
touch certificate/default_cert.pem
echo "  ✓ Default certificate created"

# 5. Clean cargo build artifacts
echo "🧹 Cleaning cargo build artifacts..."
cargo clean
echo "  ✓ Build artifacts cleaned"

# 6. Try to build the project
echo "🏗️ Building project..."
cargo check --quiet

# Check if the build succeeded
if [ $? -eq 0 ]; then
  echo "✅ Build succeeded! The fixes have been applied successfully."
else
  echo "⚠️ Build still has issues. You might need to make additional fixes."
fi

echo ""
echo "📝 Next steps:"
echo "1. Run 'cargo run --bin qkd_client_demo -- --device simulated --operation status' to test the QKD client"
echo "2. Run 'cargo run --bin vrf_qkd_demo_simple' to test the VRF demo"
echo "3. Run 'cargo run --bin byzantine_qkd_demo' to test the Byzantine consensus demo"
echo ""
