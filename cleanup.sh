#!/bin/bash
# cleanup_project.sh - Fix and organize the QKD client project

echo "🧹 QKD Client Project Cleanup"
echo "============================"

# 1. Create necessary directories
echo "Creating necessary directories..."
mkdir -p src/bin/archive/old_demos
mkdir -p certificate/default

# 2. Create a default certificate for testing
echo "Creating default certificate..."
touch certificate/default_cert.pem

# 3. Move the corrected files into place
echo "Installing fixed files..."

# Save the list of binary files to keep
KEEP_BINS=(
  "test_qkd_keys.rs"
  "qkd_client_demo.rs"
  "vrf_qkd_demo_simple.rs"
  "byzantine_qkd_demo.rs"
)

# First, move all bin files to archive
for file in src/bin/*.rs; do
  if [ -f "$file" ]; then
    filename=$(basename "$file")
    mv "$file" "src/bin/archive/old_demos/" 2>/dev/null
  fi
done

# Now copy our fixed files back to bin
cp -f qkd_client_demo_fixed.rs src/bin/qkd_client_demo.rs 2>/dev/null
cp -f fixed_byzantine_demo.rs src/bin/byzantine_qkd_demo.rs 2>/dev/null
cp -f test_qkd_keys.rs src/bin/test_qkd_keys.rs 2>/dev/null
cp -f vrf_qkd_demo_simple.rs src/bin/vrf_qkd_demo_simple.rs 2>/dev/null

# 4. Update the ETSI API implementation
echo "Updating ETSI API implementation..."
cp -f fixed_etsi_api.rs src/qkd/etsi_api.rs 2>/dev/null

# 5. Clean up Cargo artifacts
echo "Cleaning Cargo artifacts..."
cargo clean

# 6. Run cargo update to refresh dependencies
echo "Updating dependencies..."
cargo update

# 7. Apply automatic fixes
echo "Applying automatic fixes..."
cargo fix --allow-dirty

echo ""
echo "✅ Cleanup complete!"
echo "Run 'cargo build' to verify the fixes."
