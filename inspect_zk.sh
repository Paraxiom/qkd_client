#!/usr/bin/env bash
#
# inspect_zk_mocks.sh
#
# Recursively searches the 'qkd_client' directory for lines that mention
# suspicious placeholders like "mock", "fake", "dummy", or "todo" which could
# indicate a mocked ZK proof or incomplete implementation.
#
# Usage:
#   chmod +x inspect_zk_mocks.sh
#   ./inspect_zk_mocks.sh
#

set -euo pipefail

echo "=== Searching for mock/fake/dummy references related to ZK proofs in qkd_client ==="

# Customize this list of keywords if needed
KEYWORDS='mock\|fake\|dummy\|todo\|ZKPROOF_MOCK\|ZK_PROOF_STUB'

grep --color=always -rIn -C3 \
    --exclude-dir='.git' \
    --exclude-dir='node_modules' \
    --exclude-dir='target' \
    --exclude-dir='.venv' \
    -E "$KEYWORDS" . || true

echo "=== DONE: Inspect lines above to find any mocked or incomplete ZK proof code. ==="

