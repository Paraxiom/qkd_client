#!/usr/bin/env bash
#
# concat_zk_only.sh
#
# Concatenate the contents of all regular files in src/zk/,
# excluding common large or hidden directories.
# Writes to "combined_zk_only.txt".
#
# Usage:
#   chmod +x concat_zk_only.sh
#   ./concat_zk_only.sh

set -euo pipefail

OUTPUT_FILE="combined_zk_only.txt"
rm -f "$OUTPUT_FILE"

echo "=== Concatenating from 'src/zk/' only ==="
echo "Output file: $OUTPUT_FILE"

# Check if src/zk exists
if [ -d "src/zk" ]; then
  # We find only regular files (-type f), skipping .git, node_modules, target, .venv, etc.
  find "src/zk" \
    -path "*/.git/*" -prune -o \
    -path "*/node_modules/*" -prune -o \
    -path "*/target/*" -prune -o \
    -path "*/.venv/*" -prune -o \
    -type f -print0 |
  xargs -0 cat >> "$OUTPUT_FILE"

  echo "=== DONE: Created '$OUTPUT_FILE' from all files in 'src/zk/' ==="
else
  echo "Directory 'src/zk/' does not exist. Skipping."
fi

