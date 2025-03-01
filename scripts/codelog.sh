#!/usr/bin/env bash

# 1) Name of the final combined file
OUTFILE="combined_output.txt"

# 2) Create/capture logs in a temporary file
TMPLOG=$(mktemp)

echo "Running cargo run to capture logs..."
echo "================================================" > "$TMPLOG"
date >> "$TMPLOG"
echo "================================================" >> "$TMPLOG"

# Run Cargo with full backtrace and direct output to $TMPLOG
RUST_BACKTRACE=full cargo run --bin qkd_client >> "$TMPLOG" 2>&1

# 3) Start writing to the final combined file
echo "=== COMBINED LOGS AND CODE ===" > "$OUTFILE"
echo ">>> RUNTIME LOGS" >> "$OUTFILE"
cat "$TMPLOG" >> "$OUTFILE"

# 4) Now append the code from main.rs
echo "" >> "$OUTFILE"
echo ">>> MAIN.RS CODE" >> "$OUTFILE"
echo "================================================" >> "$OUTFILE"
cat src/main.rs >> "$OUTFILE"

# (Optional) Append more files if desired, e.g.:
# echo "" >> "$OUTFILE"
# echo ">>> PROOF.RS CODE" >> "$OUTFILE"
# echo "================================================" >> "$OUTFILE"
# cat src/zk/proof.rs >> "$OUTFILE"

# 5) Clean up the temp file
rm -f "$TMPLOG"

echo "Done! Created $OUTFILE with logs and code together."

