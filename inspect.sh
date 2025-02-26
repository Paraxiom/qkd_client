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

# 4) Append your Cargo.toml for reference
echo "" >> "$OUTFILE"
echo ">>> CARGO.TOML" >> "$OUTFILE"
echo "================================================" >> "$OUTFILE"
cat Cargo.toml >> "$OUTFILE"

# 5) Append **all** .rs files (main.rs, proof.rs, etc.) to get current code state
echo "" >> "$OUTFILE"
echo ">>> ALL SRC/.RS CODE" >> "$OUTFILE"
echo "================================================" >> "$OUTFILE"
for f in $(find src -name '*.rs'); do
  echo "------------------ $f ------------------" >> "$OUTFILE"
  cat "$f" >> "$OUTFILE"
  echo "" >> "$OUTFILE"
done

# 6) Clean up the temp file
rm -f "$TMPLOG"

echo "Done! Created $OUTFILE with logs and code together."

