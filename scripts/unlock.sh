#!/bin/bash
# unlock_cargo.sh - Release file locks for Cargo

echo "🔓 Unlocking Cargo file locks..."

# Path to Cargo's lock files
CARGO_DIR="$HOME/.cargo"
PROJECT_DIR="."

# Find and remove Cargo lock files
echo "Checking for lock files in Cargo directory..."
find "$CARGO_DIR" -name ".package-cache" -type f -delete
echo "✓ Removed Cargo package cache locks"

# Find and remove lock files in project directory
echo "Checking for lock files in project directory..."
find "$PROJECT_DIR/target" -name ".lock" -type f -delete
echo "✓ Removed project target locks"

# Kill any running cargo processes
echo "Checking for running cargo processes..."
if pgrep -x "cargo" > /dev/null; then
    echo "Found running cargo processes, attempting to terminate..."
    pkill -9 cargo
    echo "✓ Terminated cargo processes"
else
    echo "No running cargo processes found"
fi

echo "✅ Lock files cleaned up!"
echo "Try running 'cargo build' again."
