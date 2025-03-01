#!/bin/bash
# unlock_cargo.sh - Script to release cargo locks

# Define colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Checking for locked Cargo processes...${NC}"

# Find the lock file location
CARGO_DIR="$HOME/.cargo"
TARGET_DIR="$PWD/target"

# Look for lock files
LOCKS=(
  "$CARGO_DIR/.package-cache"
  "$TARGET_DIR/.rustc_info.json"
  "$TARGET_DIR/CACHEDIR.TAG"
  "$TARGET_DIR/.cargo-lock"
)

# Check for cargo processes
CARGO_PIDS=$(pgrep -l cargo | awk '{print $1}')

if [ -n "$CARGO_PIDS" ]; then
  echo -e "${RED}Found running cargo processes:${NC}"
  ps -f -p $CARGO_PIDS
  
  read -p "Do you want to kill these processes? (y/n) " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    kill $CARGO_PIDS
    echo -e "${GREEN}Processes terminated.${NC}"
  fi
fi

# Check and remove lock files
for LOCK in "${LOCKS[@]}"; do
  if [ -f "$LOCK.lock" ]; then
    echo -e "${YELLOW}Found lock file: $LOCK.lock${NC}"
    read -p "Do you want to remove this lock file? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      rm -f "$LOCK.lock"
      echo -e "${GREEN}Lock file removed.${NC}"
    fi
  fi
done

echo -e "${GREEN}Cargo should now be unlocked!${NC}"
echo -e "${YELLOW}Try running 'cargo build' again.${NC}"
