#!/bin/bash
# deploy-remote.sh - Deploy and build BoAT Attestor (C) on the VisionFive2 board via SSH
# Usage: ./deploy-remote.sh [build|run|dry-run]

set -e

# Replace with the real SSH host/alias for your VisionFive2 board
BOARD="vf2-board"

REMOTE_DIR="~/boatattestor-c"

ACTION="${1:-build}"

echo "=== BoAT Attestor (C) Remote Deploy ==="

# Step 1: Sync source and Makefile to the board
echo "[1] Syncing source code..."
ssh "$BOARD" "mkdir -p $REMOTE_DIR"
scp -q boat-attest-c.c Makefile "$BOARD:$REMOTE_DIR/"

# Step 2: Build or run (Makefile handles cloning BoAT4 from GitHub)
case "$ACTION" in
    build)
        echo "[2] Building on board..."
        ssh "$BOARD" "cd $REMOTE_DIR && make clean && make"
        echo "=== Build complete ==="
        ;;
    run)
        echo "[2] Building and running..."
        ssh "$BOARD" "cd $REMOTE_DIR && make -q 2>/dev/null || make && ./boat-attest-c"
        ;;
    dry-run)
        echo "[2] Building and dry-running..."
        ssh "$BOARD" "cd $REMOTE_DIR && make -q 2>/dev/null || make && ./boat-attest-c --dry-run"
        ;;
    *)
        echo "Usage: $0 [build|run|dry-run]"
        exit 1
        ;;
esac
