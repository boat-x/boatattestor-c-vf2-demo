#!/bin/bash
# deploy-local.sh - Build BoAT Attestor (C) locally on the VisionFive2 board
# Usage: Run this script from ~/boatattestor-c on the board
#   ./deploy-local.sh [build|run|dry-run]
#
# Prerequisites:
#   1. Copy boat-attest-c.c and Makefile to ~/boatattestor-c/ on the board
#   2. Install build dependencies:
#        sudo apt-get install gcc make git libcurl4-openssl-dev libcjson-dev libssl-dev
#   3. The Makefile will automatically clone BoAT4 SDK from GitHub on first build

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

ACTION="${1:-build}"

echo "=== BoAT Attestor (C) Local Build ==="

case "$ACTION" in
    build)
        echo "[1] Building..."
        make clean && make
        echo "=== Build complete ==="
        ;;
    run)
        echo "[1] Building and running..."
        make -q 2>/dev/null || make
        echo ""
        ./boat-attest-c
        ;;
    dry-run)
        echo "[1] Building and dry-running..."
        make -q 2>/dev/null || make
        echo ""
        ./boat-attest-c --dry-run
        ;;
    *)
        echo "Usage: $0 [build|run|dry-run]"
        exit 1
        ;;
esac
