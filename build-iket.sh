#!/bin/bash
set -e

# Iket Build Script
# Compiles the gateway server and cli client

# Ensure Homebrew path is included for Go on macOS
export PATH=$PATH:/opt/homebrew/bin:/usr/local/bin

BIN_DIR="./bin"
mkdir -p $BIN_DIR

# Check if we should cross-compile for Linux
if [ "${1:-}" == "--linux" ]; then
    echo "🌍 Cross-compiling for Linux AMD64..."
    export GOOS=linux
    export GOARCH=amd64
    OS="linux"
    ARCH="amd64"
else
    # Build for current platform
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi
    if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then ARCH="arm64"; fi
    echo "🚀 Building Iket for local ($OS/$ARCH)..."
fi

echo "Building Iket Gateway..."
go build -o $BIN_DIR/iket ./cmd/iket

echo "Building Iket CLI..."
go build -o $BIN_DIR/iket-cli ./cmd/iket-cli

echo "✅ Build complete! Binaries located in: $BIN_DIR/"
