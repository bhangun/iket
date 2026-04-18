#!/bin/bash
set -e

# Iket Local Installer Script
# Builds the binaries for the current platform and installs them to /usr/local/bin/

echo "🚀 Building Iket for local system..."
chmod +x ./build-iket.sh
./build-iket.sh

echo "📦 Installing binaries to /usr/local/bin/ (this requires sudo)..."
sudo cp bin/iket bin/iket-cli /usr/local/bin/
sudo chmod +x /usr/local/bin/iket /usr/local/bin/iket-cli

if [ -d "$HOME/.local/bin" ]; then
    echo "📦 Copying to $HOME/.local/bin/ as well..."
    cp bin/iket bin/iket-cli "$HOME/.local/bin/"
    chmod +x "$HOME/.local/bin/iket" "$HOME/.local/bin/iket-cli"
fi

echo "✅ Installation complete! You can now run 'iket' and 'iket-cli' directly."
