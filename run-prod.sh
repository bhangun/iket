#!/bin/bash
# =============================================================================
# Iket Production Runner Script
# =============================================================================
# Builds and runs Iket Gateway in production mode with systemd integration.
# =============================================================================

set -euo pipefail

# Colors
BLUE='\033[1;34m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[i]${NC} $1"; }
print_success() { echo -e "${GREEN}[v]${NC} $1"; }

# 1. Build
print_info "Building Iket for production..."
./build-iket.sh

# 2. Install
print_info "Installing Iket binaries..."
sudo cp bin/iket-server bin/iket /usr/local/bin/
sudo cp /usr/local/bin/iket /usr/local/bin/iket-cli
sudo cp /usr/local/bin/iket-server /usr/local/bin/iket-gateway

# 3. Directories & Permissions
print_info "Ensuring production directories exist..."
sudo mkdir -p /etc/iket/certs
sudo mkdir -p /var/log/iket

# 4. Service
if [ -d "/etc/systemd/system" ]; then
    print_info "Configuring systemd service..."
    ./scripts/install.sh --service-only || true
    sudo systemctl daemon-reload
    sudo systemctl enable iket
    sudo systemctl restart iket
    print_success "Iket is running via systemd."
    echo "Check status: sudo systemctl status iket"
else
    print_info "No systemd detected. Starting manually in background..."
    nohup /usr/local/bin/iket-server --config /etc/iket/config.yaml > /var/log/iket/server.log 2>&1 &
    print_success "Iket started in background."
fi

print_success "Production deployment complete!"
