#!/bin/bash
# =============================================================================
# Iket Development Runner Script
# =============================================================================
# Automatically builds and runs Iket in development mode with hot-reloading 
# simulation (manual restart on change) and monitoring.
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
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[x]${NC} $1"; }

# Config
PID_FILE="/tmp/iket-dev.pid"
CONFIG_FILE="./config/config.yaml"
SERVICES_FILE="./config/service.yaml"

cleanup() {
    print_info "Cleaning up..."
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID"
        fi
        rm -f "$PID_FILE"
    fi
}

trap cleanup EXIT INT TERM

build_binaries() {
    print_info "Building binaries..."
    ./build-iket.sh
}

run_gateway() {
    print_info "Starting Iket Gateway..."
    ./bin/iket --config "$CONFIG_FILE" --services "$SERVICES_FILE" &
    echo $! > "$PID_FILE"
    print_success "Iket running with PID $(cat "$PID_FILE")"
}

main() {
    # Ensure config exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        print_warning "Config file not found at $CONFIG_FILE. Creating default..."
        mkdir -p config
        cat > "$CONFIG_FILE" <<EOF
server:
  port: 8080
  enableLogging: true
EOF
    fi

    build_binaries
    run_gateway
    
    print_info "Press Ctrl+C to stop"
    wait
}

main "$@"
