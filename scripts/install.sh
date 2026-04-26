#!/bin/bash
# =============================================================================
# 🧶 Iket Gateway - Ultimate Installation Script
# =============================================================================
# Automates: platform detection, dependency installation, source cloning, 
# building, binary installation, mTLS cert generation, and configuration.
# =============================================================================

set -euo pipefail

# Colors and Emojis
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Icons
CHECK="✅"
INFO="ℹ️ "
WARN="⚠️ "
ERROR="❌"
STEP="🚀"
LOCK="🔒"
BUILD="🏗️ "
PKG="📦"

# Print functions
print_info() { echo -e "${BLUE}${INFO}${NC} $1"; }
print_success() { echo -e "${GREEN}${CHECK}${NC} $1"; }
print_warning() { echo -e "${YELLOW}${WARN}${NC} $1"; }
print_error() { echo -e "${RED}${ERROR}${NC} $1" >&2; }

print_step() {
    echo ""
    echo -e "${PURPLE}${STEP} $1${NC}"
    echo -e "${PURPLE}─────────────────────────────────────────────────────${NC}"
}

# Detection Variables
OS=""
ARCH=""
ORIGINAL_USER="${SUDO_USER:-$(whoami)}"
ORIGINAL_HOME=$(eval echo "~$ORIGINAL_USER")
REPO_URL="https://github.com/bhangun/iket.git"
RELEASE_BASE_URL="https://github.com/bhangun/iket/releases/latest/download"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="$ORIGINAL_HOME/.iket"
HAS_SYSTEMD=false
CLI_ONLY=false
FROM_SOURCE=false
DOWNLOADER=""

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --cli-only)
                CLI_ONLY=true
                shift
                ;;
            --from-source)
                FROM_SOURCE=true
                shift
                ;;
            *)
                shift
                ;;
        esac
    done
}

# 1. Detect Platform
detect_platform() {
    print_step "Detecting Platform"
    
    case "$(uname -s)" in
        Linux*)  OS="linux" ;;
        Darwin*) OS="darwin" ;;
        *)       print_error "Unsupported OS: $(uname -s)"; exit 1 ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)             print_error "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac

    print_success "Detected ${OS}/${ARCH} for user ${ORIGINAL_USER}"
}

# 2. Check & Install Prerequisites
preflight_checks() {
    print_step "Checking Dependencies"

    local tools=()
    if [ "$FROM_SOURCE" = true ]; then
        tools=("git" "go" "make")
    else
        if command -v curl &> /dev/null; then
            DOWNLOADER="curl"
        elif command -v wget &> /dev/null; then
            DOWNLOADER="wget"
        else
            tools=("curl")
        fi
    fi
    local missing_tools=()

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            # Special case for go as some package managers call it golang or golang-go
            if [ "$tool" == "go" ]; then
                missing_tools+=("go")
            else
                missing_tools+=("$tool")
            fi
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_warning "Missing dependencies: ${missing_tools[*]}"
        
        SUDO_CMD=""
        if [ "$EUID" -ne 0 ] && command -v sudo &>/dev/null; then SUDO_CMD="sudo"; fi

        if [ "$OS" == "linux" ]; then
            if command -v apt-get &> /dev/null; then
                print_info "${PKG} Detected Debian/Ubuntu (apt-get). Installing..."
                $SUDO_CMD apt-get update -qq
                if [ "$FROM_SOURCE" = true ]; then
                    $SUDO_CMD apt-get install -y -qq git golang-go make
                else
                    $SUDO_CMD apt-get install -y -qq curl
                fi
            elif command -v dnf &> /dev/null; then
                print_info "${PKG} Detected Fedora/RHEL (dnf). Installing..."
                if [ "$FROM_SOURCE" = true ]; then
                    $SUDO_CMD dnf install -y git golang make
                else
                    $SUDO_CMD dnf install -y curl
                fi
            elif command -v yum &> /dev/null; then
                print_info "${PKG} Detected CentOS/RHEL (yum). Installing..."
                if [ "$FROM_SOURCE" = true ]; then
                    $SUDO_CMD yum install -y git golang make
                else
                    $SUDO_CMD yum install -y curl
                fi
            elif command -v pacman &> /dev/null; then
                print_info "${PKG} Detected Arch Linux (pacman). Installing..."
                if [ "$FROM_SOURCE" = true ]; then
                    $SUDO_CMD pacman -Sy --noconfirm git go make
                else
                    $SUDO_CMD pacman -Sy --noconfirm curl
                fi
            else
                print_error "Unsupported package manager. Please manually install: ${missing_tools[*]}"
                exit 1
            fi
        elif [ "$OS" == "darwin" ]; then
            if command -v brew &>/dev/null; then
                print_info "${PKG} Detected macOS (Homebrew). Installing..."
                if [ "$FROM_SOURCE" = true ]; then
                    brew install git go make
                else
                    brew install curl
                fi
            else
                print_error "Homebrew not found. Please install Homebrew or manually install: ${missing_tools[*]}"
                exit 1
            fi
        else
            print_error "Unsupported OS for auto-installation. Please manually install: ${missing_tools[*]}"
            exit 1
        fi
        print_success "Dependencies installed."
    else
        print_success "All prerequisites met."
    fi

    if [ "$FROM_SOURCE" != true ] && [ -z "$DOWNLOADER" ]; then
        if command -v curl &> /dev/null; then
            DOWNLOADER="curl"
        elif command -v wget &> /dev/null; then
            DOWNLOADER="wget"
        else
            print_error "A downloader is required. Please install curl or wget, or rerun with --from-source."
            exit 1
        fi
    fi

    # Check for systemd
    if [ "$OS" == "linux" ] && pidof systemd &>/dev/null; then
        HAS_SYSTEMD=true
    fi
}

# 3. Handle Repository (for curl | bash mode)
prepare_source() {
    if [ "$FROM_SOURCE" != true ]; then
        return 0
    fi
    if [ ! -f "Makefile" ]; then
        print_step "Cloning Repository"
        local tmp_repo=$(mktemp -d)
        print_info "Cloning Iket into temporary directory..."
        git clone --depth 1 "$REPO_URL" "$tmp_repo" > /dev/null 2>&1
        cd "$tmp_repo"
    fi
}

download_file() {
    local url="$1"
    local output="$2"
    if [ "$DOWNLOADER" = "curl" ]; then
        curl -fsSL "$url" -o "$output"
    else
        wget -qO "$output" "$url"
    fi
}

download_prebuilt_binaries() {
    print_step "Downloading Prebuilt Binaries"

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local cli_asset="iket-${OS}-${ARCH}"
    local server_asset="iket-server-${OS}-${ARCH}"
    local cli_path="$tmp_dir/$cli_asset"
    local server_path="$tmp_dir/$server_asset"

    print_info "Downloading CLI binary (${cli_asset})..."
    if ! download_file "${RELEASE_BASE_URL}/${cli_asset}" "$cli_path"; then
        print_error "Failed to download ${cli_asset} from ${RELEASE_BASE_URL}."
        print_error "If you want to build locally instead, rerun the installer with --from-source."
        exit 1
    fi
    chmod +x "$cli_path"

    if [ "$CLI_ONLY" != true ]; then
        print_info "Downloading gateway binary (${server_asset})..."
        if ! download_file "${RELEASE_BASE_URL}/${server_asset}" "$server_path"; then
            print_error "Failed to download ${server_asset} from ${RELEASE_BASE_URL}."
            print_error "If you want to build locally instead, rerun the installer with --from-source."
            exit 1
        fi
        chmod +x "$server_path"
    fi

    PREBUILT_TMP_DIR="$tmp_dir"
    PREBUILT_CLI_PATH="$cli_path"
    PREBUILT_SERVER_PATH="$server_path"
    print_success "Prebuilt binaries downloaded."
}

# 4. Build and Install
build_and_install() {
    SUDO_CMD=""
    if [ "$EUID" -ne 0 ] && command -v sudo &>/dev/null; then SUDO_CMD="sudo"; fi

    if [ "$FROM_SOURCE" = true ]; then
        print_step "Building & Installing"
        if [ "$CLI_ONLY" = true ]; then
            print_info "${BUILD} Building CLI binary..."
            make build-cli > /dev/null
            print_info "Moving iket to $INSTALL_DIR..."
            $SUDO_CMD install -m 755 bin/iket "$INSTALL_DIR/iket"
            $SUDO_CMD install -m 755 bin/iket "$INSTALL_DIR/iket-cli"
        else
            print_info "${BUILD} Building binaries (this may take a minute)..."
            make build build-cli > /dev/null
            print_info "Moving binaries to $INSTALL_DIR..."
            $SUDO_CMD install -m 755 bin/iket-server "$INSTALL_DIR/iket-server"
            $SUDO_CMD install -m 755 bin/iket "$INSTALL_DIR/iket"
            $SUDO_CMD install -m 755 bin/iket "$INSTALL_DIR/iket-cli"
            $SUDO_CMD install -m 755 bin/iket-server "$INSTALL_DIR/iket-gateway"
        fi
    else
        download_prebuilt_binaries
        print_step "Installing Binaries"
        print_info "Installing prebuilt CLI binary to $INSTALL_DIR..."
        $SUDO_CMD install -m 755 "$PREBUILT_CLI_PATH" "$INSTALL_DIR/iket"
        $SUDO_CMD install -m 755 "$PREBUILT_CLI_PATH" "$INSTALL_DIR/iket-cli"
        if [ "$CLI_ONLY" != true ]; then
            print_info "Installing prebuilt gateway binary to $INSTALL_DIR..."
            $SUDO_CMD install -m 755 "$PREBUILT_SERVER_PATH" "$INSTALL_DIR/iket-server"
            $SUDO_CMD install -m 755 "$PREBUILT_SERVER_PATH" "$INSTALL_DIR/iket-gateway"
        fi
    fi
    
    print_success "Binaries installed successfully."
}

# 5. Security & Configuration
setup_security() {
    if [ "$CLI_ONLY" = true ]; then
        print_step "Configuring CLI Security"
    else
        print_step "Configuring Security (mTLS)"
    fi
    
    local cert_dir="$CONFIG_DIR/certs"
    mkdir -p "$cert_dir"
    chown -R "$ORIGINAL_USER" "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR" "$cert_dir"

    if [ "$CLI_ONLY" != true ]; then
        if [ ! -f "$cert_dir/ca.crt" ]; then
            print_info "${LOCK} Generating default mTLS certificates..."
            # Use the freshly installed CLI
            $INSTALL_DIR/iket cert gen --cert-dir "$cert_dir" --server-hostname localhost --server-ip 127.0.0.1 > /dev/null
            print_success "Certificates generated in $cert_dir"
        else
            print_info "Certificates already exist, keeping them."
        fi

        # Server Config
        if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
            cat > "$CONFIG_DIR/config.yaml" <<EOF
server:
  port: 8080
  enableLogging: true
security:
  tls:
    enabled: true
    port: 8443
    enrollmentPort: 9443
    enrollmentMaxActive: 10
    certFile: "$cert_dir/server.crt"
    keyFile: "$cert_dir/server.key"
    clientCAFile: "$cert_dir/ca.crt"
    clientAuthType: "RequireAndVerifyClientCert"
    minVersion: "TLS1.2"
    autoGenerate: true
  enableBasicAuth: true
  basicAuthUsers:
    admin: admin123
storage:
  mode: postgres
  postgres_url: "postgres://iket:iket@127.0.0.1:55432/iket?sslmode=disable"
  mirror_files: true
EOF
            print_success "Server configuration created."
        fi
    fi

    # CLI Config
    if [ ! -f "$CONFIG_DIR/cli-config.yaml" ]; then
        cat > "$CONFIG_DIR/cli-config.yaml" <<EOF
server_url: "https://localhost:8443"
cert_file: "$cert_dir/client.crt"
key_file: "$cert_dir/client.key"
ca_file: "$cert_dir/ca.crt"
skip_verify: false
EOF
        print_success "CLI configuration created."
    fi
    
    chown -R "$ORIGINAL_USER" "$CONFIG_DIR"
}

# 6. Service Configuration
setup_service() {
    if [ "$HAS_SYSTEMD" != "true" ] || [ "$CLI_ONLY" = true ]; then return 0; fi
    
    print_step "Configuring System Service"
    local SUDO_CMD=""
    if [ "$EUID" -ne 0 ]; then SUDO_CMD="sudo"; fi

    cat <<EOF | $SUDO_CMD tee /etc/systemd/system/iket.service >/dev/null
[Unit]
Description=Iket API Gateway
After=network.target

[Service]
Type=simple
User=$ORIGINAL_USER
WorkingDirectory=$ORIGINAL_HOME
ExecStart=$INSTALL_DIR/iket-server --config $CONFIG_DIR/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    $SUDO_CMD systemctl daemon-reload
    $SUDO_CMD systemctl enable iket > /dev/null 2>&1 || true
    print_success "Systemd service 'iket' configured and enabled."
}

# Main
main() {
    parse_args "$@"

    echo -e "${CYAN}"
    echo "  🧶  IKET GATEWAY INSTALLER"
    if [ "$CLI_ONLY" = true ]; then
        echo "  (CLI ONLY MODE)"
    fi
    if [ "$FROM_SOURCE" = true ]; then
        echo "  (FROM SOURCE MODE)"
    else
        echo "  (PREBUILT RELEASE MODE)"
    fi
    echo "  ──────────────────────────"
    echo -e "${NC}"

    detect_platform
    preflight_checks
    prepare_source
    build_and_install
    setup_security
    setup_service

    print_step "Installation Summary"
    print_success "Done! Iket is ready to go."
    echo ""
    if [ "$CLI_ONLY" != true ]; then
        echo -e "  ${BLUE}Server Bin:${NC}    $INSTALL_DIR/iket-server"
    fi
    echo -e "  ${BLUE}CLI Bin:${NC}       $INSTALL_DIR/iket"
    echo -e "  ${BLUE}Config Dir:${NC}    $CONFIG_DIR"
    echo ""
    
    if [ "$CLI_ONLY" != true ]; then
        print_info "To start the gateway:"
        if [ "$HAS_SYSTEMD" == "true" ]; then
            echo -e "  ${YELLOW}sudo systemctl start iket${NC}"
        else
            echo -e "  ${YELLOW}iket-server --config ~/.iket/config.yaml${NC}"
        fi
        echo ""
    fi
    
    print_info "To check status with CLI:"
    echo -e "  ${YELLOW}iket gateway status${NC}"
    echo ""
    echo -e "${PURPLE}Enjoy your secure gateway!${NC}"
}

main "$@"
