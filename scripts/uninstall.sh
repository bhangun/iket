#!/bin/bash
# =============================================================================
# 🧶 Iket Gateway - Uninstall Script
# =============================================================================
# Removes installed binaries and service files, with optional state backup and
# optional full purge of local Iket configuration/state.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

CHECK="✅"
INFO="ℹ️ "
WARN="⚠️ "
ERROR="❌"
STEP="🧹"
BOX="📦"

print_info() { echo -e "${BLUE}${INFO}${NC} $1"; }
print_success() { echo -e "${GREEN}${CHECK}${NC} $1"; }
print_warning() { echo -e "${YELLOW}${WARN}${NC} $1"; }
print_error() { echo -e "${RED}${ERROR}${NC} $1" >&2; }

print_step() {
    echo ""
    echo -e "${PURPLE}${STEP} $1${NC}"
    echo -e "${PURPLE}─────────────────────────────────────────────────────${NC}"
}

ORIGINAL_USER="${SUDO_USER:-$(whoami)}"
ORIGINAL_HOME=$(eval echo "~$ORIGINAL_USER")
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="$ORIGINAL_HOME/.iket"
SERVICE_NAME="iket"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
BACKUP_DIR="$ORIGINAL_HOME/iket-backups"
BACKUP_STATE=false
PURGE_STATE=false
CLI_ONLY=false
ASSUME_YES=false
DRY_RUN=false
OS=""
HAS_SYSTEMD=false
SUDO_CMD=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --backup                  Create a backup archive before removing files
  --backup-dir <dir>        Directory for backup archives (default: ~/iket-backups)
  --purge-state             Remove ~/.iket after uninstalling binaries/service
  --cli-only                Remove only iket, leave server/service installed
  --config-dir <dir>        Override the Iket state/config directory (default: ~/.iket)
  --service-name <name>     Override the systemd service name (default: iket)
  --yes                     Skip confirmation prompts
  --dry-run                 Show what would be removed without changing anything
  -h, --help                Show this help message

Examples:
  $(basename "$0")
  $(basename "$0") --backup
  $(basename "$0") --backup --purge-state
  $(basename "$0") --cli-only
EOF
}

run_cmd() {
    if [ "$DRY_RUN" = true ]; then
        echo "DRY-RUN: $*"
    else
        "$@"
    fi
}

run_shell() {
    local cmd="$1"
    if [ "$DRY_RUN" = true ]; then
        echo "DRY-RUN: $cmd"
    else
        eval "$cmd"
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --backup)
                BACKUP_STATE=true
                shift
                ;;
            --backup-dir)
                BACKUP_DIR="$2"
                shift 2
                ;;
            --purge-state)
                PURGE_STATE=true
                shift
                ;;
            --cli-only)
                CLI_ONLY=true
                shift
                ;;
            --config-dir)
                CONFIG_DIR="$2"
                shift 2
                ;;
            --service-name)
                SERVICE_NAME="$2"
                shift 2
                ;;
            --yes)
                ASSUME_YES=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

detect_platform() {
    case "$(uname -s)" in
        Linux*)  OS="linux" ;;
        Darwin*) OS="darwin" ;;
        *)       OS="unknown" ;;
    esac

    if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1; then
        HAS_SYSTEMD=true
    fi

    if [ "$EUID" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
        SUDO_CMD="sudo"
    fi

    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
}

validate_paths() {
    if [ -z "${CONFIG_DIR}" ] || [ "$CONFIG_DIR" = "/" ]; then
        print_error "Refusing to operate on unsafe config dir: '$CONFIG_DIR'"
        exit 1
    fi

    if [ -z "${BACKUP_DIR}" ] || [ "$BACKUP_DIR" = "/" ]; then
        print_error "Refusing to use unsafe backup dir: '$BACKUP_DIR'"
        exit 1
    fi
}

confirm() {
    if [ "$ASSUME_YES" = true ] || [ "$DRY_RUN" = true ]; then
        return 0
    fi

    echo ""
    print_warning "This will remove installed Iket binaries."
    if [ "$CLI_ONLY" = true ]; then
        echo "  - ${INSTALL_DIR}/iket"
    else
        echo "  - ${INSTALL_DIR}/iket"
        echo "  - ${INSTALL_DIR}/iket-server"
        echo "  - ${INSTALL_DIR}/iket-gateway"
        echo "  - ${SERVICE_FILE} (if present)"
    fi
    if [ "$PURGE_STATE" = true ]; then
        echo "  - ${CONFIG_DIR}"
    else
        echo "  - ${CONFIG_DIR} will be kept"
    fi
    if [ "$BACKUP_STATE" = true ]; then
        echo "  - Backup archive will be created in ${BACKUP_DIR}"
    fi
    echo ""
    read -r -p "Continue? [y/N] " reply
    case "$reply" in
        y|Y|yes|YES) ;;
        *)
            print_info "Aborted."
            exit 0
            ;;
    esac
}

backup_state() {
    if [ "$BACKUP_STATE" != true ]; then
        return 0
    fi

    print_step "Backing Up Iket State"

    local timestamp
    timestamp=$(date +"%Y%m%d-%H%M%S")
    local archive_name="iket-backup-${timestamp}.tar.gz"
    local archive_path="${BACKUP_DIR%/}/${archive_name}"
    local staging_dir
    staging_dir=$(mktemp -d)

    mkdir -p "$staging_dir"
    run_cmd mkdir -p "$BACKUP_DIR"

    if [ -d "$CONFIG_DIR" ]; then
        run_cmd cp -R "$CONFIG_DIR" "$staging_dir/config"
    else
        print_warning "Config/state directory not found: $CONFIG_DIR"
    fi

    if [ -f "$SERVICE_FILE" ]; then
        run_cmd mkdir -p "$staging_dir/systemd"
        run_cmd cp "$SERVICE_FILE" "$staging_dir/systemd/$(basename "$SERVICE_FILE")"
    fi

    cat > "$staging_dir/manifest.txt" <<EOF
iket uninstall backup
created_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
original_user=$ORIGINAL_USER
config_dir=$CONFIG_DIR
service_name=$SERVICE_NAME
service_file=$SERVICE_FILE
cli_only=$CLI_ONLY
purge_state=$PURGE_STATE
EOF

    if [ "$DRY_RUN" = true ]; then
        echo "DRY-RUN: tar -czf \"$archive_path\" -C \"$staging_dir\" ."
    else
        tar -czf "$archive_path" -C "$staging_dir" .
        print_success "Backup created: $archive_path"
    fi

    rm -rf "$staging_dir"
}

stop_and_remove_service() {
    if [ "$CLI_ONLY" = true ]; then
        return 0
    fi

    print_step "Removing Service"

    if [ "$HAS_SYSTEMD" = true ]; then
        if systemctl list-unit-files "${SERVICE_NAME}.service" >/dev/null 2>&1 || [ -f "$SERVICE_FILE" ]; then
            run_shell "$SUDO_CMD systemctl stop ${SERVICE_NAME} >/dev/null 2>&1 || true"
            run_shell "$SUDO_CMD systemctl disable ${SERVICE_NAME} >/dev/null 2>&1 || true"
        fi
    fi

    if [ -f "$SERVICE_FILE" ]; then
        run_shell "$SUDO_CMD rm -f \"$SERVICE_FILE\""
        if [ "$HAS_SYSTEMD" = true ]; then
            run_shell "$SUDO_CMD systemctl daemon-reload >/dev/null 2>&1 || true"
        fi
        print_success "Removed service file: $SERVICE_FILE"
    else
        print_info "No service file found at $SERVICE_FILE"
    fi
}

remove_binaries() {
    print_step "Removing Binaries"

    local binaries=("$INSTALL_DIR/iket")
    if [ "$CLI_ONLY" != true ]; then
        binaries+=("$INSTALL_DIR/iket-server" "$INSTALL_DIR/iket-gateway")
    fi

    local existing=()
    local bin
    for bin in "${binaries[@]}"; do
        if [ -e "$bin" ]; then
            existing+=("$bin")
        fi
    done

    if [ ${#existing[@]} -eq 0 ]; then
        print_info "No matching binaries found."
        return 0
    fi

    local cmd="$SUDO_CMD rm -f"
    for bin in "${existing[@]}"; do
        cmd="$cmd \"$bin\""
    done
    run_shell "$cmd"
    print_success "Removed ${#existing[@]} binary file(s)."
}

purge_state() {
    if [ "$PURGE_STATE" != true ]; then
        print_info "Keeping Iket state in $CONFIG_DIR"
        return 0
    fi

    print_step "Purging State"
    if [ -d "$CONFIG_DIR" ]; then
        run_shell "rm -rf \"$CONFIG_DIR\""
        print_success "Removed state directory: $CONFIG_DIR"
    else
        print_info "No state directory found at $CONFIG_DIR"
    fi
}

print_summary() {
    print_step "Uninstall Summary"
    print_success "Iket uninstall completed."
    echo ""
    echo -e "  ${BLUE}Binaries:${NC}       Removed"
    if [ "$CLI_ONLY" != true ]; then
        echo -e "  ${BLUE}Service:${NC}        ${SERVICE_FILE}"
    fi
    if [ "$PURGE_STATE" = true ]; then
        echo -e "  ${BLUE}State:${NC}          Removed (${CONFIG_DIR})"
    else
        echo -e "  ${BLUE}State:${NC}          Preserved (${CONFIG_DIR})"
    fi
    if [ "$BACKUP_STATE" = true ]; then
        echo -e "  ${BLUE}Backup Dir:${NC}     ${BACKUP_DIR}"
    fi
}

main() {
    parse_args "$@"
    detect_platform
    validate_paths

    echo -e "${CYAN}"
    echo "  🧶  IKET UNINSTALLER"
    if [ "$CLI_ONLY" = true ]; then
        echo "  (CLI ONLY MODE)"
    fi
    if [ "$PURGE_STATE" = true ]; then
        echo "  (PURGE STATE MODE)"
    fi
    if [ "$DRY_RUN" = true ]; then
        echo "  (DRY RUN MODE)"
    fi
    echo "  ──────────────────────────"
    echo -e "${NC}"

    confirm
    backup_state
    stop_and_remove_service
    remove_binaries
    purge_state
    print_summary
}

main "$@"
