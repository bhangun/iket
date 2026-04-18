#!/bin/bash
# =============================================================================
# Iket Deployment Script
# =============================================================================
# Automates version bumping, tagging, building, and pushing to GitHub
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
print_step() {
    echo ""
    echo -e "${PURPLE}[STEP]${NC} $1"
    echo "─────────────────────────────────────────────────────"
}

# Default values
VERSION=""
DRY_RUN=false
SKIP_TESTS=false
SKIP_BUILD=false
SKIP_PUSH=false
REMOTE="origin"
BRANCH="main"

show_usage() {
    cat << 'EOF'
Usage: ./deploy.sh VERSION [OPTIONS]

Automate Iket deployment: version bump, tag, build, and push.

Required:
  VERSION                     Version number (e.g., 0.2.12)

Options:
  --dry-run                   Show what would be done without executing
  --skip-tests                Skip running tests
  --skip-build                Skip building binaries
  --skip-push                 Skip pushing to remote (tag only)
  --remote REMOTE             Remote name (default: origin)
  --branch BRANCH             Branch name (default: main)
  --help                      Show this help message
EOF
    exit 0
}

parse_args() {
    if [[ $# -eq 0 ]]; then show_usage; fi
    VERSION="$1"
    shift
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run) DRY_RUN=true; shift ;;
            --skip-tests) SKIP_TESTS=true; shift ;;
            --skip-build) SKIP_BUILD=true; shift ;;
            --skip-push) SKIP_PUSH=true; shift ;;
            --remote) REMOTE="$2"; shift 2 ;;
            --branch) BRANCH="$2"; shift 2 ;;
            --help|-h) show_usage ;;
            *) print_error "Unknown option: $1"; show_usage ;;
        esac
    done
}

validate_environment() {
    print_step "Validating Environment"
    if ! git rev-parse --git-dir &> /dev/null; then print_error "Not a git repository"; exit 1; fi
    print_success "Environment validation passed"
}

run_tests() {
    if [[ "$SKIP_TESTS" == true ]]; then return 0; fi
    print_step "Running Tests"
    go test ./...
    print_success "All tests passed"
}

build_binaries() {
    if [[ "$SKIP_BUILD" == true ]]; then return 0; fi
    print_step "Building Binaries (v$VERSION)"
    ./build-iket.sh
    print_success "Binaries built successfully"
}

create_tag() {
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would create tag v$VERSION"
        return 0
    fi
    print_step "Creating Git Tag v$VERSION"
    git tag -a "v$VERSION" -m "Release v$VERSION"
    print_success "Created tag v$VERSION"
}

push_to_remote() {
    if [[ "$SKIP_PUSH" == true || "$DRY_RUN" == true ]]; then return 0; fi
    print_step "Pushing to $REMOTE"
    git push "$REMOTE" "$BRANCH"
    git push "$REMOTE" "v$VERSION"
    print_success "Pushed to $REMOTE"
}

main() {
    parse_args "$@"
    validate_environment
    run_tests
    build_binaries
    create_tag
    push_to_remote
    print_success "Deployment of v$VERSION complete!"
}

main "$@"
