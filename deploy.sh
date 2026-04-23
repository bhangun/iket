#!/bin/bash
# =============================================================================
# 🚀 Iket Deployment & Release Automator
# =============================================================================
# This script handles the end-to-end release process for Iket:
# 1. Environment validation (git check)
# 2. Automated testing
# 3. Multi-platform binary compilation
# 4. Git tagging (with optional force-overwrite)
# 5. Remote synchronization (pushing branches and tags)
# =============================================================================

set -euo pipefail

# --- UI / Helper Functions ---

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Logging functions for consistent output
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Step header for clear workflow visibility
print_step() {
    echo ""
    echo -e "${PURPLE}[STEP]${NC} $1"
    echo "─────────────────────────────────────────────────────"
}

# --- Configuration & Defaults ---

VERSION=""
MESSAGE=""
DRY_RUN=false
SKIP_TESTS=false
SKIP_BUILD=false
SKIP_PUSH=false
FORCE=false
REMOTE="origin"
BRANCH="main"

# --- Logic Functions ---

# Display help documentation
show_usage() {
    cat << 'EOF'
Usage: ./deploy.sh [VERSION] [OPTIONS]

Automate Iket deployment: version bump, tag, build, and push.

Required (if not using -v):
  VERSION                     Version number (e.g., 0.2.12)

Options:
  -v, --version VERSION       Specify version number
  -m, --message MESSAGE       Custom git tag message (comment)
  --dry-run                   Show what would be done without executing
  --force                     Overwrite existing tag (locally and on remote)
  --skip-tests                Skip running tests before deployment
  --skip-build                Skip building binaries
  --skip-push                 Skip pushing to remote (create tag only)
  --remote REMOTE             Remote name (default: origin)
  --branch BRANCH             Branch name (default: main)
  --help                      Show this help message

Examples:
  ./deploy.sh 0.1.0 -m "Initial stable release"
  ./deploy.sh -v 0.2.0 --force
EOF
    exit 0
}

# Parse command line arguments
parse_args() {
    # Check if at least one argument is provided
    if [[ $# -eq 0 ]]; then show_usage; fi
    
    # Check if first argument is a version number (doesn't start with -)
    if [[ ! "$1" =~ ^- ]]; then
        VERSION="$1"
        shift
    fi
    
    # Process remaining optional flags
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--version) VERSION="$2"; shift 2 ;;
            -m|--message) MESSAGE="$2"; shift 2 ;;
            --dry-run)    DRY_RUN=true; shift ;;
            --force)      FORCE=true; shift ;;
            --skip-tests) SKIP_TESTS=true; shift ;;
            --skip-build) SKIP_BUILD=true; shift ;;
            --skip-push)  SKIP_PUSH=true; shift ;;
            --remote)     REMOTE="$2"; shift 2 ;;
            --branch)     BRANCH="$2"; shift 2 ;;
            --help|-h)    show_usage ;;
            *)            print_error "Unknown option: $1"; show_usage ;;
        esac
    done

    # Final check for version
    if [[ -z "$VERSION" ]]; then
        print_error "Version number is required."
        show_usage
    fi
}

# Ensure we are in a valid git repository
validate_environment() {
    print_step "Validating Environment"
    if ! git rev-parse --git-dir &> /dev/null; then 
        print_error "Not a git repository. Please run this script from within the Iket repo."
        exit 1
    fi
    print_success "Environment validation passed."
}

# Run the full test suite
run_tests() {
    if [[ "$SKIP_TESTS" == true ]]; then 
        print_info "Skipping tests as requested."
        return 0 
    fi
    
    print_step "Running Tests"
    go test ./...
    print_success "All tests passed."
}

# Invoke the build script to generate binaries
build_binaries() {
    if [[ "$SKIP_BUILD" == true ]]; then 
        print_info "Skipping build as requested."
        return 0 
    fi
    
    print_step "Building Binaries (v$VERSION)"
    ./build-iket.sh
    print_success "Binaries built successfully."
}

# Create a git tag for the new version
create_tag() {
    local tag_name="v$VERSION"
    # Use provided message or fallback to default
    local tag_msg="${MESSAGE:-Release $tag_name}"
    
    # Check if the tag already exists
    if git rev-parse "$tag_name" >/dev/null 2>&1; then
        if [[ "$FORCE" == true ]]; then
            print_warning "Tag $tag_name already exists. Overwriting due to --force..."
            # Delete local tag if not in dry-run mode
            if [[ "$DRY_RUN" == false ]]; then
                git tag -d "$tag_name"
            fi
        else
            print_error "Tag $tag_name already exists. Use --force to overwrite if you're sure."
            exit 1
        fi
    fi

    # Dry run check
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would create tag $tag_name with message: \"$tag_msg\""
        return 0
    fi
    
    print_step "Creating Git Tag $tag_name"
    git tag -a "$tag_name" -m "$tag_msg"
    print_success "Created tag $tag_name locally with message: \"$tag_msg\""
}

# Push changes to the remote repository
push_to_remote() {
    if [[ "$SKIP_PUSH" == true ]]; then 
        print_info "Skipping push as requested."
        return 0 
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would push branch and tag to $REMOTE"
        return 0
    fi
    
    print_step "Pushing to $REMOTE"
    
    # 1. Push the main branch
    git push "$REMOTE" "$BRANCH"
    
    # 2. Push the version tag
    local force_flag=""
    if [[ "$FORCE" == true ]]; then
        force_flag="--force"
        print_warning "Using --force to push tag v$VERSION to remote."
    fi
    
    git push "$REMOTE" "v$VERSION" $force_flag
    print_success "Pushed to $REMOTE."
}

# --- Main Execution Flow ---

main() {
    parse_args "$@"
    
    echo -e "${PURPLE}"
    echo "  🧶  IKET RELEASE PROCESS (v$VERSION)"
    if [[ "$DRY_RUN" == true ]]; then echo "      *** DRY RUN MODE ***"; fi
    echo "  ──────────────────────────────────────────"
    echo -e "${NC}"

    validate_environment
    run_tests
    build_binaries
    create_tag
    push_to_remote
    
    print_step "Release Summary"
    print_success "Deployment of v$VERSION complete!"
    echo ""
    print_info "Version:   $VERSION"
    print_info "Remote:    $REMOTE"
    print_info "Branch:    $BRANCH"
    echo ""
}

main "$@"
