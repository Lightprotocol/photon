#!/bin/bash

# Block Dumping Demo Script for Photon Indexer
# This script demonstrates the block dumping and loading features

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
DEMO_DIR="./demo_dumps"
PHOTON_BIN="./target/debug/photon"
DUMP_MANAGER_BIN="./target/debug/photon-dump-manager"
RPC_URL="http://127.0.0.1:8899"

# Check if binaries exist
check_binaries() {
    log_info "Checking if Photon binaries are built..."

    if [[ ! -f "$PHOTON_BIN" ]]; then
        log_error "Photon binary not found at $PHOTON_BIN"
        log_info "Please run: cargo build --bin photon"
        exit 1
    fi

    if [[ ! -f "$DUMP_MANAGER_BIN" ]]; then
        log_error "Dump manager binary not found at $DUMP_MANAGER_BIN"
        log_info "Please run: cargo build --bin photon-dump-manager"
        exit 1
    fi

    log_success "Binaries found!"
}

# Setup demo environment
setup_demo() {
    log_info "Setting up demo environment..."

    # Clean up previous demo
    if [[ -d "$DEMO_DIR" ]]; then
        log_warning "Removing existing demo directory: $DEMO_DIR"
        rm -rf "$DEMO_DIR"
    fi

    # Create demo directory
    mkdir -p "$DEMO_DIR"
    log_success "Demo directory created: $DEMO_DIR"
}

# Demonstrate block dumping
demo_block_dumping() {
    log_info "=== DEMO: Block Dumping ==="
    log_info "This demo shows how to enable block dumping during indexing"

    log_info "Starting Photon with block dumping enabled..."
    log_info "Command: $PHOTON_BIN --enable-block-dump --dump-dir $DEMO_DIR --blocks-per-dump-file 10 --dump-format json --disable-api --start-slot latest"

    # Note: In a real demo, you would run this against a local validator
    # For this demo, we'll show the command and simulate with a timeout
    echo ""
    echo "# This would start Photon with block dumping:"
    echo "$PHOTON_BIN \\"
    echo "  --enable-block-dump \\"
    echo "  --dump-dir $DEMO_DIR \\"
    echo "  --blocks-per-dump-file 10 \\"
    echo "  --dump-format json \\"
    echo "  --disable-api \\"
    echo "  --start-slot latest"
    echo ""

    log_warning "NOTE: This demo requires a running Solana validator"
    log_warning "To run against localnet, start a validator first:"
    log_warning "  solana-test-validator"

    # Create some sample dump files for demonstration
    create_sample_dumps
}

# Create sample dump files for demonstration
create_sample_dumps() {
    log_info "Creating sample dump files for demonstration..."

    # Sample block data (simplified)
    cat > "$DEMO_DIR/blocks_0000000000001000_0000000000001009.json" << 'EOF'
{
  "blocks": [
    {
      "metadata": {
        "slot": 1000,
        "parent_slot": 999,
        "block_time": 1703123456,
        "blockhash": "11111111111111111111111111111112",
        "parent_blockhash": "11111111111111111111111111111112",
        "block_height": 1000
      },
      "transactions": []
    }
  ],
  "metadata": {
    "start_slot": 1000,
    "end_slot": 1009,
    "block_count": 10,
    "created_at": 1703123456
  }
}
EOF

    # Sample metadata file
    cat > "$DEMO_DIR/blocks_0000000000001000_0000000000001009.meta" << 'EOF'
{
  "file_path": "./demo_dumps/blocks_0000000000001000_0000000000001009.json",
  "start_slot": 1000,
  "end_slot": 1009,
  "block_count": 10,
  "format": "json",
  "compressed": false,
  "created_at": 1703123456
}
EOF

    # Create another sample file
    cat > "$DEMO_DIR/blocks_0000000000001010_0000000000001019.json" << 'EOF'
{
  "blocks": [
    {
      "metadata": {
        "slot": 1010,
        "parent_slot": 1009,
        "block_time": 1703123466,
        "blockhash": "11111111111111111111111111111113",
        "parent_blockhash": "11111111111111111111111111111112",
        "block_height": 1010
      },
      "transactions": []
    }
  ],
  "metadata": {
    "start_slot": 1010,
    "end_slot": 1019,
    "block_count": 10,
    "created_at": 1703123466
  }
}
EOF

    cat > "$DEMO_DIR/blocks_0000000000001010_0000000000001019.meta" << 'EOF'
{
  "file_path": "./demo_dumps/blocks_0000000000001010_0000000000001019.json",
  "start_slot": 1010,
  "end_slot": 1019,
  "block_count": 10,
  "format": "json",
  "compressed": false,
  "created_at": 1703123466
}
EOF

    log_success "Sample dump files created!"
}

# Demonstrate dump management
demo_dump_management() {
    log_info "=== DEMO: Dump File Management ==="
    log_info "This demo shows how to manage and inspect dump files"

    echo ""
    log_info "1. Listing dump files:"
    $DUMP_MANAGER_BIN list --dump-dir "$DEMO_DIR"

    echo ""
    log_info "2. Showing detailed information:"
    $DUMP_MANAGER_BIN list --dump-dir "$DEMO_DIR" --verbose

    echo ""
    log_info "3. Showing statistics:"
    $DUMP_MANAGER_BIN stats --dump-dir "$DEMO_DIR"

    echo ""
    log_info "4. Validating dump files:"
    $DUMP_MANAGER_BIN validate --dump-dir "$DEMO_DIR"

    echo ""
    log_info "5. Showing range information:"
    $DUMP_MANAGER_BIN range --dump-dir "$DEMO_DIR" --start-slot 1000 --end-slot 1015
}

# Demonstrate loading from dumps
demo_loading_from_dumps() {
    log_info "=== DEMO: Loading from Dump Files ==="
    log_info "This demo shows how to reindex from dump files"

    echo ""
    log_info "Loading all blocks from dumps:"
    echo "$PHOTON_BIN --load-from-dumps $DEMO_DIR --disable-api"

    echo ""
    log_info "Loading specific slot range from dumps:"
    echo "$PHOTON_BIN --load-from-dumps $DEMO_DIR --dump-start-slot 1000 --dump-end-slot 1015 --disable-api"

    log_warning "NOTE: These commands would actually load and index the blocks"
    log_warning "For this demo, we're showing the commands without executing them"
}

# Show use cases
show_use_cases() {
    log_info "=== USE CASES ==="

    echo ""
    echo "1. BACKUP AND RECOVERY:"
    echo "   # Create backups while indexing"
    echo "   photon --enable-block-dump --dump-dir /backup/blocks"
    echo "   # Restore from backup"
    echo "   photon --load-from-dumps /backup/blocks"

    echo ""
    echo "2. DEVELOPMENT AND TESTING:"
    echo "   # Dump blocks for testing"
    echo "   photon --enable-block-dump --blocks-per-dump-file 100"
    echo "   # Test with specific ranges"
    echo "   photon --load-from-dumps ./dumps --dump-start-slot 1000 --dump-end-slot 2000"

    echo ""
    echo "3. DATA MIGRATION:"
    echo "   # Export in binary format"
    echo "   photon --enable-block-dump --dump-format bincode --dump-dir /export"
    echo "   # Import to new system"
    echo "   photon --load-from-dumps /export"

    echo ""
    echo "4. PERFORMANCE OPTIMIZATION:"
    echo "   # Use bincode for better performance"
    echo "   photon --enable-block-dump --dump-format bincode"
    echo "   # Adjust batch sizes for your use case"
    echo "   photon --enable-block-dump --blocks-per-dump-file 5000"
}

# Cleanup demo
cleanup_demo() {
    log_info "=== CLEANUP ==="
    read -p "Do you want to clean up the demo directory? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$DEMO_DIR"
        log_success "Demo directory cleaned up!"
    else
        log_info "Demo files kept at: $DEMO_DIR"
    fi
}

# Main demo function
main() {
    echo "======================================"
    echo "  PHOTON BLOCK DUMPING DEMO"
    echo "======================================"
    echo ""

    check_binaries
    setup_demo
    demo_block_dumping
    echo ""
    demo_dump_management
    echo ""
    demo_loading_from_dumps
    echo ""
    show_use_cases
    echo ""
    cleanup_demo

    echo ""
    log_success "Demo completed!"
    log_info "For more information, see: BLOCK_DUMPING.md"
}

# Run the demo
main "$@"
