#!/bin/bash
set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Track if we're in the middle of processing an epoch
CURRENT_EPOCH=""
RPC_PID=""

# Cleanup function for graceful shutdown
cleanup() {
    local exit_code=$?
    log_warn "Caught interrupt signal, cleaning up..."

    # Kill RPC server if running
    if [ -n "$RPC_PID" ] && kill -0 $RPC_PID 2>/dev/null; then
        log_info "Stopping RPC server (PID: $RPC_PID)..."
        kill $RPC_PID 2>/dev/null || true
        wait $RPC_PID 2>/dev/null || true
    fi

    if [ -n "$CURRENT_EPOCH" ]; then
        log_error "Interrupted while processing epoch $CURRENT_EPOCH"
        log_error "You may need to reprocess this epoch from where it left off"
    fi

    exit 130  # Standard exit code for SIGINT
}

# Set up trap for SIGINT (Ctrl+C) and SIGTERM
trap cleanup SIGINT SIGTERM

# Configuration
START_SLOT=${START_SLOT:-286193746}
END_SLOT=${END_SLOT:-388871421}
SNAPSHOT_DIR=${SNAPSHOT_DIR:-"$PROJECT_DIR/snapshots"}
WORK_DIR=${WORK_DIR:-"/tmp/old-faithful"}
FAITHFUL_CLI=${FAITHFUL_CLI:-"$PROJECT_DIR/../yellowstone-faithful/yellowstone-faithful"}
SNAPSHOTTER_BIN=${SNAPSHOTTER_BIN:-"$PROJECT_DIR/target/release/photon-snapshotter"}
LOCAL_RPC_PORT=${LOCAL_RPC_PORT:-8899}
SNAPSHOT_INTERVAL=${SNAPSHOT_INTERVAL:-10000}
FULL_SNAPSHOT_INTERVAL=${FULL_SNAPSHOT_INTERVAL:-100000}
MAX_CONCURRENT_FETCHES=${MAX_CONCURRENT_FETCHES:-100}

# Constants
SLOTS_PER_EPOCH=432000
BASE_URL="https://files.old-faithful.net"

# Calculate epoch from slot
slot_to_epoch() {
    echo $(( $1 / SLOTS_PER_EPOCH ))
}

# Calculate first slot of epoch
epoch_start_slot() {
    echo $(( $1 * SLOTS_PER_EPOCH ))
}

# Calculate last slot of epoch
epoch_end_slot() {
    echo $(( ($1 + 1) * SLOTS_PER_EPOCH - 1 ))
}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Create work directory
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Calculate epoch range
START_EPOCH=$(slot_to_epoch $START_SLOT)
END_EPOCH=$(slot_to_epoch $END_SLOT)

log_info "Slot range: $START_SLOT - $END_SLOT"
log_info "Epoch range: $START_EPOCH - $END_EPOCH ($(( END_EPOCH - START_EPOCH + 1 )) epochs)"
log_info "Work directory: $WORK_DIR"
log_info "Estimated storage needed: ~600GB per epoch (temporary)"

# Check for faithful-cli
if ! command -v $FAITHFUL_CLI &> /dev/null; then
    log_error "faithful-cli not found. Install from: https://github.com/rpcpool/yellowstone-faithful"
    log_info "Quick install:"
    log_info "  git clone https://github.com/rpcpool/yellowstone-faithful"
    log_info "  cd yellowstone-faithful && make build"
    log_info "  export PATH=\$PATH:\$(pwd)"
    exit 1
fi

# Check for snapshotter
if [ ! -f "$SNAPSHOTTER_BIN" ]; then
    log_error "Snapshotter not found at $SNAPSHOTTER_BIN"
    log_info "Build with: cargo build --release --bin photon-snapshotter"
    exit 1
fi

# Create snapshot directory
mkdir -p "$SNAPSHOT_DIR"
log_info "Snapshots will be stored in: $SNAPSHOT_DIR"

# Process each epoch
for EPOCH in $(seq $START_EPOCH $END_EPOCH); do
    CURRENT_EPOCH=$EPOCH
    EPOCH_START=$(epoch_start_slot $EPOCH)
    EPOCH_END=$(epoch_end_slot $EPOCH)

    # Calculate actual slot range for this epoch
    ACTUAL_START=$START_SLOT
    ACTUAL_END=$END_SLOT
    [ $EPOCH_START -gt $ACTUAL_START ] && ACTUAL_START=$EPOCH_START
    [ $EPOCH_END -lt $ACTUAL_END ] && ACTUAL_END=$EPOCH_END

    log_info "=========================================="
    log_info "Processing Epoch $EPOCH / $END_EPOCH"
    log_info "Epoch slots: $EPOCH_START - $EPOCH_END"
    log_info "Processing slots: $ACTUAL_START - $ACTUAL_END"
    log_info "=========================================="

    EPOCH_DIR="$WORK_DIR/epoch-$EPOCH"
    mkdir -p "$EPOCH_DIR"
    cd "$EPOCH_DIR"

    # Step 1: Get the CID for this epoch
    log_info "Step 1: Fetching epoch CID..."
    CID_URL="$BASE_URL/$EPOCH/epoch-$EPOCH.cid"
    if ! curl -sf "$CID_URL" -o epoch-$EPOCH.cid; then
        log_error "Failed to fetch CID for epoch $EPOCH. Epoch may not be available yet."
        log_warn "Skipping epoch $EPOCH"
        cd "$WORK_DIR"
        rm -rf "$EPOCH_DIR"
        continue
    fi
    CID=$(cat epoch-$EPOCH.cid)
    log_info "CID: $CID"

    # Step 2: Download epoch CAR file
    CAR_FILE="epoch-$EPOCH.car"
    CAR_URL="$BASE_URL/$EPOCH/$CAR_FILE"

    # Get expected file size from server
    EXPECTED_SIZE=$(curl -sI "$CAR_URL" | grep -i content-length | awk '{print $2}' | tr -d '\r')

    NEED_DOWNLOAD=true
    if [ -f "$CAR_FILE" ]; then
        LOCAL_SIZE=$(stat -f%z "$CAR_FILE" 2>/dev/null || stat -c%s "$CAR_FILE" 2>/dev/null)
        if [ -n "$EXPECTED_SIZE" ] && [ "$LOCAL_SIZE" = "$EXPECTED_SIZE" ]; then
            log_info "Step 2: CAR file already exists and is complete ($LOCAL_SIZE bytes), skipping download"
            NEED_DOWNLOAD=false
        else
            log_warn "Step 2: CAR file exists but is incomplete (local: $LOCAL_SIZE, expected: $EXPECTED_SIZE)"
            log_info "Resuming download..."
        fi
    fi

    if [ "$NEED_DOWNLOAD" = true ]; then
        log_info "Step 2: Downloading CAR file (~500GB)..."
        log_info "URL: $CAR_URL"

        # Use aria2c for faster downloads if available, otherwise curl with resume support
        if command -v aria2c &> /dev/null; then
            aria2c -x 16 -s 16 -k 100M -c "$CAR_URL" -o "$CAR_FILE" || {
                log_error "Failed to download CAR file"
                exit 1
            }
        else
            curl -L -C - --progress-bar "$CAR_URL" -o "$CAR_FILE" || {
                log_error "Failed to download CAR file"
                exit 1
            }
        fi
    fi

    # Step 3: Download indexes
    log_info "Step 3: Downloading indexes..."

    INDEX_FILES=(
        "epoch-$EPOCH-$CID-mainnet-cid-to-offset-and-size.index"
        "epoch-$EPOCH-$CID-mainnet-sig-exists.index"
        "epoch-$EPOCH-$CID-mainnet-sig-to-cid.index"
        "epoch-$EPOCH-$CID-mainnet-slot-to-blocktime.index"
        "epoch-$EPOCH-$CID-mainnet-slot-to-cid.index"
    )

    for INDEX_FILE in "${INDEX_FILES[@]}"; do
        if [ -f "$INDEX_FILE" ]; then
            log_info "  $INDEX_FILE already exists"
        else
            INDEX_URL="$BASE_URL/$EPOCH/$INDEX_FILE"
            log_info "  Downloading $INDEX_FILE..."
            curl -L --progress-bar "$INDEX_URL" -o "$INDEX_FILE" || {
                log_warn "Failed to download $INDEX_FILE, will generate locally"
            }
        fi
    done

    # Step 3b: Generate missing indexes if needed
    MISSING_INDEXES=false
    for INDEX_FILE in "${INDEX_FILES[@]}"; do
        if [ ! -f "$INDEX_FILE" ]; then
            MISSING_INDEXES=true
            break
        fi
    done

    if [ "$MISSING_INDEXES" = true ]; then
        log_info "Step 3b: Generating missing indexes locally..."
        $FAITHFUL_CLI index all "$CAR_FILE" . --network mainnet || {
            log_error "Failed to generate indexes"
            exit 1
        }
    fi

    # Step 4: Start faithful RPC server
    log_info "Step 4: Starting Old Faithful RPC server on port $LOCAL_RPC_PORT..."

    # Kill any existing process on the port (use fuser as fallback if lsof hangs)
    if command -v fuser &> /dev/null; then
        fuser -k $LOCAL_RPC_PORT/tcp 2>/dev/null || true
    else
        # Try to connect to see if port is in use, then use pkill
        if nc -z 127.0.0.1 $LOCAL_RPC_PORT 2>/dev/null; then
            log_warn "Port $LOCAL_RPC_PORT is in use, attempting to free it..."
            pkill -f "rpc.*:$LOCAL_RPC_PORT" 2>/dev/null || true
            sleep 1
        fi
    fi

    # Create epoch config for faithful-cli
    cat > epoch-config.yaml << EOF
version: 1
epoch: $EPOCH
data:
  car:
    uri: $EPOCH_DIR/$CAR_FILE
indexes:
  cid_to_offset_and_size:
    uri: $EPOCH_DIR/epoch-$EPOCH-$CID-mainnet-cid-to-offset-and-size.index
  slot_to_cid:
    uri: $EPOCH_DIR/epoch-$EPOCH-$CID-mainnet-slot-to-cid.index
  sig_to_cid:
    uri: $EPOCH_DIR/epoch-$EPOCH-$CID-mainnet-sig-to-cid.index
  sig_exists:
    uri: $EPOCH_DIR/epoch-$EPOCH-$CID-mainnet-sig-exists.index
  slot_to_blocktime:
    uri: $EPOCH_DIR/epoch-$EPOCH-$CID-mainnet-slot-to-blocktime.index
EOF

    # Start RPC server in background (redirect output to log file)
    RPC_LOG="$EPOCH_DIR/rpc.log"
    $FAITHFUL_CLI rpc --listen ":$LOCAL_RPC_PORT" "$EPOCH_DIR" > "$RPC_LOG" 2>&1 &
    RPC_PID=$!

    # Wait for RPC to be ready
    log_info "Waiting for RPC server to start (PID: $RPC_PID, log: $RPC_LOG)..."
    sleep 5

    # Check if process is still running
    if ! kill -0 $RPC_PID 2>/dev/null; then
        log_error "RPC server failed to start. Log output:"
        cat "$RPC_LOG"
        exit 1
    fi

    for i in {1..30}; do
        if curl -sf "http://127.0.0.1:$LOCAL_RPC_PORT" -X POST \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","id":1,"method":"getSlot"}' > /dev/null 2>&1; then
            log_info "RPC server is ready!"
            break
        fi
        sleep 2
    done

    # Step 5: Run snapshotter
    log_info "Step 5: Running snapshotter for slots $ACTUAL_START - $ACTUAL_END..."

    cd "$WORK_DIR"

    # Run snapshotter with local RPC (with end-slot to stop at epoch boundary)
    $SNAPSHOTTER_BIN \
        --rpc-url "http://127.0.0.1:$LOCAL_RPC_PORT" \
        --snapshot-dir "$SNAPSHOT_DIR" \
        --start-slot "$ACTUAL_START" \
        --end-slot "$ACTUAL_END" \
        --incremental-snapshot-interval-slots "$SNAPSHOT_INTERVAL" \
        --snapshot-interval-slots "$FULL_SNAPSHOT_INTERVAL" \
        -m "$MAX_CONCURRENT_FETCHES" \
        --disable-api

    log_info "Snapshotter finished for epoch $EPOCH"

    # Step 6: Cleanup
    log_info "Step 6: Cleaning up epoch $EPOCH..."

    # Kill the RPC server
    kill $RPC_PID 2>/dev/null || true
    wait $RPC_PID 2>/dev/null || true

    # Remove epoch data to free space
    cd "$WORK_DIR"
    rm -rf "$EPOCH_DIR"

    log_info "Epoch $EPOCH complete! Freed ~600GB"
    log_info ""

    # Clear current epoch marker (epoch completed successfully)
    CURRENT_EPOCH=""
    RPC_PID=""

    # Update start slot for next iteration
    START_SLOT=$((EPOCH_END + 1))
done

log_info "=========================================="
log_info "All epochs processed!"
log_info "=========================================="
