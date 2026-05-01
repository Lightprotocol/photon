#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CAPTURE="$SCRIPT_DIR/tests/fixtures/shielded_pool_proofless_append_capture.json"

cd "$REPO_ROOT"

SBF_OUT_DIR="${SBF_OUT_DIR:-$REPO_ROOT/target/deploy}" \
PHOTON_PROOFLESS_APPEND_CAPTURE_EXPECTED="$CAPTURE" \
cargo test \
  -p system-cpi-v2-test \
  --features test-sbf \
  proofless_shielded_append_emits_light_and_shielded_events \
  -- --nocapture
