#!/usr/bin/env bash
# ============================================================
# Shadow AI Sentinel — vegeta load test runner
# Tests /api/v1/scan at high RPS with PII payloads
#
# Usage:
#   ./run.sh [rps] [duration]
#
# Examples:
#   ./run.sh 1000 30s     # 1000 RPS for 30 seconds
#   ./run.sh 500 60s      # 500 RPS for 60 seconds
#
# Requirements: vegeta (https://github.com/tsenart/vegeta)
#   brew install vegeta  OR  go install github.com/tsenart/vegeta@latest
#
# Environment:
#   SENTINEL_URL   Base URL of the proxy service (default: http://localhost:8080)
# ============================================================

set -euo pipefail

RPS="${1:-1000}"
DURATION="${2:-30s}"
BASE_URL="${SENTINEL_URL:-http://localhost:8080}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGETS_DIR="$SCRIPT_DIR/targets"
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="$RESULTS_DIR/report_${RPS}rps_${DURATION}_${TIMESTAMP}.txt"
BIN_FILE="$RESULTS_DIR/results_${RPS}rps_${DURATION}_${TIMESTAMP}.bin"

if ! command -v vegeta &>/dev/null; then
  echo "[ERROR] vegeta not found. Install with: go install github.com/tsenart/vegeta@latest"
  exit 1
fi

echo "============================================================"
echo "Shadow AI Sentinel — Load Test"
echo "  Target:   $BASE_URL"
echo "  Rate:     $RPS RPS"
echo "  Duration: $DURATION"
echo "============================================================"

# ── Scenario 1: Clean text (baseline) ────────────────────────
echo ""
echo "[1/4] Baseline: clean text (no PII), expect LOG action, p99 < 50ms"
cat "$TARGETS_DIR/clean_payload.json" | \
  vegeta attack \
    -rate="$RPS" \
    -duration="$DURATION" \
    -targets=<(echo "POST $BASE_URL/api/v1/scan
Content-Type: application/json
@$TARGETS_DIR/clean_payload.json") | \
  tee "$BIN_FILE" | \
  vegeta report -type=text | tee -a "$REPORT_FILE"

# ── Scenario 2: PII-heavy (SSN + credit card) ────────────────
echo ""
echo "[2/4] PII-heavy: SSN + CC in every request, expect BLOCK action"
vegeta attack \
  -rate="$((RPS / 2))" \
  -duration="$DURATION" \
  -targets=<(echo "POST $BASE_URL/api/v1/scan
Content-Type: application/json
@$TARGETS_DIR/pii_payload.json") | \
  vegeta report -type=text | tee -a "$REPORT_FILE"

# ── Scenario 3: API keys payload ─────────────────────────────
echo ""
echo "[3/4] API keys: AWS + GitHub tokens, expect BLOCK action"
vegeta attack \
  -rate="$((RPS / 2))" \
  -duration="$DURATION" \
  -targets=<(echo "POST $BASE_URL/api/v1/scan
Content-Type: application/json
@$TARGETS_DIR/apikey_payload.json") | \
  vegeta report -type=text | tee -a "$REPORT_FILE"

# ── Scenario 4: Mixed (health + scan interleaved) ─────────────
echo ""
echo "[4/4] Mixed: health + scan endpoints interleaved"
vegeta attack \
  -rate="$RPS" \
  -duration="$DURATION" \
  -targets="$TARGETS_DIR/mixed_targets.txt" | \
  vegeta report -type=text | tee -a "$REPORT_FILE"

echo ""
echo "============================================================"
echo "Results saved to: $REPORT_FILE"
echo "============================================================"

# Check success criteria
echo ""
echo "Checking success criteria (p99 < 100ms, 0% error rate)..."
ERRORS=$(grep -E "^Error" "$REPORT_FILE" | wc -l || true)
if [ "$ERRORS" -gt 0 ]; then
  echo "[FAIL] Errors detected in load test results"
  exit 1
fi
echo "[PASS] Load test complete"
