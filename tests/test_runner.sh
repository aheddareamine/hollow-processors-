#!/bin/bash
# Smoke tests for the process hollowing detector.
# Run as root: sudo bash tests/test_runner.sh

set -e

DETECTOR="${1:-./detector}"

if [ ! -f "$DETECTOR" ]; then
    echo "Error: '$DETECTOR' not found. Run 'make' first."
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "Error: tests must run as root."
    echo "  sudo bash $0"
    exit 1
fi

echo "=== Test 1: scan current shell (PID $$) ==="
$DETECTOR -v -p $$
echo ""

echo "=== Test 2: scan init / systemd (PID 1) ==="
$DETECTOR -p 1
echo ""

echo "=== Test 3: full scan with JSON report ==="
REPORT=$(mktemp /tmp/detector_XXXXXX.json)
$DETECTOR --report "$REPORT"
echo ""
echo "First 10 lines of report:"
head -10 "$REPORT"
rm -f "$REPORT"
echo ""

echo "=== All tests passed ==="
