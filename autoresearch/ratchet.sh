#!/bin/bash
# AutoResearch Ratchet Setup
# Creates a branch, runs baseline evaluation, and prints the command to start the agent loop.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_DIR"

TAG=${1:-$(date +%Y%m%d-%H%M%S)}
BRANCH="autoresearch/$TAG"

echo "=== AppReagent AutoResearch ==="
echo "Tag: $TAG"
echo "Branch: $BRANCH"
echo ""

# Create branch
git checkout -b "$BRANCH"

# Initialize results log
echo -e "experiment\ttimestamp\tscore\tbaseline\tdescription" > autoresearch/results.tsv

# Build
echo "Building..."
make -j"$(nproc)" 2>&1 | tail -1

# Run baseline evaluation
echo ""
echo "Running baseline evaluation..."
BASELINE=$(./autoresearch/evaluate.sh 2>/tmp/area-eval-detail.txt)

if [[ "$BASELINE" == FAIL:* ]]; then
    echo "Baseline evaluation failed: $BASELINE"
    cat /tmp/area-eval-detail.txt
    exit 1
fi

echo -e "0\t$(date +%s)\t$BASELINE\t$BASELINE\tbaseline" >> autoresearch/results.tsv
git add autoresearch/results.tsv
git commit -m "autoresearch: baseline $BASELINE"

echo ""
echo "Per-file breakdown:"
cat /tmp/area-eval-detail.txt
echo ""
echo "=== Baseline score: $BASELINE ==="
echo ""
echo "Ready. Start the agent with:"
echo "  claude --prompt 'Read autoresearch/program.md and begin the AutoResearch loop. Current baseline: $BASELINE'"
