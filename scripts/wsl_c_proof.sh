#!/usr/bin/env bash
# One-shot proof of the unified run_pipeline() C mode under WSL.
set -e
REPO="/mnt/c/Users/panka/OneDrive/Desktop/hack/ai-kavach-crs"
WS="/tmp/kavach_wsl_demo"

rm -rf "$WS"
mkdir -p "$WS/target"
cp "$REPO/targets/sample_vuln/vuln.c" "$WS/target/"
cp "$REPO/targets/build_target.sh" "$WS/"

cd "$REPO"
export FUZZ_TIMEOUT_S="${FUZZ_TIMEOUT_S:-45}"
exec .venv-wsl/bin/python -m ai_kavach.orchestrator \
  --target /tmp/kavach_wsl_demo/target \
  --run-id wsl-c-proof
