#!/usr/bin/env bash
# Minimal Linux venv for running the C pipeline under WSL.
set -e
REPO="/mnt/c/Users/panka/OneDrive/Desktop/hack/ai-kavach-crs"
cd "$REPO"
if [ ! -x .venv-wsl/bin/python ]; then
  python3 -m venv .venv-wsl
  .venv-wsl/bin/pip install --quiet python-dotenv openai
fi
.venv-wsl/bin/python -c "import dotenv, openai; print('WSL venv OK')"
