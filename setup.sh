#!/usr/bin/env bash
# setup.sh — create a virtual environment and install project dependencies
# Usage:
#   ./setup.sh        # uses system python3
#   PYTHON=python3.10 ./setup.sh   # use a specific python executable

set -euo pipefail

PYTHON="${PYTHON:-python3}"
VENV_DIR=".venv"
REQ_FILE="requirements.txt"

echo "[setup] Using Python: $PYTHON"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Error: $PYTHON not found on PATH" >&2
  exit 2
fi

if [ -d "$VENV_DIR" ]; then
  echo "[setup] Virtual environment $VENV_DIR already exists. Reusing it." 
else
  echo "[setup] Creating venv in $VENV_DIR..."
  "$PYTHON" -m venv "$VENV_DIR"
fi

echo "[setup] Upgrading pip, setuptools, wheel inside venv..."
"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel

if [ -f "$REQ_FILE" ]; then
  echo "[setup] Installing from $REQ_FILE..."
  "$VENV_DIR/bin/pip" install -r "$REQ_FILE"
else
  echo "[setup] $REQ_FILE not found — installing recommended minimal deps (pysocks, stem)" 
  "$VENV_DIR/bin/pip" install pysocks stem
fi

echo
echo "[setup] Done. Activate the venv with:"
echo "  source $VENV_DIR/bin/activate"
echo "Then run the tool, for example:"
echo "  python torNmap.py --target 127.0.0.1"
