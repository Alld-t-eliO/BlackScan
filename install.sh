#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON_BIN=${PYTHON:-python3}
MODE=${1:-}
VENV_DIR="$ROOT_DIR/venv"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    printf '%s\n' "ERROR: Python 3.10 or newer is required."
    exit 1
fi

if [ "${2:-}" != "" ]; then
    printf '%s\n' "Usage: ./install.sh [--dev]"
    exit 2
fi

"$PYTHON_BIN" - <<'PY'
import sys

if sys.version_info < (3, 10):
    raise SystemExit("ERROR: Python 3.10 or newer is required.")
PY

cd "$ROOT_DIR"
"$PYTHON_BIN" -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel

case "$MODE" in
    "")
        "$VENV_DIR/bin/python" -m pip install -e .
        ;;
    "--dev")
        "$VENV_DIR/bin/python" -m pip install -r requirements.txt
        ;;
    *)
        printf '%s\n' "Usage: ./install.sh [--dev]"
        exit 2
        ;;
esac

mkdir -p reports network_scanner/payloads/payloads
"$VENV_DIR/bin/python" -m network_scanner --help >/dev/null

printf '%s\n' ""
printf '%s\n' "BlackScan installed."
printf '%s\n' "Run: source venv/bin/activate"
printf '%s\n' "Then: blackscan --help"
printf '%s\n' "TUI:  blackscan --tui"
