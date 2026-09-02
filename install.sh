#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON_BIN=${PYTHON:-python3}
MODE=${1:-}

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    printf '%s\n' "ERROR: python3 is required."
    exit 1
fi

"$PYTHON_BIN" - <<'PY'
import sys

if sys.version_info < (3, 10):
    raise SystemExit("ERROR: Python 3.10 or newer is required.")
PY

cd "$ROOT_DIR"
"$PYTHON_BIN" -m venv venv
. "$ROOT_DIR/venv/bin/activate"
python -m pip install --upgrade pip setuptools wheel

case "$MODE" in
    "")
        python -m pip install -e .
        ;;
    "--audit")
        python -m pip install -e ".[audit]"
        ;;
    "--dev")
        python -m pip install -r requirements.txt
        ;;
    *)
        printf '%s\n' "Usage: ./install.sh [--audit|--dev]"
        exit 2
        ;;
esac

mkdir -p reports
python -m network_scanner --help >/dev/null

printf '%s\n' ""
printf '%s\n' "BlackScan installed."
printf '%s\n' "Run: source venv/bin/activate"
printf '%s\n' "Then: blackscan --help"
printf '%s\n' "TUI:  blackscan --tui"
