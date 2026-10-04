#!/usr/bin/env bash
# Optional Linux/macOS launcher. The console entry point works on Windows too.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${ESXI_MCP_PROJECT_DIR:-$SCRIPT_DIR}"
PYTHON="${ESXI_MCP_PYTHON:-$PROJECT_DIR/.venv/bin/python}"

if [ ! -x "$PYTHON" ]; then
    echo "Python executable missing: $PYTHON. Create .venv or set ESXI_MCP_PYTHON." >&2
    exit 1
fi

export PYTHONPATH="$PROJECT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"
# Writes are disabled by default; configuration and explicit environment overrides
# are handled by load_config. This launcher does not force-enable them.
exec "$PYTHON" -m esxi_mcp.server
