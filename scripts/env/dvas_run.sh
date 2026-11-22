#!/usr/bin/env bash
# Run a command inside the DVAS-EV venv with liboqs on the library path.
# Usage: scripts/env/dvas_run.sh python scripts/....py [args]
set -euo pipefail
VENV="${DVAS_VENV:-$HOME/venvs/dvas-ev}"
source "$VENV/dvas_env.sh"
export PATH="$VENV/bin:$HOME/.foundry/bin:$PATH"
export PYTHONWARNINGS="${PYTHONWARNINGS:-ignore::UserWarning}"
export PYTHONPATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)${PYTHONPATH:+:$PYTHONPATH}"
exec "$@"
