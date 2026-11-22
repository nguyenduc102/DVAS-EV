#!/usr/bin/env bash
# Environment bootstrap for the DVAS-EV artifact (Linux or WSL2, tested on Ubuntu 24.04).
# 1. builds liboqs 0.15.0 into a user-local prefix,
# 2. creates a Python venv with the pinned requirements and liboqs-python 0.14.0,
# 3. writes $VENV/dvas_env.sh, which scripts/env/dvas_run.sh sources.
# Needs: git, cmake, ninja-build, gcc, python3-venv.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFIX="${OQS_PREFIX:-$HOME/.local/liboqs-dvas}"
VENV="${DVAS_VENV:-$HOME/venvs/dvas-ev}"
BUILD="${OQS_BUILD_DIR:-$HOME/.cache/dvas-liboqs-build}"
LIBOQS_TAG="${LIBOQS_TAG:-0.15.0}"
LIBOQS_PY_TAG="${LIBOQS_PY_TAG:-0.14.0}"

if [[ ! -f "$PREFIX/lib/liboqs.so" ]]; then
  rm -rf "$BUILD"; mkdir -p "$BUILD"
  git clone --depth 1 --branch "$LIBOQS_TAG" https://github.com/open-quantum-safe/liboqs.git "$BUILD/src"
  cmake -S "$BUILD/src" -B "$BUILD/build" -GNinja \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_BUILD_TYPE=Release
  ninja -C "$BUILD/build"
  ninja -C "$BUILD/build" install
fi

if [[ ! -x "$VENV/bin/python" ]]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -r "$REPO/requirements.txt"
"$VENV/bin/pip" install -q "git+https://github.com/open-quantum-safe/liboqs-python.git@$LIBOQS_PY_TAG"
echo "export OQS_INSTALL_PATH=$PREFIX; export LD_LIBRARY_PATH=$PREFIX/lib:\${LD_LIBRARY_PATH:-}" > "$VENV/dvas_env.sh"
OQS_INSTALL_PATH="$PREFIX" LD_LIBRARY_PATH="$PREFIX/lib" "$VENV/bin/python" -c \
  "import oqs; print('liboqs', oqs.oqs_version(), 'liboqs-python', oqs.oqs_python_version())"
