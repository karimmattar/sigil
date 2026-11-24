#!/usr/bin/env bash
# Build the Sigil desktop app on macOS or Linux.
#
#   ./packaging/build.sh            # uses python3 from PATH
#   PYTHON=/path/to/python ./packaging/build.sh
#
# Output: dist/Sigil.app (macOS) or dist/sigil (Linux).
set -euo pipefail

cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"

"$PYTHON" -m pip install --upgrade pip
"$PYTHON" -m pip install ".[tray,build]"
"$PYTHON" -m PyInstaller --noconfirm --clean packaging/sigil.spec

echo
echo "Build finished:"
ls -la dist
