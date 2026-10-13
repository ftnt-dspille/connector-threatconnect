#!/usr/bin/env bash
# Build dist/threatconnect-<version>.tgz: the folder FortiSOAR installs from, nothing else.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
VERSION="$(python3 -c "import json; print(json.load(open('threatconnect/info.json'))['version'])")"
OUT="dist/threatconnect-${VERSION}.tgz"
rm -rf dist && mkdir -p dist/stage
cp -R threatconnect dist/stage/threatconnect
find dist/stage -name __pycache__ -type d -prune -exec rm -rf {} +
tar czf "$OUT" -C dist/stage threatconnect
echo "built $OUT ($(du -h "$OUT" | cut -f1))"
