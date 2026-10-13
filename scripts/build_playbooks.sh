#!/usr/bin/env bash
# Compile playbooks/threatconnect.yaml -> threatconnect/playbooks/playbooks.json (the file
# FortiSOAR imports with the connector). Author the YAML; regenerate the JSON.
#
# Needs the fsrpb compiler (github: fsr-playbook-framework); set FSRPB_HOME to its checkout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRAMEWORK="${FSRPB_HOME:-$HOME/PycharmProjects/fsr-playbook-framework}"
SRC="$ROOT/playbooks/threatconnect.yaml"
OUT="$ROOT/threatconnect/playbooks/playbooks.json"

if [ ! -d "$FRAMEWORK" ]; then
  echo "fsrpb not found at $FRAMEWORK; set FSRPB_HOME to its checkout." >&2
  exit 1
fi

( cd "$FRAMEWORK" && uv run fsrpb provision "$ROOT/threatconnect" --force >/dev/null )
( cd "$FRAMEWORK" && uv run fsrpb validate "$SRC" )
( cd "$FRAMEWORK" && uv run fsrpb compile "$SRC" -o "$OUT" )
echo "wrote $OUT"
