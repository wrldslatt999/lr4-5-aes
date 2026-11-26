#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export AES_LAB_PASSWORD="$(python -c 'import secrets;print(secrets.token_hex(24))')"
ARGS=(--home "$TMP/state")
python aes_cli.py "${ARGS[@]}" key new --label default
for mode in gcm cbc ctr; do
  python aes_cli.py "${ARGS[@]}" enc --in data/sample.txt --out "$TMP/$mode.enc" --label default --mode "$mode"
  python aes_cli.py "${ARGS[@]}" dec --in "$TMP/$mode.enc" --out "$TMP/$mode.dec"
  cmp data/sample.txt "$TMP/$mode.dec"
done
python tamper_demo.py --file "$TMP/gcm.enc" --out "$TMP/gcm.tampered" --which tag
if python aes_cli.py "${ARGS[@]}" dec --in "$TMP/gcm.tampered" --out "$TMP/must-not-appear"; then
  echo "ERROR: tampering was not detected" >&2
  exit 1
fi
test ! -e "$TMP/must-not-appear"
python aes_cli.py "${ARGS[@]}" logs summary
echo 'All modes round-tripped and tampering rejected.'
