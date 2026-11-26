#!/usr/bin/env bash
set -euo pipefail
REPO="${REPO:-lr4-5-aes}"
OWNER="${OWNER:-wrldslatt999}"
VISIBILITY="${VISIBILITY:-private}"
if [[ "$VISIBILITY" != public && "$VISIBILITY" != private ]]; then echo 'Use VISIBILITY=public|private' >&2; exit 1; fi
cd "$(dirname "$0")/.."
command -v gh >/dev/null || { echo 'Install GitHub CLI: sudo apt install gh' >&2; exit 1; }
gh auth status >/dev/null || { echo 'Authenticate first: gh auth login' >&2; exit 1; }
if [[ -d .git ]]; then
  echo 'A local .git directory already exists. Verify remote manually.' >&2
  exit 1
fi
printf 'Create and upload %s/%s (visibility=%s)? [y/N]: ' "$OWNER" "$REPO" "$VISIBILITY"
read -r answer
[[ "$answer" == y || "$answer" == Y ]] || exit 0
if gh repo view "$OWNER/$REPO" >/dev/null 2>&1; then
  echo 'Repository already exists. Refusing to overwrite or push automatically.' >&2
  exit 1
fi
git init -b main
git config user.name "${GIT_AUTHOR_NAME:-wrldslatt999}"
git config user.email "${GIT_AUTHOR_EMAIL:-74917236+wrldslatt999@users.noreply.github.com}"
git add -A
git commit -m 'Implement LR4-5 AES file encryption, key lifecycle, tests and benchmarks'
gh repo create "$OWNER/$REPO" --"$VISIBILITY" --source=. --remote=origin --push
printf '\nProject uploaded: https://github.com/%s/%s\n' "$OWNER" "$REPO"
