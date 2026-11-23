#!/usr/bin/env bash
# uninstall.sh — Remove vitalsd, screenshotd, and everythingd.
set -euo pipefail

PREFIX="$HOME/.local/bin"
[[ "${1:-}" == "--prefix" && $# -ge 2 ]] && PREFIX="$2"

for bin in vitalsd screenshotd everythingd; do
  if [[ -f "$PREFIX/$bin" ]]; then
    rm -f "$PREFIX/$bin"
    echo "Removed: $PREFIX/$bin"
  fi
done
