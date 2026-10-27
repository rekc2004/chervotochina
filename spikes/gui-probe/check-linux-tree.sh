#!/usr/bin/env bash
# Fails if the Linux normal-dependency tree contains the zbus / zvariant family or accesskit_unix.
set -euo pipefail
cd "$(dirname "$0")"
tree=$(cargo tree -e normal --target x86_64-unknown-linux-gnu --prefix none --locked)
if echo "$tree" | grep -E '^(zbus|zvariant|zbus_names|accesskit_unix) '; then
  echo "LINUX TREE GUARD FAIL"; exit 1
fi
echo "LINUX TREE GUARD PASS"
