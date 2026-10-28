#!/usr/bin/env bash
# Stage 18b (DECISION 2.9, 18p report): the Linux normal-dependency tree of chervo-gui must not
# contain the old zbus 5 / zvariant family or accesskit_unix. deny.toml excludes accesskit_unix
# from the graph (cargo-deny ignores per-target features), so this script is the guard.
# zbus itself is allowed ONLY as 6.x (the project's own Secret Service client, chervo-identity);
# zvariant, zvariant_derive, zvariant_utils, zbus_names and accesskit_unix are banned at any version.
#   bash scripts/check-gui-linux-tree.sh
#   bash scripts/check-gui-linux-tree.sh --self-test
set -euo pipefail

# Reads `cargo tree --prefix none` lines on stdin, prints the offending lines.
bad_lines() {
  grep -E '^(zvariant|zvariant_derive|zvariant_utils|zbus_names|accesskit_unix) |^zbus v[0-5]\.' || true
}

if [[ "${1:-}" == "--self-test" ]]; then
  fail=0
  ok_tree=$'chervo-gui v0.0.0 (/x)\nzbus v6.0.0\nzbus_macros v6.0.0 (proc-macro)\nzbus_utils v6.0.0\naccesskit v0.25.2\nrfd v0.17.2'
  [[ -z "$(printf '%s\n' "$ok_tree" | bad_lines)" ]] || { echo "self-test: FAILED (clean tree flagged)" >&2; fail=1; }
  for planted in 'zbus v5.9.0' 'zvariant v5.1.0' 'zbus_names v4.0.0' 'accesskit_unix v0.17.0' 'zvariant_derive v5.0.0' 'zvariant_utils v3.0.0'; do
    got="$(printf '%s\n%s\n' "$ok_tree" "$planted" | bad_lines)"
    [[ -n "$got" ]] || { echo "self-test: FAILED (not caught: $planted)" >&2; fail=1; }
  done
  [[ $fail -eq 0 ]] && echo "check-gui-linux-tree: self-test ok"
  exit "$fail"
fi

cd "$(dirname "$0")/.."
tree="$(cargo tree -e normal --target x86_64-unknown-linux-gnu --prefix none --locked -p chervo-gui)"
# the tree must be a real one (the guard would be empty otherwise)
printf '%s\n' "$tree" | grep -q '^chervo-gui ' || { echo "GUI LINUX TREE GUARD FAIL: no chervo-gui in the tree" >&2; exit 1; }
found="$(printf '%s\n' "$tree" | bad_lines)"
if [[ -n "$found" ]]; then
  echo "GUI LINUX TREE GUARD FAIL:" >&2
  printf '%s\n' "$found" >&2
  exit 1
fi
echo "GUI LINUX TREE GUARD PASS"
