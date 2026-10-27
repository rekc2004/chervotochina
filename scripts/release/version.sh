#!/usr/bin/env bash
# Prints the version of the released package (chervo-cli = workspace version) from
# `cargo metadata --no-deps --locked --format-version 1`. No jq/python needed.
#   bash scripts/release/version.sh            -> 0.0.0
#   bash scripts/release/version.sh --self-test
set -euo pipefail

# stdin: cargo metadata JSON; stdout: version of package "chervo-cli" ("name" is followed by "version").
extract() {
  sed -n 's/.*"name":"chervo-cli","version":"\([^"]*\)".*/\1/p'
}

valid() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

if [[ "${1:-}" == "--self-test" ]]; then
  fail=0
  got="$(printf '%s' '{"packages":[{"name":"other","version":"9.9.9","id":"x"},{"name":"chervo-cli","version":"1.2.3","id":"y"}],"x":1}' | extract)"
  [[ "$got" == "1.2.3" ]] || { echo "self-test: FAILED (extract: '$got')" >&2; fail=1; }
  got="$(printf '%s' '{"packages":[{"name":"other","version":"9.9.9"}]}' | extract)"
  [[ -z "$got" ]] || { echo "self-test: FAILED (absent package gave '$got')" >&2; fail=1; }
  for v in 1.2.3 0.0.0 10.20.30; do
    valid "$v" || { echo "self-test: FAILED (rejected $v)" >&2; fail=1; }
  done
  for v in 01.2.3 1.2 1.2.3.4 1.2.3-rc1 v1.2.3 "" "1.2.3 "; do
    if valid "$v"; then echo "self-test: FAILED (accepted '$v')" >&2; fail=1; fi
  done
  [[ $fail -eq 0 ]] && echo "self-test: ok"
  exit "$fail"
fi

cd "$(dirname "$0")/../.."
ver="$(cargo metadata --no-deps --locked --format-version 1 | extract)"
if ! valid "$ver"; then
  echo "version.sh: cannot read a valid version of chervo-cli (got '$ver')" >&2
  exit 1
fi
printf '%s\n' "$ver"
