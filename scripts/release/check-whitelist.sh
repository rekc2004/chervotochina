#!/usr/bin/env bash
# Stage 19b: release directory must contain EXACTLY the expected files (white list).
# Any extra file (node13, node14, node15, node16, netcheck, upnp_probe, knockflood, ...), any
# subdirectory or any missing expected file fails.
#   bash scripts/release/check-whitelist.sh <dir> <version>
#   bash scripts/release/check-whitelist.sh --self-test
set -euo pipefail

expected_names() {
  local v="$1"
  printf '%s\n' \
    "chervo-$v-linux-x86_64" \
    "chervo-$v-macos-aarch64" \
    "chervo-$v-macos-x86_64" \
    "chervo-$v-windows-x86_64.exe" \
    "chervo-$v-sbom.cdx.json"
}

check() {
  local dir="$1" ver="$2" bad=0 name
  [[ -d "$dir" ]] || { echo "not a directory: $dir" >&2; return 1; }
  # What is there (names only, one level; sub-directories are listed too and will not match).
  local present
  present="$(cd "$dir" && ls -A | LC_ALL=C sort)"
  local want
  want="$(expected_names "$ver" | LC_ALL=C sort)"
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    if ! grep -qxF -- "$name" <<<"$want"; then
      echo "unexpected file in release directory: $name" >&2; bad=1
    elif [[ ! -f "$dir/$name" ]]; then
      echo "not a regular file: $name" >&2; bad=1
    fi
  done <<<"$present"
  while IFS= read -r name; do
    if ! grep -qxF -- "$name" <<<"$present"; then
      echo "expected file is missing: $name" >&2; bad=1
    fi
  done <<<"$want"
  return "$bad"
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  ver=1.2.3
  fail=0
  mkdir "$tmp/ok"
  expected_names "$ver" | while IFS= read -r n; do : > "$tmp/ok/$n"; done
  rc=0; check "$tmp/ok" "$ver" 2>/dev/null || rc=$?
  [[ $rc -eq 0 ]] || { echo "self-test: FAILED (exact set rejected)" >&2; fail=1; }
  for extra in node13 node14 node15 node16 netcheck upnp_probe knockflood chervo-1.2.3-linux-x86_64.minisig; do
    rm -rf "$tmp/x"; cp -r "$tmp/ok" "$tmp/x"; : > "$tmp/x/$extra"
    rc=0; check "$tmp/x" "$ver" 2>/dev/null || rc=$?
    [[ $rc -ne 0 ]] || { echo "self-test: FAILED (extra '$extra' accepted)" >&2; fail=1; }
  done
  rm -rf "$tmp/x"; cp -r "$tmp/ok" "$tmp/x"; mkdir "$tmp/x/sub"
  rc=0; check "$tmp/x" "$ver" 2>/dev/null || rc=$?
  [[ $rc -ne 0 ]] || { echo "self-test: FAILED (subdirectory accepted)" >&2; fail=1; }
  rm -rf "$tmp/x"; cp -r "$tmp/ok" "$tmp/x"; rm "$tmp/x/chervo-$ver-macos-x86_64"
  rc=0; check "$tmp/x" "$ver" 2>/dev/null || rc=$?
  [[ $rc -ne 0 ]] || { echo "self-test: FAILED (missing file accepted)" >&2; fail=1; }
  rm -rf "$tmp/x"; cp -r "$tmp/ok" "$tmp/x"; : > "$tmp/x/chervo-9.9.9-linux-x86_64"
  rc=0; check "$tmp/x" "$ver" 2>/dev/null || rc=$?
  [[ $rc -ne 0 ]] || { echo "self-test: FAILED (wrong-version file accepted)" >&2; fail=1; }
  if [[ $fail -eq 0 ]]; then echo "self-test: ok"; fi
  exit "$fail"
fi

if [[ $# -ne 2 ]]; then
  echo "usage: check-whitelist.sh <dir> <version>" >&2
  exit 2
fi
if check "$1" "$2"; then
  echo "whitelist: ok"
else
  echo "whitelist: FAILED" >&2
  exit 1
fi
