#!/usr/bin/env bash
# Stage 19b/19g: release directory must contain EXACTLY the expected files (white list, 7 names: the CLI
# for Linux only (Q5 b), the window for 4 targets, 2 SBOMs). Any extra file (node13, ..., the CLI of
# another OS, a verifier, .dmg), any subdirectory (Chervotochina.app) or any missing expected file fails.
#   bash scripts/release/check-whitelist.sh <dir> <version>
#   bash scripts/release/check-whitelist.sh --self-test
set -euo pipefail

expected_names() {
  local v="$1"
  printf '%s\n' \
    "chervo-$v-linux-x86_64" \
    "chervotochina-$v-linux-x86_64" \
    "chervotochina-$v-macos-aarch64.zip" \
    "chervotochina-$v-macos-x86_64.zip" \
    "chervotochina-$v-windows-x86_64.exe" \
    "chervo-$v-sbom.cdx.json" \
    "chervotochina-$v-sbom.cdx.json"
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
  for extra in node13 node14 node15 node16 netcheck upnp_probe knockflood chervo-1.2.3-linux-x86_64.minisig \
               "chervo-$ver-windows-x86_64.exe" "chervo-$ver-macos-aarch64" "chervo-$ver-macos-x86_64" \
               "chervo-verifier-$ver-windows-x86_64.exe" "chervo-verifier-$ver-macos-aarch64" \
               "chervotochina-$ver-macos-aarch64.dmg" chervo-release.txt; do
    rm -rf "$tmp/x"; cp -r "$tmp/ok" "$tmp/x"; : > "$tmp/x/$extra"
    rc=0; check "$tmp/x" "$ver" 2>/dev/null || rc=$?
    [[ $rc -ne 0 ]] || { echo "self-test: FAILED (extra '$extra' accepted)" >&2; fail=1; }
  done
  rm -rf "$tmp/x"; cp -r "$tmp/ok" "$tmp/x"; mkdir "$tmp/x/sub"
  rc=0; check "$tmp/x" "$ver" 2>/dev/null || rc=$?
  [[ $rc -ne 0 ]] || { echo "self-test: FAILED (subdirectory accepted)" >&2; fail=1; }
  rm -rf "$tmp/x"; cp -r "$tmp/ok" "$tmp/x"; mkdir "$tmp/x/Chervotochina.app"
  rc=0; check "$tmp/x" "$ver" 2>/dev/null || rc=$?
  [[ $rc -ne 0 ]] || { echo "self-test: FAILED (Chervotochina.app directory accepted)" >&2; fail=1; }
  for gone in "chervo-$ver-linux-x86_64" "chervotochina-$ver-linux-x86_64" "chervotochina-$ver-macos-aarch64.zip" \
              "chervotochina-$ver-macos-x86_64.zip" "chervotochina-$ver-windows-x86_64.exe" \
              "chervo-$ver-sbom.cdx.json" "chervotochina-$ver-sbom.cdx.json"; do
    rm -rf "$tmp/x"; cp -r "$tmp/ok" "$tmp/x"; rm "$tmp/x/$gone"
    rc=0; check "$tmp/x" "$ver" 2>/dev/null || rc=$?
    [[ $rc -ne 0 ]] || { echo "self-test: FAILED (missing '$gone' accepted)" >&2; fail=1; }
  done
  [[ "$(expected_names "$ver" | wc -l | tr -d '[:space:]')" == 7 ]] || { echo "self-test: FAILED (not 7 names)" >&2; fail=1; }
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
