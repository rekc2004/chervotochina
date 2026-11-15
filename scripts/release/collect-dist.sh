#!/usr/bin/env bash
# Stage 19e, review round 1 (B4): collects the 8 artifacts of `build` and `installers` into the dist directory.
#   bash scripts/release/collect-dist.sh <art-dir> <dist-dir> [<version>]
#   bash scripts/release/collect-dist.sh --self-test
# <art-dir> holds ONE sub-directory per artifact (the workflow downloads each artifact by its exact name into
# art/<name>). Each sub-directory must hold EXACTLY the file names that its artifact may carry (below), regular
# files only (no links, no directories); the file is then copied into <dist-dir>. A file that already exists in
# <dist-dir> is an error: no artifact can replace the file of another one. Why: `installers` runs a foreign program
# (Inno Setup) that could put a file with a foreign permitted name (say chervo-<v>-linux-x86_64) into inst-windows-x86_64
# and, with one common directory, overwrite the real one from bin-linux-x86_64. With the exact list per artifact
# such a file is rejected before it is copied. <version> is read by version.sh when it is not given.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"

ARTIFACTS="bin-linux-x86_64 bin-macos-aarch64 bin-macos-x86_64 bin-windows-x86_64 inst-linux-x86_64 inst-macos-aarch64 inst-macos-x86_64 inst-windows-x86_64"

# expected_files ARTIFACT VERSION -> the file names the artifact may hold, one per line (nothing else is accepted)
expected_files() {
  local v="$2"
  case "$1" in
    bin-linux-x86_64)     printf '%s\n' "chervo-$v-linux-x86_64" "chervotochina-$v-linux-x86_64" ;;
    bin-macos-aarch64)    printf '%s\n' "chervotochina-$v-macos-aarch64.zip" ;;
    bin-macos-x86_64)     printf '%s\n' "chervotochina-$v-macos-x86_64.zip" ;;
    bin-windows-x86_64)   printf '%s\n' "chervotochina-$v-windows-x86_64.exe" ;;
    inst-linux-x86_64)    printf '%s\n' "chervotochina-$v-linux-x86_64.deb" ;;
    inst-macos-aarch64)   printf '%s\n' "chervotochina-$v-macos-aarch64.dmg" ;;
    inst-macos-x86_64)    printf '%s\n' "chervotochina-$v-macos-x86_64.dmg" ;;
    inst-windows-x86_64)  printf '%s\n' "chervotochina-$v-windows-x86_64-setup.exe" ;;
    *) return 1 ;;
  esac
}

# collect ART DIST VERSION -> 0, or 1 with every problem printed (nothing is copied unless ALL artifacts are right)
collect() {
  local art="$1" dist="$2" v="$3" a d want got f bad=0
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "collect-dist: bad version '$v'" >&2; return 2; }
  [[ -d "$art" ]] || { echo "collect-dist: no such directory: $art" >&2; return 1; }
  # nothing but the 8 directories
  got="$(cd "$art" && ls -A | LC_ALL=C sort | tr '\n' ' ')"
  want="$(printf '%s\n' $ARTIFACTS | LC_ALL=C sort | tr '\n' ' ')"
  [[ "$got" == "$want" ]] || { echo "collect-dist: $art holds '$got', expected '$want'" >&2; return 1; }
  for a in $ARTIFACTS; do
    d="$art/$a"
    if [[ -L "$d" || ! -d "$d" ]]; then echo "collect-dist: $a is not a plain directory" >&2; bad=1; continue; fi
    got="$(cd "$d" && ls -A | LC_ALL=C sort | tr '\n' ' ')"
    want="$(expected_files "$a" "$v" | LC_ALL=C sort | tr '\n' ' ')"
    if [[ "$got" != "$want" ]]; then
      echo "collect-dist: artifact $a holds '$got', expected exactly '$want'" >&2; bad=1; continue
    fi
    while IFS= read -r f; do
      if [[ -L "$d/$f" || ! -f "$d/$f" ]]; then echo "collect-dist: $a/$f is not a regular file" >&2; bad=1; fi
      if [[ -e "$dist/$f" ]]; then echo "collect-dist: $dist/$f already exists (an artifact must not replace another one)" >&2; bad=1; fi
    done < <(expected_files "$a" "$v")
  done
  [[ $bad -eq 0 ]] || return 1
  mkdir -p "$dist"
  for a in $ARTIFACTS; do
    while IFS= read -r f; do
      [[ ! -e "$dist/$f" ]] || { echo "collect-dist: $dist/$f already exists" >&2; return 1; }
      cp -- "$art/$a/$f" "$dist/$f"
    done < <(expected_files "$a" "$v")
  done
  echo "collect-dist: ok, $(ls -A "$dist" | wc -l | tr -d '[:space:]') files in $dist"
}

if [[ "${1:-}" == "--self-test" ]]; then
  fail=0
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  v=1.2.3
  mk() { # DIR: a good set of 8 artifact directories
    rm -rf "$1"; mkdir -p "$1"
    local a f
    for a in $ARTIFACTS; do
      mkdir -p "$1/$a"
      while IFS= read -r f; do echo "$a $f" > "$1/$a/$f"; done < <(expected_files "$a" "$v")
    done
  }
  expect() { # name want-rc command...
    local name="$1" want="$2" rc=0
    shift 2
    "$@" >/dev/null 2>&1 || rc=$?
    [[ "$rc" == "$want" ]] || { echo "self-test: FAILED ($name: rc=$rc, expected $want)" >&2; fail=1; }
  }
  mk "$tmp/a"; rm -rf "$tmp/d"
  expect good-set 0 collect "$tmp/a" "$tmp/d" "$v"
  [[ "$(ls -A "$tmp/d" | wc -l | tr -d '[:space:]')" == 9 ]] || { echo "self-test: FAILED (the good set must give 9 files, got $(ls -A "$tmp/d" | wc -l))" >&2; fail=1; }
  # the hostile case of the review: inst-windows-x86_64 carries a file with the name of the real Linux CLI
  mk "$tmp/a"; rm -rf "$tmp/d"; echo "FAKE" > "$tmp/a/inst-windows-x86_64/chervo-$v-linux-x86_64"
  expect inst-carries-foreign-name 1 collect "$tmp/a" "$tmp/d" "$v"
  [[ ! -e "$tmp/d" ]] || { echo "self-test: FAILED (files were copied although an artifact was wrong)" >&2; fail=1; }
  mk "$tmp/a"; rm -rf "$tmp/d"; rm "$tmp/a/inst-windows-x86_64/chervotochina-$v-windows-x86_64-setup.exe"; echo x > "$tmp/a/inst-windows-x86_64/chervo-$v-linux-x86_64"
  expect inst-replaced-by-foreign-name 1 collect "$tmp/a" "$tmp/d" "$v"
  mk "$tmp/a"; rm -rf "$tmp/d"; echo x > "$tmp/a/inst-linux-x86_64/extra.txt"
  expect extra-file 1 collect "$tmp/a" "$tmp/d" "$v"
  mk "$tmp/a"; rm -rf "$tmp/d"; rm "$tmp/a/bin-linux-x86_64/chervo-$v-linux-x86_64"
  expect missing-file 1 collect "$tmp/a" "$tmp/d" "$v"
  mk "$tmp/a"; rm -rf "$tmp/d"; echo x > "$tmp/a/bin-windows-x86_64/chervotochina-$v-windows-x86_64-setup.exe"
  expect setup-name-in-bin-artifact 1 collect "$tmp/a" "$tmp/d" "$v"
  mk "$tmp/a"; rm -rf "$tmp/d"; mkdir "$tmp/a/inst-linux-x86_64/sub"
  expect subdirectory 1 collect "$tmp/a" "$tmp/d" "$v"
  mk "$tmp/a"; rm -rf "$tmp/d"; mkdir "$tmp/a/bin-zzz"
  expect extra-artifact-directory 1 collect "$tmp/a" "$tmp/d" "$v"
  mk "$tmp/a"; rm -rf "$tmp/d"; rm -rf "$tmp/a/inst-macos-x86_64"
  expect missing-artifact-directory 1 collect "$tmp/a" "$tmp/d" "$v"
  mk "$tmp/a"; rm -rf "$tmp/d"; rm "$tmp/a/inst-linux-x86_64/chervotochina-$v-linux-x86_64.deb"; ln -s /etc/hostname "$tmp/a/inst-linux-x86_64/chervotochina-$v-linux-x86_64.deb" 2>/dev/null || true
  if [[ -L "$tmp/a/inst-linux-x86_64/chervotochina-$v-linux-x86_64.deb" ]]; then expect symlink 1 collect "$tmp/a" "$tmp/d" "$v"; fi
  # a file that is already in dist is never replaced
  mk "$tmp/a"; rm -rf "$tmp/d"; mkdir "$tmp/d"; echo old > "$tmp/d/chervotochina-$v-linux-x86_64"
  expect already-in-dist 1 collect "$tmp/a" "$tmp/d" "$v"
  [[ "$(cat "$tmp/d/chervotochina-$v-linux-x86_64")" == old ]] || { echo "self-test: FAILED (an existing dist file was replaced)" >&2; fail=1; }
  expect bad-version 2 collect "$tmp/a" "$tmp/d" "1.2"
  [[ $fail -eq 0 ]] && echo "self-test: ok"
  exit "$fail"
fi

if [[ $# -ne 2 && $# -ne 3 ]]; then
  echo "usage: collect-dist.sh <art-dir> <dist-dir> [<version>] | --self-test" >&2
  exit 2
fi
ver="${3:-$(bash "$root/scripts/release/version.sh")}"
rc=0
collect "$1" "$2" "$ver" || rc=$?
exit "$rc"
