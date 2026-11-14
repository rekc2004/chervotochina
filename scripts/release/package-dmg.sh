#!/usr/bin/env bash
# Stage 19e-3 (SPEC 19e R19e-5, 3.4, 5.3 item 5): builds the macOS disk image from the ALREADY BUILT, ad-hoc signed
# Chervotochina.app of the .zip of the same target (the image packs the same .app tree as the signed .zip).
#   bash scripts/release/package-dmg.sh <zip> <version> <label> <out-dir>      label: macos-aarch64 | macos-x86_64
#   bash scripts/release/package-dmg.sh --self-test                            (validators only; no macOS tools)
# Steps: `ditto -x -k` into a NEW EMPTY directory; exactly one element Chervotochina.app; `codesign --verify --strict`;
# `ln -s /Applications Applications`; `hdiutil create -volname Chervotochina -srcfolder <stage> -fs HFS+ -format UDZO`
# (up to 3 attempts, 10 s apart: "Resource busy" is a known failure on runners; every attempt goes to the summary);
# `hdiutil verify`; check-dmg.sh; the image is built TWICE and the SHA-256 of both is only RECORDED (UDIF carries
# time stamps and ids). No Apple signature, no notarisation (U18); the .dmg itself is not signed.
# [not verified on a macOS runner: the hdiutil flags are from the man page; the first check is the trial run in CI]
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=lib.sh
. "$root/scripts/release/lib.sh"

valid_version() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; }
valid_label() { [[ "$1" == macos-aarch64 || "$1" == macos-x86_64 ]]; }

if [[ "${1:-}" == "--self-test" ]]; then
  fail=0
  for v in 1.2.3 0.0.0 10.20.30; do valid_version "$v" || { echo "self-test: FAILED (rejected version $v)" >&2; fail=1; }; done
  for v in 1.2 1.2.3.4 v1.2.3 '' '1.2.3 ' '$(id)' '1.2.3;x' $'1.2.3\n'; do
    if valid_version "$v"; then echo "self-test: FAILED (accepted version '$v')" >&2; fail=1; fi
  done
  valid_label macos-aarch64 && valid_label macos-x86_64 || { echo "self-test: FAILED (label)" >&2; fail=1; }
  for l in linux-x86_64 windows-x86_64 macos '' '../x' 'macos-aarch64 '; do
    if valid_label "$l"; then echo "self-test: FAILED (accepted label '$l')" >&2; fail=1; fi
  done
  [[ -f "$root/scripts/release/check-dmg.sh" ]] || { echo "self-test: FAILED (no check-dmg.sh)" >&2; fail=1; }
  [[ $fail -eq 0 ]] && echo "self-test: ok"
  exit "$fail"
fi

if [[ $# -ne 4 ]]; then
  echo "usage: package-dmg.sh <zip> <version> <label> <out-dir> | --self-test" >&2
  exit 2
fi
zip="$1"; ver="$2"; label="$3"; outdir="$4"
valid_version "$ver" || { echo "package-dmg: bad version '$ver'" >&2; exit 2; }
valid_label "$label" || { echo "package-dmg: bad label '$label'" >&2; exit 2; }
[[ -f "$zip" && ! -L "$zip" ]] || { echo "package-dmg: no such file: $zip" >&2; exit 1; }
for tool in ditto hdiutil codesign; do
  command -v "$tool" >/dev/null 2>&1 || { echo "package-dmg: '$tool' is not available (macOS only)" >&2; exit 1; }
done
name="chervotochina-$ver-$label.dmg"
mkdir -p "$outdir"
outdir="$(cd "$outdir" && pwd -P)"
zip="$(cd "$(dirname "$zip")" && pwd -P)/$(basename "$zip")"
[[ ! -e "$outdir/$name" ]] || { echo "package-dmg: already exists: $outdir/$name" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
stage="$work/stage"
mkdir "$stage"
ditto -x -k "$zip" "$stage"
items="$(ls -A "$stage")"
[[ "$items" == Chervotochina.app ]] || { echo "package-dmg: the zip must hold exactly Chervotochina.app, found: $items" >&2; exit 1; }
codesign --verify --strict --verbose=2 "$stage/Chervotochina.app"
ln -s /Applications "$stage/Applications"

summary "### package-dmg: $name" "- sw_vers: $(sw_vers -productVersion 2>/dev/null || echo '?'), hdiutil: $(command -v hdiutil)"
# build N -> $work/oN/<name>; up to 3 attempts, each one recorded
build() {
  local d="$work/o$1" attempt rc
  mkdir -p "$d"
  for attempt in 1 2 3; do
    rc=0
    hdiutil create -volname Chervotochina -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$d/$name" > "$work/hdiutil$1.log" 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
      summary "- build $1, attempt $attempt: ok"
      return 0
    fi
    summary "- build $1, attempt $attempt: hdiutil create exit $rc: $(tail -n 2 "$work/hdiutil$1.log" | tr '\n' ' ')"
    rm -f "$d/$name"
    [[ $attempt -eq 3 ]] || sleep 10
  done
  echo "package-dmg: hdiutil create failed 3 times" >&2
  return 1
}
build 1
hdiutil verify "$work/o1/$name"
bash "$root/scripts/release/check-dmg.sh" "$work/o1/$name" "$zip"
build 2
hdiutil verify "$work/o2/$name"
s1="$(sha256_of "$work/o1/$name")"; s2="$(sha256_of "$work/o2/$name")"
if [[ "$s1" == "$s2" ]]; then same="совпало"; else same="не совпало"; fi
cp -- "$work/o1/$name" "$outdir/$name"
summary "- dmg sha256: \`$s1\`" "- second build: \`$s2\` ($same; recorded only)" "- size: $(size_of "$outdir/$name") bytes"
echo "packaged $outdir/$name"
