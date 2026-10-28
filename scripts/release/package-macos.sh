#!/usr/bin/env bash
# Stage 19g-3 (R19g-1): packs the macOS window binary into Chervotochina.app and a .zip.
#   bash scripts/release/package-macos.sh <binary> <version> <label> <out-dir>
#   bash scripts/release/package-macos.sh --self-test
# Output: <out-dir>/chervotochina-<version>-<label>.zip with Chervotochina.app inside.
# The app is built in a NEW EMPTY temp directory, signed ad hoc (no Apple identity, no notarisation,
# U18), checked, and archived with `ditto -c -k --keepParent` (macOS tools: plutil, codesign, ditto, otool).
# [not verified on a macOS runner: codesign/ditto flags are from the man pages]
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
template="$root/packaging/macos/Info.plist"

valid_version() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; }
valid_label() { [[ "$1" == macos-aarch64 || "$1" == macos-x86_64 ]]; }

# render_plist VERSION -> Info.plist text on stdout (the only label in the template is @VERSION@).
render_plist() {
  local tpl
  tpl="$(cat "$template")"
  printf '%s\n' "${tpl//@VERSION@/$1}"
}

if [[ "${1:-}" == "--self-test" ]]; then
  fail=0
  for v in 1.2.3 0.0.0 10.20.30; do
    valid_version "$v" || { echo "self-test: FAILED (rejected version $v)" >&2; fail=1; }
  done
  for v in 1.2 1.2.3.4 1.2.3-rc1 v1.2.3 '' '1.2.3 ' '1.2.3<' '$(id)' '1.2.3&x' $'1.2.3\n'; do
    if valid_version "$v"; then echo "self-test: FAILED (accepted version '$v')" >&2; fail=1; fi
  done
  valid_label macos-aarch64 && valid_label macos-x86_64 || { echo "self-test: FAILED (label)" >&2; fail=1; }
  for l in linux-x86_64 windows-x86_64 macos '' '../x'; do
    if valid_label "$l"; then echo "self-test: FAILED (accepted label '$l')" >&2; fail=1; fi
  done
  [[ -f "$template" ]] || { echo "self-test: FAILED (no template $template)" >&2; exit 1; }
  # The template has exactly two @VERSION@ and no other '@'.
  raw="$(cat "$template")"
  stripped="${raw//@VERSION@/}"
  [[ "$stripped" != *@* ]] || { echo "self-test: FAILED (template has a label other than @VERSION@)" >&2; fail=1; }
  n=$(( (${#raw} - ${#stripped}) / 9 ))
  [[ "$n" -eq 2 ]] || { echo "self-test: FAILED (expected 2 x @VERSION@, got $n)" >&2; fail=1; }
  out="$(render_plist 1.2.3)"
  [[ "$out" != *@* ]] || { echo "self-test: FAILED (label left after substitution)" >&2; fail=1; }
  [[ "$(grep -c '<string>1.2.3</string>' <<<"$out")" == 2 ]] || { echo "self-test: FAILED (version not substituted twice)" >&2; fail=1; }
  for k in '<key>CFBundleExecutable</key>' '<string>chervotochina</string>' '<string>io.github.rekc2004.chervotochina</string>' \
           '<string>APPL</string>' '<string>11.0</string>' '<key>NSHighResolutionCapable</key>'; do
    grep -qF -- "$k" <<<"$out" || { echo "self-test: FAILED (missing in plist: $k)" >&2; fail=1; }
  done
  if command -v plutil >/dev/null 2>&1; then
    tmp="$(mktemp -d)"
    printf '%s\n' "$out" > "$tmp/Info.plist"
    plutil -lint "$tmp/Info.plist" >/dev/null || { echo "self-test: FAILED (plutil -lint)" >&2; fail=1; }
    rm -rf "$tmp"
  else
    echo "self-test: plutil not found, lint skipped (macOS only)"
  fi
  [[ $fail -eq 0 ]] && echo "self-test: ok"
  exit "$fail"
fi

if [[ $# -ne 4 ]]; then
  echo "usage: package-macos.sh <binary> <version> <label> <out-dir>" >&2
  exit 2
fi
bin="$1"; ver="$2"; label="$3"; outdir="$4"
valid_version "$ver" || { echo "package-macos: bad version '$ver'" >&2; exit 2; }
valid_label "$label" || { echo "package-macos: bad label '$label'" >&2; exit 2; }
[[ -f "$bin" ]] || { echo "package-macos: no such file: $bin" >&2; exit 1; }
for tool in plutil codesign ditto otool; do
  command -v "$tool" >/dev/null 2>&1 || { echo "package-macos: '$tool' is not available (macOS only)" >&2; exit 1; }
done

mkdir -p "$outdir"
outdir="$(cd "$outdir" && pwd -P)"
bin="$(cd "$(dirname "$bin")" && pwd -P)/$(basename "$bin")"
zip="$outdir/chervotochina-$ver-$label.zip"
[[ ! -e "$zip" ]] || { echo "package-macos: already exists: $zip" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
app="$work/Chervotochina.app"
mkdir -p "$app/Contents/MacOS"
cp "$bin" "$app/Contents/MacOS/chervotochina"
chmod 755 "$app/Contents/MacOS/chervotochina"
render_plist "$ver" > "$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist"

cd "$work"
codesign --force --sign - --timestamp=none Chervotochina.app
codesign --verify --strict --verbose=2 Chervotochina.app
bash "$root/scripts/release/check-deps.sh" macos "$app/Contents/MacOS/chervotochina"
ditto -c -k --keepParent Chervotochina.app "$zip"
echo "packaged $zip"
