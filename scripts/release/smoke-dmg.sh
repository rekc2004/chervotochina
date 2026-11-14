#!/usr/bin/env bash
# Stage 19e-3 (SPEC 19e 5.3 item 8): smoke test of the macOS disk image (the built file, not a rebuild). macOS only.
#   bash scripts/release/smoke-dmg.sh <release-dir> <label>          label: macos-aarch64 | macos-x86_64
# First step: the SHA-256 of the .dmg and of the .zip equals the manifest line of its OWN target, otherwise nothing is
# opened or run. Then check-dmg.sh (the .zip of <release-dir> is the reference), a copy of the .app by `ditto` into
# $RUNNER_TEMP/Applications (the system /Applications is NOT touched), `codesign --verify --strict`, `--render-check`
# must return 0, the copy is removed. Gatekeeper on a real Mac is not tested (SPEC 9.1).
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: smoke-dmg.sh <release-dir> <label>" >&2
  exit 2
fi
rel="$1"; label="$2"
root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=lib.sh
. "$root/scripts/release/lib.sh"
[[ "$label" == macos-aarch64 || "$label" == macos-x86_64 ]] || { echo "unknown label: $label" >&2; exit 2; }

fail=0
bad() { summary "- FAIL: $*"; fail=1; }
good() { summary "- ok: $*"; }
with_timeout() {
  local secs="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"
  else "$@"; fi
}

manifest="$rel/chervo-release.txt"
[[ -f "$manifest" ]] || { echo "no manifest: $manifest" >&2; exit 1; }
ver="$(awk '$1 == "version" { print $2; exit }' "$manifest" | tr -d '\r')"
[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "bad version in the manifest: $ver" >&2; exit 1; }
dmg_name="chervotochina-$ver-$label.dmg"
zip_name="chervotochina-$ver-$label.zip"
dmg="$rel/$dmg_name"; zip="$rel/$zip_name"
[[ -f "$dmg" && ! -L "$dmg" ]] || { echo "no release file: $dmg" >&2; exit 1; }
[[ -f "$zip" && ! -L "$zip" ]] || { echo "no release file: $zip" >&2; exit 1; }

summary "### smoke-dmg: $label (file \`$dmg_name\`)"
for pair in "$dmg_name:$dmg" "$zip_name:$zip"; do
  n="${pair%%:*}"; f="${pair#*:}"
  want="$(awk -v n="$n" -v t="$label" '$1 == "artifact" && $2 == t && $5 == n { print $3 }' "$manifest" | tr -d '\r')"
  have="$(sha256_of "$f")"
  summary "- $n: manifest \`${want:-<none>}\`, file \`$have\`"
  if [[ -z "$want" || "$want" != "$have" ]]; then
    bad "SHA-256 of $n differs from the manifest line (or the line is missing); nothing is opened or run"
    summary ""
    exit 1
  fi
done
good "SHA-256 of the .dmg and of the .zip equal the manifest lines of $label"

if bash "$root/scripts/release/check-dmg.sh" "$dmg" "$zip"; then good "check-dmg.sh"; else bad "check-dmg.sh failed"; fi

base="${RUNNER_TEMP:-$(mktemp -d)}"
dest="$base/Applications"
mnt="$(mktemp -d)"
attached=no
cleanup() {
  if [[ "$attached" == yes ]]; then hdiutil detach "$mnt" >/dev/null 2>&1 || hdiutil detach -force "$mnt" >/dev/null 2>&1 || true; fi
  rm -rf "$dest" "$mnt"
}
trap cleanup EXIT
mkdir -p "$dest"
hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$mnt" "$dmg" >/dev/null
attached=yes
ditto "$mnt/Chervotochina.app" "$dest/Chervotochina.app"
if codesign --verify --strict "$dest/Chervotochina.app"; then good "codesign --verify --strict on the copy"; else bad "codesign --verify --strict failed on the copy"; fi
RC=0
with_timeout 120 "$dest/Chervotochina.app/Contents/MacOS/chervotochina" --render-check || RC=$?
summary "- \`--render-check\` rc=$RC"
if [[ $RC -eq 0 ]]; then good "--render-check: rc 0"; else bad "--render-check: expected rc 0"; fi
summary ""
exit "$fail"
