#!/usr/bin/env bash
# Stage 19g-3 (R19g-3): smoke test of the BUILT window file `chervotochina` (not a rebuild).
#   bash scripts/release/smoke-gui.sh <release-dir> <label> <gext> [--check-only]
#     <release-dir>  directory with chervo-release.txt and chervotochina-<ver>-<label><gext> (from `assemble`)
#     <label>        linux-x86_64 | macos-aarch64 | macos-x86_64 | windows-x86_64
#     <gext>         "" (Linux) | ".zip" (macOS) | ".exe" (Windows)
#     --check-only   only the SHA-256 check (Windows: the run is done by a pwsh step of the workflow)
# The SHA-256 of the file must equal the manifest line of its OWN target, otherwise the file is NOT run
# (as smoke.sh). `--render-check` draws all states without a node, keys or files; the GUI has no
# `--version` (no printing in the GUI, no console on Windows).
#   Linux:   timeout 120 xvfb-run -a <file> --render-check   (the workflow installs xvfb and Mesa with apt; CI only)
#   macOS:   unzip with `ditto -x -k` into a NEW EMPTY directory, `codesign --verify --strict`, run the binary inside.
set -euo pipefail

check_only=no
args=()
for a in "$@"; do
  if [[ "$a" == "--check-only" ]]; then check_only=yes; else args+=( "$a" ); fi
done
if [[ ${#args[@]} -ne 3 ]]; then
  echo "usage: smoke-gui.sh <release-dir> <label> <gext> [--check-only]" >&2
  exit 2
fi
rel="${args[0]}"; label="${args[1]}"; gext="${args[2]}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=lib.sh
. "$root/scripts/release/lib.sh"

want_ext="$(gui_ext "$label")" || { echo "unknown label: $label" >&2; exit 2; }
[[ "$gext" == "$want_ext" ]] || { echo "extension '$gext' does not fit $label (expected '$want_ext')" >&2; exit 2; }

fail=0
bad() { summary "- FAIL: $*"; fail=1; }
good() { summary "- ok: $*"; }

# with_timeout SECONDS COMMAND...: `timeout` (or Homebrew `gtimeout`); macOS runners may have neither,
# then the job's timeout-minutes is the only limit.
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
name="chervotochina-$ver-$label$gext"
file="$rel/$name"
[[ -f "$file" && ! -L "$file" ]] || { echo "no release file: $file" >&2; exit 1; }

summary "### smoke-gui: $label (file \`$name\`)"

# 1. SHA-256 equals the manifest line of this target; otherwise the file is never run.
want="$(awk -v n="$name" -v t="$label" '$1 == "artifact" && $2 == t && $5 == n { print $3 }' "$manifest" | tr -d '\r')"
have="$(sha256_of "$file")"
summary "- manifest sha256: \`${want:-<none>}\`" "- file sha256:     \`$have\`"
if [[ -n "$want" && "$want" == "$have" ]]; then
  good "SHA-256 of the window file equals the manifest line of $label"
else
  bad "SHA-256 differs from the manifest line (or the line is missing); the file is NOT run"
  summary ""
  exit 1
fi

if [[ "$check_only" == yes ]]; then
  summary "- run: left to the next step of the workflow (--check-only)" ""
  exit 0
fi

# 2. --render-check.
RC=0
case "$label" in
  linux-x86_64)
    chmod +x "$file"
    with_timeout 120 xvfb-run -a "$file" --render-check || RC=$?
    ;;
  macos-aarch64|macos-x86_64)
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    ditto -x -k "$file" "$work"
    app="$work/Chervotochina.app"
    [[ -d "$app" ]] || { bad "no Chervotochina.app in the archive"; summary ""; exit 1; }
    if codesign --verify --strict "$app"; then good "codesign --verify --strict"; else bad "codesign --verify --strict failed"; fi
    with_timeout 120 "$app/Contents/MacOS/chervotochina" --render-check || RC=$?
    ;;
  *)
    echo "smoke-gui: no run mode for $label (Windows is run by the pwsh step)" >&2
    exit 2
    ;;
esac
summary "- \`--render-check\` rc=$RC"
if [[ $RC -eq 0 ]]; then good "--render-check: rc 0"; else bad "--render-check: expected rc 0"; fi

summary ""
exit "$fail"
