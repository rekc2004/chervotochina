#!/usr/bin/env bash
# Stage 19b (3a): positive check of a SIGNED draft release, run by the owner after sign.sh.
#   bash scripts/release/release-smoke.sh <downloaded-release-dir> <label> <ext>
# The directory must hold chervo-release.txt, chervo-release.txt.minisig and the release files.
# Uses the downloaded binary of its own target; nothing is rebuilt, nothing is uploaded.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: release-smoke.sh <dir> <label> <ext>" >&2
  exit 2
fi
rel="$1"; label="$2"; ext="$3"
root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=lib.sh
. "$root/scripts/release/lib.sh"

fail=0
bad() { summary "- FAIL: $*"; fail=1; }
good() { summary "- ok: $*"; }
RC=0; OUT=""
run() {
  RC=0
  OUT="$("$@" 2>&1)" || RC=$?
  OUT="${OUT//$'\r'/}"
}

manifest="$rel/chervo-release.txt"
sig="$rel/chervo-release.txt.minisig"
[[ -f "$manifest" && -f "$sig" ]] || { echo "manifest or signature is missing in $rel" >&2; exit 1; }
ver="$(awk '$1 == "version" { print $2; exit }' "$manifest" | tr -d '\r')"
name="chervo-$ver-$label$ext"
bin="$rel/$name"
[[ -f "$bin" ]] || { echo "no release file: $bin" >&2; exit 1; }
chmod +x "$bin"

summary "### release-smoke: $label (\`$name\`)"

# Files of target "any" (SBOM), names from the signed manifest.
any_files=()
while IFS= read -r n; do
  [[ -n "$n" ]] && any_files+=( "$rel/$n" )
done < <(awk '$1 == "artifact" && $2 == "any" { print $5 }' "$manifest" | tr -d '\r')

# 1. Positive: own binary and the "any" files, every line OK ... same, rc 0.
run "$bin" verify-release "$manifest" "$sig" "$bin" "${any_files[@]}"
summary "- \`verify-release\` (own target + any) rc=$RC:" '```' "$OUT" '```'
total=$(( 1 + ${#any_files[@]} ))
nok="$(grep -cE '^OK [A-Za-z0-9._-]+ [0-9]+\.[0-9]+\.[0-9]+ same$' <<<"$OUT" || true)"
nlines="$(grep -c . <<<"$OUT" || true)"
if [[ $RC -eq 0 && "$nok" == "$total" && "$nlines" == "$total" ]]; then
  good "verify-release: rc 0, $total line(s) 'OK ... same'"
else bad "verify-release: expected rc 0 and $total line(s) 'OK <name> <ver> same'"; fi

# 2. Negative: a file of another target.
other=""
while IFS= read -r n; do
  [[ -n "$n" && -f "$rel/$n" ]] && { other="$rel/$n"; break; }
done < <(awk -v t="$label" '$1 == "artifact" && $2 != t && $2 != "any" { print $5 }' "$manifest" | tr -d '\r')
if [[ -n "$other" ]]; then
  run "$bin" verify-release "$manifest" "$sig" "$other"
  summary "- \`verify-release\` (file of another target) rc=$RC:" '```' "$OUT" '```'
  if [[ $RC -eq 1 ]] && grep -qx 'FAIL WrongTarget' <<<"$OUT"; then good "other target: rc 1, WrongTarget"; else bad "other target: expected rc 1 and 'FAIL WrongTarget'"; fi
else
  bad "no file of another target in the release"
fi

# 3. Negative: a copy of own binary with one changed byte.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tampered="$work/tampered-$name"
cp "$bin" "$tampered"
orig="$(od -An -tu1 -j1000 -N1 "$tampered" | tr -d '[:space:]')"
newb=$(( orig ^ 255 ))
printf "\\$(printf '%03o' "$newb")" | dd of="$tampered" bs=1 seek=1000 conv=notrunc 2>/dev/null
run "$bin" verify-release "$manifest" "$sig" "$tampered"
summary "- \`verify-release\` (changed byte) rc=$RC:" '```' "$OUT" '```'
if [[ $RC -eq 1 ]] && grep -q '^FAIL ' <<<"$OUT"; then good "changed byte: rc 1"; else bad "changed byte: expected rc 1 and a FAIL line"; fi

# 4. key ids for comparison with the README (printed, compared by a human).
run "$bin" release-keys
summary "- \`release-keys\` rc=$RC (compare key_id with README and the owner's second channel):" '```' "$OUT" '```'
if [[ $RC -ne 0 ]]; then bad "release-keys rc=$RC"; fi

summary ""
exit "$fail"
