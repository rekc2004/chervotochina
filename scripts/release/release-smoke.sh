#!/usr/bin/env bash
# Stage 19b (3a) / 19g-3: positive check of a SIGNED draft release, run in CI by release-smoke.yml (job `check`).
#   bash scripts/release/release-smoke.sh <downloaded-release-dir> <label> <ext>                  Linux
#   bash scripts/release/release-smoke.sh <downloaded-release-dir> <label> <ext> <verifier-dir>   Windows, macOS
# The directory must hold chervo-release.txt, chervo-release.txt.minisig and the release files.
# Q5 b: the CLI is released for Linux only. On Linux the downloaded `chervo` does the checking. On Windows
# and macOS the checker is the verifier (chervo-verifier-<ver>-<label><ext>) built by CI from the SAME
# commit as the tag; it is not in the release (R19g-11). <verifier-dir>/verifier-source.txt names its
# commit and run; the commit must equal the commit of the signed manifest.
# Nothing is rebuilt, nothing is uploaded.
set -euo pipefail

if [[ $# -ne 3 && $# -ne 4 ]]; then
  echo "usage: release-smoke.sh <dir> <label> <ext> [<verifier-dir>]" >&2
  exit 2
fi
rel="$1"; label="$2"; ext="$3"
verifier_mode=no
vdir=""
if [[ $# -eq 4 ]]; then verifier_mode=yes; vdir="$4"; fi
if [[ "$verifier_mode" == no && "$label" != linux-x86_64 ]]; then
  echo "CLI is released for Linux only (Q5 b); pass the verifier dir" >&2
  exit 2
fi
if [[ "$verifier_mode" == yes && "$label" == linux-x86_64 ]]; then
  echo "verifier mode is for Windows and macOS only; Linux checks the released CLI" >&2
  exit 2
fi
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
mcommit="$(awk '$1 == "commit" { print $2; exit }' "$manifest" | tr -d '\r')"
gext="$(gui_ext "$label")" || { echo "unknown label: $label" >&2; exit 2; }
guiname="chervotochina-$ver-$label$gext"
gui="$rel/$guiname"
[[ -f "$gui" ]] || { echo "no window file of this target: $gui" >&2; exit 1; }

if [[ "$verifier_mode" == no ]]; then
  name="chervo-$ver-$label$ext"
  bin="$rel/$name"
  summary "### release-smoke: $label (\`$name\`)"
else
  name="chervo-verifier-$ver-$label$ext"
  bin="$vdir/$name"
  summary "### release-smoke: $label (verifier \`$name\`, not published)"
  # verifier-source.txt: exactly two lines, `commit <40 hex>` and `run <digits>`. The verifier must
  # come from the commit of the signed manifest, otherwise it is not run.
  src="$vdir/verifier-source.txt"
  [[ -f "$src" && ! -L "$src" ]] || { echo "no $src" >&2; exit 1; }
  src_lines=()
  while IFS= read -r l || [[ -n "$l" ]]; do src_lines+=( "$l" ); done < "$src"
  if [[ ${#src_lines[@]} -ne 2 || ! "${src_lines[0]}" =~ ^commit\ ([0-9a-f]{40})$ ]]; then
    bad "verifier-source.txt: line 1 must be 'commit <40 hex>', and the file must have exactly 2 lines; the verifier is NOT run"
    summary ""; exit 1
  fi
  vcommit="${BASH_REMATCH[1]}"
  if [[ ! "${src_lines[1]}" =~ ^run\ ([0-9]+)$ ]]; then
    bad "verifier-source.txt: line 2 must be 'run <digits>'; the verifier is NOT run"
    summary ""; exit 1
  fi
  vrun="${BASH_REMATCH[1]}"
  if [[ ! "$mcommit" =~ ^[0-9a-f]{40}$ || "$vcommit" != "$mcommit" ]]; then
    bad "verifier commit $vcommit differs from the commit of the signed manifest ($mcommit); the verifier is NOT run"
    summary ""; exit 1
  fi
  [[ -f "$bin" && ! -L "$bin" ]] || { echo "no verifier: $bin" >&2; exit 1; }
  summary "- verifier sha256: \`$(sha256_of "$bin")\`, CI run $vrun, commit $vcommit (verifier, not published)"
fi
[[ -f "$bin" ]] || { echo "no file to run: $bin" >&2; exit 1; }
chmod +x "$bin"

# Files of this target and of target "any", names from the signed manifest.
own_files=()
while IFS= read -r n; do
  [[ -n "$n" ]] && own_files+=( "$rel/$n" )
done < <(awk -v t="$label" '$1 == "artifact" && ($2 == t || $2 == "any") { print $5 }' "$manifest" | tr -d '\r')
have_gui=no
for f in "${own_files[@]}"; do [[ "$f" == "$gui" ]] && have_gui=yes; done
[[ "$have_gui" == yes ]] || { echo "the manifest has no line for $guiname in target $label" >&2; exit 1; }

# 1. Positive: own files (window, on Linux also the CLI) and the "any" files, every line OK ... same, rc 0.
run "$bin" verify-release "$manifest" "$sig" "${own_files[@]}"
summary "- \`verify-release\` (own target + any) rc=$RC:" '```' "$OUT" '```'
total=${#own_files[@]}
ver_re="${ver//./[.]}"
nok="$(grep -cE "^OK [A-Za-z0-9._-]+ $ver_re same$" <<<"$OUT" || true)"
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

# 3. Negative: a copy of the window file of this target with one changed byte. The check is by hash,
#    so the answer must be exactly NotInManifest.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tampered="$work/tampered-$guiname"
cp "$gui" "$tampered"
orig="$(od -An -tu1 -j1000 -N1 "$tampered" | tr -d '[:space:]')"
newb=$(( orig ^ 255 ))
printf "\\$(printf '%03o' "$newb")" | dd of="$tampered" bs=1 seek=1000 conv=notrunc 2>/dev/null
run "$bin" verify-release "$manifest" "$sig" "$tampered"
summary "- \`verify-release\` (changed byte) rc=$RC:" '```' "$OUT" '```'
if [[ $RC -eq 1 && "$OUT" == "FAIL NotInManifest" ]]; then good "changed byte: rc 1, exactly 'FAIL NotInManifest'"; else bad "changed byte: expected rc 1 and exactly the line 'FAIL NotInManifest'"; fi

# 4. key ids for comparison with the README (printed, compared by a human).
run "$bin" release-keys
summary "- \`release-keys\` rc=$RC (compare key_id with README and the owner's second channel):" '```' "$OUT" '```'
if [[ $RC -ne 0 ]]; then bad "release-keys rc=$RC"; fi

summary ""
exit "$fail"
