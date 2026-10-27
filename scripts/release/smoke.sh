#!/usr/bin/env bash
# Stage 19b: smoke test of the BUILT release file (not a rebuild, not a test wrapper).
#   bash scripts/release/smoke.sh <release-dir> <label> <ext>
#     <release-dir>  directory with chervo-release.txt and chervo-<ver>-<label><ext> (from `assemble`)
#     <label>        linux-x86_64 | macos-aarch64 | macos-x86_64 | windows-x86_64
#     <ext>          "" or ".exe"
# Environment:
#   SKIP_KEYS  "true" if the owner keys are knowingly not embedded (trial run, no tag); else keys must be there
#   REF_TYPE   github.ref_type ("tag" makes missing fixtures a failure); REF_NAME  github.ref_name
# `chervo check-update` is deliberately not run (the release is a draft; no network from CI).
# `chervo doctor` is added after stage 19v is merged (not before).
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: smoke.sh <release-dir> <label> <ext>" >&2
  exit 2
fi
rel="$1"; label="$2"; ext="$3"
root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=lib.sh
. "$root/scripts/release/lib.sh"

skip_keys="${SKIP_KEYS:-false}"
ref_type="${REF_TYPE:-}"
ref_name="${REF_NAME:-}"
manifest="$rel/chervo-release.txt"
fixture_sig="$root/crates/chervo-update/tests/fixtures/chervo-release.txt.minisig"

fail=0
bad() { summary "- FAIL: $*"; fail=1; }
good() { summary "- ok: $*"; }
RC=0; OUT=""
run() { # run command, capture combined output into OUT and exit code into RC
  RC=0
  OUT="$("$@" 2>&1)" || RC=$?
  OUT="${OUT//$'\r'/}"
}

[[ -f "$manifest" ]] || { echo "no manifest: $manifest" >&2; exit 1; }
ver="$(awk '$1 == "version" { print $2; exit }' "$manifest" | tr -d '\r')"
name="chervo-$ver-$label$ext"
bin="$rel/$name"
[[ -f "$bin" ]] || { echo "no release file: $bin" >&2; exit 1; }
chmod +x "$bin"

summary "### smoke: $label (file \`$name\`)"

# 1. SHA-256 of the file we are about to run equals the manifest line.
want="$(awk -v n="$name" -v t="$label" '$1 == "artifact" && $2 == t && $5 == n { print $3 }' "$manifest" | tr -d '\r')"
have="$(sha256_of "$bin")"
summary "- manifest sha256: \`${want:-<none>}\`" "- file sha256:     \`$have\`"
if [[ -n "$want" && "$want" == "$have" ]]; then
  good "SHA-256 of the file equals the manifest line"
else
  # Review 19b, L4: a file that does not match the manifest is never executed.
  bad "SHA-256 differs from the manifest line (or the line is missing); the file is NOT run"
  summary ""
  exit 1
fi

# 2. --version prints the version of the tag (trial run: version of the workspace = manifest version).
if [[ "$ref_type" == "tag" ]]; then expected="${ref_name#v}"; else expected="$ver"; fi
run "$bin" --version
summary "- \`--version\` rc=$RC: \`$OUT\`"
if [[ $RC -eq 0 && "$OUT" == "chervo $expected" ]]; then good "--version = chervo $expected"; else bad "--version expected 'chervo $expected'"; fi

# 3. release-keys.
run "$bin" release-keys
summary "- \`release-keys\` rc=$RC:" '```' "$OUT" '```'
if [[ "$skip_keys" == "true" ]]; then
  if [[ $RC -eq 1 && "$OUT" == *"ключи владельца не вшиты"* ]]; then
    good "release-keys: rc 1 and 'keys not embedded' (skip_keys_check)"
  else bad "release-keys with skip_keys_check: expected rc 1 and 'ключи владельца не вшиты'"; fi
else
  nprim="$(grep -cE '^primary [0-9A-Fa-f]{16} ' <<<"$OUT" || true)"
  nback="$(grep -cE '^backup [0-9A-Fa-f]{16} ' <<<"$OUT" || true)"
  nlines="$(grep -c . <<<"$OUT" || true)"
  if [[ $RC -eq 0 && "$nprim" == 1 && "$nback" == 1 && "$nlines" == 2 ]]; then
    good "release-keys: rc 0, one primary and one backup key"
  else bad "release-keys: expected rc 0 and exactly one primary and one backup line"; fi
fi

# 4. verify-release with a foreign signature must fail with a known code.
if [[ "$skip_keys" == "true" ]]; then
  # The key set is empty, the error comes before any file is read.
  run "$bin" verify-release "$manifest" "$manifest.nonexistent.minisig" "$bin"
  want_code="NoTrustedKeys"
elif [[ -f "$fixture_sig" ]]; then
  run "$bin" verify-release "$manifest" "$fixture_sig" "$bin"
  want_code="UnknownKey"
else
  want_code=""
fi
if [[ -n "$want_code" ]]; then
  summary "- \`verify-release\` (foreign signature) rc=$RC:" '```' "$OUT" '```'
  if [[ $RC -eq 1 ]] && grep -qx "FAIL $want_code" <<<"$OUT"; then
    good "verify-release: rc 1, FAIL $want_code"
  else bad "verify-release: expected rc 1 and 'FAIL $want_code'"; fi
elif [[ "$ref_type" == "tag" ]]; then
  bad "no fixture $fixture_sig (stage 19a, foreign-key signature); required for a tag"
else
  summary "- NOT CHECKED: verify-release with a foreign signature (no fixture crates/chervo-update/tests/fixtures/chervo-release.txt.minisig)"
fi

summary ""
exit "$fail"
