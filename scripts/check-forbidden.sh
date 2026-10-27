#!/usr/bin/env bash
# Guard: forbid third-party iroh presets/relays/DNS in our code (docs/DECISION.md 2.4).
# Stage 19b (spec 19, section 4): no minisign secret keys in the repository: strings (the whole tree,
# including docs/ and .claude/, case-insensitive) and files *.key / *.sec (case-insensitive).
# [not verified: the base64 prefix of an encrypted minisign key was NOT checked against the minisign
# source, so the content guard looks only for the comment line `untrusted comment: <minisign ...>`;
# a key file whose comment was edited, or a bare base64 line, is NOT caught by content]
set -euo pipefail
patterns=( 'presets::N0' 'N0DisableRelay' 'RelayMode::Default' 'RelayMode::Staging' 'iroh.link' 'n0_dns'
           # no public "what is my IP" service and no STUN (BRIEF 2.2)
           'stun:' 'stun.l.google' 'ipify' 'ifconfig.me' 'icanhazip' 'checkip.' 'ipinfo.io' 'whatismyip'
           # the owner's signing key must never be committed (stage 19, section 4)
           'minisign encrypted secret key' 'minisign secret key' )
args=()
for p in "${patterns[@]}"; do args+=( -e "$p" ); done

scan() {
  local rc=0
  grep -rnF "${args[@]}" \
    --exclude-dir=.git --exclude-dir=target --exclude-dir=docs --exclude-dir=.claude \
    --exclude=check-forbidden.sh -- "$1" || rc=$?
  return "$rc"
}

# The comment line of a minisign secret key file, searched in the WHOLE tree (docs/ and .claude/
# included), ignoring case. Built from parts so that this script does not contain it whole.
# (-E, not -F: GNU grep 3.0 of Git for Windows aborts on `-r -i -F`.)
secret_comment="untrusted comment:[[:space:]]*minisign[[:space:]]+encrypted[[:space:]]+""secret[[:space:]]+key"

scan_secret() {
  local rc=0
  grep -rniE -e "$secret_comment" \
    --exclude-dir=.git --exclude-dir=target \
    --exclude=check-forbidden.sh -- "$1" || rc=$?
  return "$rc"
}

# Prints *.key and *.sec files under $1 (the work tree; .git and target are skipped), ignoring case.
find_key_files() {
  find "$1" \( -name .git -o -name target \) -prune -o -type f \( -iname '*.key' -o -iname '*.sec' \) -print
}

# Tracked or staged *.key / *.sec files of the git index (also those deleted from the work tree).
git_key_files() {
  git -C "$1" ls-files -- ':(icase,glob)**/*.key' ':(icase,glob)**/*.sec'
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  fail=0
  printf 'let x = %s;\n' "RelayMode::""Default" > "$tmp/bad.rs"
  rc=0; scan "$tmp" >/dev/null || rc=$?
  if [[ $rc -ne 0 ]]; then echo "self-test: FAILED (iroh pattern, rc=$rc)" >&2; fail=1; fi
  rm -f "$tmp/bad.rs"
  # Planted strings of a minisign secret key file (assembled so this script never contains them whole).
  mkdir "$tmp/s1" "$tmp/s2" "$tmp/s3"
  printf 'untrusted comment: %s\nRWRTY0Iy\n' "minisign encrypted ""secret key" > "$tmp/s1/primary.txt"
  printf 'untrusted comment: %s\nRWQ\n' "minisign ""secret key ABCD" > "$tmp/s2/notes.txt"
  for d in s1 s2; do
    rc=0; scan "$tmp/$d" >/dev/null || rc=$?
    if [[ $rc -ne 0 ]]; then echo "self-test: FAILED (secret key string in $d, rc=$rc)" >&2; fail=1; fi
  done
  # A public key file must NOT trigger the guard.
  printf 'untrusted comment: %s\nRWQ\n' "minisign public key ABCD" > "$tmp/s3/primary.pub"
  rc=0; scan "$tmp/s3" >/dev/null || rc=$?
  if [[ $rc -ne 1 ]]; then echo "self-test: FAILED (public key flagged, rc=$rc)" >&2; fail=1; fi
  # Whole-tree content guard: docs/ and .claude/ are scanned, the case does not matter.
  mkdir -p "$tmp/w1/docs" "$tmp/w2/.claude/x" "$tmp/w3/docs" "$tmp/w4/target"
  printf 'untrusted comment: %s\n' "minisign encrypted ""secret key" > "$tmp/w1/docs/k.md"
  printf 'UNTRUSTED Comment: %s\n' "MiniSign Encrypted ""Secret Key" > "$tmp/w2/.claude/x/k.txt"
  printf 'untrusted comment: %s\n' "minisign public key ABCD" > "$tmp/w3/docs/p.md"
  printf 'untrusted comment: %s\n' "minisign encrypted ""secret key" > "$tmp/w4/target/ignored.txt"
  for d in w1 w2; do
    rc=0; scan_secret "$tmp/$d" >/dev/null || rc=$?
    if [[ $rc -ne 0 ]]; then echo "self-test: FAILED (whole-tree guard missed $d, rc=$rc)" >&2; fail=1; fi
  done
  for d in w3 w4; do
    rc=0; scan_secret "$tmp/$d" >/dev/null || rc=$?
    if [[ $rc -ne 1 ]]; then echo "self-test: FAILED (whole-tree guard false positive $d, rc=$rc)" >&2; fail=1; fi
  done
  # Planted key files: x.key, upper case, *.sec; target/ is skipped; other names are not flagged.
  mkdir "$tmp/k" "$tmp/k/sub" "$tmp/k/target" "$tmp/k2" "$tmp/k3" "$tmp/k4"
  : > "$tmp/k/sub/x.key"; : > "$tmp/k/target/ignored.key"
  found="$(find_key_files "$tmp/k")"
  if [[ "$found" != "$tmp/k/sub/x.key" ]]; then echo "self-test: FAILED (x.key not found or target not skipped: '$found')" >&2; fail=1; fi
  : > "$tmp/k2/PRIMARY.KEY"; : > "$tmp/k3/old.Sec"; : > "$tmp/k4/keys.txt"; : > "$tmp/k4/second.sec.txt"
  found="$(find_key_files "$tmp/k2")"
  if [[ "$found" != "$tmp/k2/PRIMARY.KEY" ]]; then echo "self-test: FAILED (PRIMARY.KEY not found: '$found')" >&2; fail=1; fi
  found="$(find_key_files "$tmp/k3")"
  if [[ "$found" != "$tmp/k3/old.Sec" ]]; then echo "self-test: FAILED (old.Sec not found: '$found')" >&2; fail=1; fi
  found="$(find_key_files "$tmp/k4")"
  if [[ -n "$found" ]]; then echo "self-test: FAILED (harmless names flagged: '$found')" >&2; fail=1; fi
  # The git index sees key files that were deleted from the work tree.
  if command -v git >/dev/null 2>&1; then
    mkdir "$tmp/g"
    git -C "$tmp/g" init -q
    mkdir "$tmp/g/d"; : > "$tmp/g/d/Old.KEY"; : > "$tmp/g/root.sec"; : > "$tmp/g/ok.txt"
    git -C "$tmp/g" add -f -- . >/dev/null 2>&1
    rm -rf "$tmp/g/d" "$tmp/g/root.sec"
    found="$(git_key_files "$tmp/g" | sort | tr '\n' ' ')"
    if [[ "$found" != "d/Old.KEY root.sec " ]]; then echo "self-test: FAILED (git index fallback: '$found')" >&2; fail=1; fi
  else
    echo "self-test: NOT CHECKED (git is missing: index fallback)" >&2
  fi
  if [[ $fail -eq 0 ]]; then echo "self-test: ok"; exit 0; fi
  exit 1
fi

root="${1:-.}"
rc=0; scan "$root" || rc=$?
case $rc in
  0) echo "FORBIDDEN strings found (see above)" >&2; exit 1 ;;
  1) ;;
  *) echo "grep error rc=$rc" >&2; exit 2 ;;
esac

rc=0; scan_secret "$root" || rc=$?
case $rc in
  0) echo "FORBIDDEN: minisign secret key comment found (see above; docs/ and .claude/ included)" >&2; exit 1 ;;
  1) ;;
  *) echo "grep error rc=$rc" >&2; exit 2 ;;
esac

keys="$(find_key_files "$root")"
# Files in the git index (staged or tracked), if this is a git work tree.
if [[ -z "$keys" ]] && git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  keys="$(git_key_files "$root")"
fi
if [[ -n "$keys" ]]; then
  echo "FORBIDDEN: *.key / *.sec files (secret keys must not be in the repository):" >&2
  echo "$keys" >&2
  exit 1
fi
echo "forbidden-strings: ok"
exit 0
