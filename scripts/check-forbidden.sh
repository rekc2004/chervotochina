#!/usr/bin/env bash
# Guard: forbid third-party iroh presets/relays/DNS in our code (docs/DECISION.md 2.4).
set -euo pipefail
patterns=( 'presets::N0' 'N0DisableRelay' 'RelayMode::Default' 'RelayMode::Staging' 'iroh.link' 'n0_dns'
           # no public "what is my IP" service and no STUN (BRIEF 2.2)
           'stun:' 'stun.l.google' 'ipify' 'ifconfig.me' 'icanhazip' 'checkip.' 'ipinfo.io' 'whatismyip' )
args=()
for p in "${patterns[@]}"; do args+=( -e "$p" ); done

scan() {
  local rc=0
  grep -rnF "${args[@]}" \
    --exclude-dir=.git --exclude-dir=target --exclude-dir=docs --exclude-dir=.claude \
    --exclude=check-forbidden.sh -- "$1" || rc=$?
  return "$rc"
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  printf 'let x = %s;\n' "RelayMode::""Default" > "$tmp/bad.rs"
  rc=0; scan "$tmp" >/dev/null || rc=$?
  if [[ $rc -eq 0 ]]; then echo "self-test: ok"; exit 0; fi
  echo "self-test: FAILED (rc=$rc)" >&2; exit 1
fi

rc=0; scan "${1:-.}" || rc=$?
case $rc in
  0) echo "FORBIDDEN strings found (see above)" >&2; exit 1 ;;
  1) echo "forbidden-strings: ok"; exit 0 ;;
  *) echo "grep error rc=$rc" >&2; exit 2 ;;
esac
