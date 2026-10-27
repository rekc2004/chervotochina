#!/usr/bin/env bash
# Live check of our Secret Service client against a real gnome-keyring (stage 17a, L1-L3).
# CI only. Run it inside a private session bus:
#   dbus-run-session -- bash scripts/ci-secret-service.sh
# It starts gnome-keyring unlocked with a throw-away password that protects nothing.
set -euo pipefail

cd "$(dirname "$0")/.."

printf '%s' 'ci-not-a-secret' | gnome-keyring-daemon --unlock --components=secrets >/dev/null

# Wait (at most 10 s) until the service owns its bus name.
owned=no
for _ in $(seq 1 50); do
  if command -v dbus-send >/dev/null 2>&1; then
    if dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
      org.freedesktop.DBus.NameHasOwner string:org.freedesktop.secrets 2>/dev/null |
      grep -q 'boolean true'; then
      owned=yes
      break
    fi
  else
    sleep 3
    owned=yes
    break
  fi
  sleep 0.2
done
if [ "$owned" != yes ]; then
  echo "org.freedesktop.secrets did not appear on the session bus" >&2
  exit 1
fi

# Stage 19v: `chervo doctor` against the unlocked service says "available"; without a bus, "unavailable".
cargo build -p chervo-cli --locked
out="$(./target/debug/chervo doctor)"
echo "doctor (unlocked): $out"
[ "$out" = "хранилище ключей доступно" ]
rc=0
out="$(env -u DBUS_SESSION_BUS_ADDRESS ./target/debug/chervo doctor)" || rc=$?
echo "doctor (no bus): rc=$rc $out"
[ "$rc" -eq 1 ]
case "$out" in "хранилище ключей недоступно"*) ;; *) exit 1 ;; esac

# L1 and L2 first. L3 locks the default collection, so it gets its own run, last.
cargo test -p chervo-identity --locked --lib -- --ignored --test-threads=1 \
  ss_live_roundtrip ss_live_attributes_exact
cargo test -p chervo-identity --locked --lib -- --ignored --test-threads=1 \
  ss_live_locked_bounded
