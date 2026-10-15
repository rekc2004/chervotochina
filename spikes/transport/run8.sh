#!/usr/bin/env bash
# Стенд замеров этапа 8 (только вариант B): установка инструментов, сборка, G8, G5, G7, натчек, G6, G4.
# Использование: run8.sh <install|build|g8 СЦЕНАРИЙ|g5|g7|natcheck|g6|g4a|g4b|teardown>
# Бинарники запускаются только внутри ns (env -i), cargo build только вне ns. Каждая подкоманда: timeout 600.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CMD="${1:-}"
ARG="${2:-}"
L8="$ROOT/logs/b8"
BIN="$ROOT/target/spike-bin"
SPK="$BIN/spike8"
STATE="$ROOT/state/b8"
SUMMARY="$L8/summary8.txt"
SHM=/dev/shm/chv8
PORT=4433
CORE="${CORE:-198.51.100}"
CLK_TCK="$(getconf CLK_TCK)"

log() { echo "[run8.sh] $*" >&2; }

# Подкоманды (кроме teardown) выполняются под timeout 600 (спецификация); обёртка перезапускает сам скрипт.
if [[ -z "${RUN8_INNER:-}" && "$CMD" != "" && "$CMD" != teardown ]]; then
  mkdir -p "$L8/time"
  tf="$L8/time/${CMD}${ARG:+-$ARG}.txt"
  rc=0
  t_start="$(date +%s.%N)"   # /usr/bin/time в среде нет (пакет time не в списке разрешённых)
  RUN8_INNER=1 timeout 600 bash "$0" "$@" || rc=$?
  echo "elapsed_s=$(awk -v a="$t_start" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}')" > "$tf"
  echo "exit_code=$rc" >> "$tf"
  exit "$rc"
fi

verdict() { # G8 случай OK|NO|DONE|INCONCLUSIVE путь причина
  mkdir -p "$L8"; touch "$SUMMARY"
  grep -v "^$1 $2 " "$SUMMARY" > "$SUMMARY.tmp" || true
  mv "$SUMMARY.tmp" "$SUMMARY"
  echo "$1 $2 $3 ${4#"$ROOT"/} $5" >> "$SUMMARY"
  log "$1 $2 $3: $5"
}

# ---------------------------------------------------------------- часть 0: установка
do_install() {
  local d="$L8/install"; rm -rf "$d"; mkdir -p "$d"
  nft list ruleset > "$d/nft-before.txt"
  { pgrep -a 'miniupnpd|iperf3' || true; } > "$d/pgrep-before.txt"
  { ls -la /usr/sbin/policy-rc.d 2>&1 || true; cat /usr/sbin/policy-rc.d 2>&1 || true; } > "$d/policy-rc-before.txt"
  local own_policy=0
  if [[ ! -e /usr/sbin/policy-rc.d ]]; then
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d; own_policy=1
  else
    log "policy-rc.d уже есть (см. $d/policy-rc-before.txt), не трогаю"
  fi
  echo "own_policy=$own_policy" > "$d/policy-rc-own.txt"
  apt-get update > "$d/apt-update.txt" 2>&1 || { log "apt-get update не удался, см. $d/apt-update.txt"; }
  local rc=0
  DEBIAN_FRONTEND=noninteractive apt-get install -y iperf3 conntrack ethtool miniupnpd-nftables > "$d/apt-install.txt" 2>&1 || rc=$?
  [[ $own_policy == 1 ]] && rm -f /usr/sbin/policy-rc.d
  echo "apt_install_rc=$rc" > "$d/apt-rc.txt"
  nft list ruleset > "$d/nft-after.txt"
  diff "$d/nft-before.txt" "$d/nft-after.txt" > "$d/nft.diff" && echo "nft diff: пуст" || echo "nft diff: НЕ ПУСТ"
  { pgrep -a 'miniupnpd|iperf3' || true; } > "$d/pgrep-after.txt"
  dpkg -l iperf3 conntrack ethtool miniupnpd miniupnpd-nftables libnftnl11 libmnl0 uuid-runtime 2>/dev/null | grep '^[a-z][a-z] ' > "$d/dpkg.txt" || true
  {
    iperf3 --version 2>&1 | head -1
    conntrack --version 2>&1 | head -1
    ethtool --version 2>&1 | head -1
    nft --version
    miniupnpd -h 2>&1 | head -3
  } > "$d/versions.txt" 2>&1 || true
  cat "$d/dpkg.txt" "$d/pgrep-after.txt" >&2
  [[ $rc == 0 ]] || { log "apt-get install: код $rc"; return 1; }
  [[ ! -s "$d/pgrep-after.txt" && ! -s "$d/nft.diff" ]] || { log "СТОП: после установки есть процесс или diff nft"; return 1; }
}

main() {
  case "$CMD" in
    install) do_install ;;
    *) echo "использование: run8.sh <install|build|g8 СЦЕНАРИЙ|g5|g7|natcheck|g6|g4a|g4b|teardown>" >&2; exit 2 ;;
  esac
}
main
