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

# ---------------------------------------------------------------- часть 0: сборка
do_build() {
  local d="$L8/build"; mkdir -p "$d"
  log "cargo build (вне ns)"
  ( cd "$ROOT"
    cargo build --release
    cargo build --release --locked
    mkdir -p "$BIN"
    cp target/release/spike8 "$BIN/"
    {
      echo "== cargo tree -i igd-next@0.18.0 =="; cargo tree -i igd-next@0.18.0
      echo "== cargo tree -e features -i attohttpc =="; cargo tree -e features -i attohttpc
      echo "== rustc -V =="; rustc -V
      echo "== uname -r =="; uname -r
    } > "$d/versions.txt" 2>&1
  ) >&2
  # в графе attohttpc не должно быть TLS-фич (иначе стоп)
  if grep -Eqi 'feature "(tls|rustls|native-tls|openssl|compress|json|form|multipart)' "$d/versions.txt"; then
    log "СТОП: у attohttpc найдены TLS/доп. фичи, см. $d/versions.txt"; return 1
  fi
  log "spike8 собран: $SPK"
}

# ---------------------------------------------------------------- общие помощники стенда
RUNSH="$ROOT/run.sh"
nsx() { local ns="$1"; shift; ip netns exec "chv-$ns" "$@"; }
spk_in() { local ns="$1"; shift; nsx "$ns" env -i PATH="$PATH" RUST_LOG=warn "$@"; }
kv() { sed -n "s/.* $1=\([^ ]*\).*/\1/p" | head -n1; }
evl() { grep "^EVENT $2 " "$1" 2>/dev/null || true; }

BG_REAL=""; BG_WRAP=""
bg_start() { # pidfile ns cmd...   (реальный pid после exec в BG_REAL)
  local pf="$1" ns="$2" i; shift 2
  rm -f "$pf"
  nsx "$ns" sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$pf" "$@" &
  BG_WRAP=$!
  for i in $(seq 1 50); do [[ -s "$pf" ]] && break; sleep 0.05; done
  BG_REAL="$(cat "$pf" 2>/dev/null || true)"
}
bg_stop() { # real wrap [сигнал]
  if [[ -n "${1:-}" ]]; then kill "-${3:-TERM}" "$1" 2>/dev/null || true; fi
  if [[ -n "${2:-}" ]]; then { wait "$2"; } 2>/dev/null || true; fi
}
# спайк в фоне: лог в $1.log, ошибки в $1.err; BG_REAL/BG_WRAP
spk_bg() { # префикс ns args...
  local p="$1" ns="$2"; shift 2
  bg_start "$p.pid" "$ns" sh -c 'exec env -i PATH="$PATH" RUST_LOG=warn "$@" >"$0.log" 2>"$0.err"' "$p" "$SPK" "$@"
}
wait_bound() { # лог-файл [сек]
  local i; for i in $(seq 1 $((${2:-5} * 10))); do grep -q '^EVENT bound' "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1
}

host_nft_snapshot() { nft list ruleset > "$1"; }
host_nft_check() { # снимок-до метка → пишет diff, возвращает 0 если пуст
  local after; after="$(mktemp)"; nft list ruleset > "$after"
  if diff "$1" "$after" > "$1.diff"; then rm -f "$after" "$1.diff"; echo "nft хоста: diff пуст ($2)" >&2; return 0
  else rm -f "$after"; echo "nft хоста: diff НЕ пуст ($2), см. $1.diff" >&2; return 1; fi
}

stand_clean_check() { # метка
  local bad=0
  ip netns list | grep -E '^chv' && bad=1
  ls -d /etc/netns/chv* 2>/dev/null && bad=1
  pgrep -a 'miniupnpd|iperf3|spike8' && bad=1
  [[ $bad == 0 ]] && echo "после $1: netns chv* пусты, /etc/netns/chv* нет, процессов нет" >&2
  return $bad
}

ensure_keys() {
  if [[ ! -f "$STATE/needles.hex" ]]; then mkdir -p "$STATE"; spk_in a "$SPK" keygen --dir "$STATE" >/dev/null; fi
}

header_txt() { # файл
  {
    echo "date=$(date -u +%FT%TZ)"
    echo "commit=$(git -C "$ROOT" rev-parse --short HEAD)"
    echo "rustc=$(rustc -V)"
    echo "uname_r=$(uname -r)"
    echo "nproc=$(nproc)"
    echo "cpu=$(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //')"
    echo "virt=$(systemd-detect-virt 2>/dev/null || echo unknown)"
    echo "clk_tck=$CLK_TCK"
    echo "iperf3=$(iperf3 --version 2>&1 | head -1)"
  } > "$1"
}

# ---------------------------------------------------------------- часть 1: G8
G8D="$L8/g8"
gen_file() { # МиБ → путь
  local mib="$1" f="$SHM/src-${1}M.bin"
  mkdir -p "$SHM"
  if [[ ! -f "$f" ]]; then
    local avail; avail="$(df -m --output=avail /dev/shm | tail -1 | tr -d ' ')"
    [[ "$avail" -ge 2048 ]] || { log "СТОП: в /dev/shm меньше 2 ГиБ ($avail МиБ)"; return 1; }
    head -c $((mib * 1048576)) /dev/urandom > "$f"
  fi
  echo "$f"
}

cmp_control() { # файл: копия с одним изменённым байтом, cmp обязан найти отличие
  local f="$1" c="$SHM/ctl-copy.bin" off b nb rc=0
  cp "$f" "$c"
  off=$(( $(stat -c %s "$f") / 2 ))
  b="$(dd if="$c" bs=1 skip=$off count=1 2>/dev/null | od -An -tu1 | tr -d ' ')"
  nb=$(( b ^ 1 ))
  printf "\\x$(printf %02x "$nb")" | dd of="$c" bs=1 seek=$off conv=notrunc 2>/dev/null
  cmp -s "$f" "$c" || rc=$?
  rm -f "$c"
  [[ $rc == 1 ]]
}

udp_rcvbuf_errors() { # ns → RcvbufErrors из /proc/net/snmp
  nsx "$1" awk '/^Udp:/ { if (!h) { for (i=1;i<=NF;i++) if ($i=="RcvbufErrors") c=i; h=1 } else print $c }' /proc/net/snmp 2>/dev/null | head -1
}
proc_stat() { awk '/^cpu / { busy=$2+$3+$4+$7+$8+$9; idle=$5+$6; print busy, idle }' /proc/stat; }

g8_params() { # сценарий → глобальные
  G8_RATE=0; G8_DELAY=0; G8_LIMIT=0; G8_LOSS=""; G8_RTT=0; G8_REPS=3; G8_IPERF=1
  case "$1" in
    LO) G8_SNS=b; G8_RNS=b; G8_TARGET="127.0.0.1:$PORT"; G8_LISTEN="127.0.0.1:$PORT"; G8_MIB=512; G8_IPERF=0 ;;
    L0) G8_SNS=a; G8_RNS=b; G8_TARGET="10.77.0.3:$PORT"; G8_LISTEN="0.0.0.0:$PORT"; G8_MIB=512; G8_IPERF_TO=10.77.0.3 ;;
    R1) G8_RATE=100; G8_DELAY=10; G8_LIMIT=500; G8_MIB=128; G8_RTT=20 ;;
    R2) G8_RATE=100; G8_DELAY=40; G8_LIMIT=1700; G8_MIB=128; G8_RTT=80 ;;
    R3) G8_RATE=100; G8_DELAY=20; G8_LIMIT=900; G8_MIB=16; G8_RTT=40; G8_LOSS="0.5%"; G8_REPS=2 ;;
    R4) G8_RATE=1000; G8_DELAY=10; G8_LIMIT=4200; G8_MIB=512; G8_RTT=20 ;;
    *) echo "сценарий: LO|L0|R1|R2|R3|R4" >&2; return 2 ;;
  esac
  if [[ $1 == R* ]]; then
    G8_SNS=a; G8_RNS=b; G8_TARGET="10.77.2.2:$PORT"; G8_LISTEN="0.0.0.0:$PORT"; G8_IPERF_TO=10.77.2.2
  fi
}

g8_netem() {
  local rate="${G8_RATE}mbit"; [[ $G8_RATE == 1000 ]] && rate=1gbit
  local i out="$G8DIR/netem-unavailable.txt" rc=0
  for i in ra rb la lb; do nsx r ethtool -K "$i" gro off gso off tso off > /dev/null 2>&1 || log "ethtool -K $i не удалось"; done
  { for i in ra rb la lb; do echo "== ethtool -k $i"; nsx r ethtool -k "$i" 2>&1 | grep -E 'generic-receive-offload|generic-segmentation-offload|tcp-segmentation-offload'; done; } > "$G8DIR/offload.txt"
  # rb: данные к получателю (с потерями в R3); ra: ACK-и (без потерь)
  if [[ -n "${G8_DEBUG_TBF:-}" ]]; then
    # ОТЛАДКА скрипта, не результат: netem нет, берём только tbf (без задержки); строки summary в этом режиме не пишутся
    nsx r tc qdisc replace dev rb root tbf rate "$rate" burst 64k latency 50ms || return 1
    nsx r tc qdisc replace dev ra root tbf rate "$rate" burst 64k latency 50ms || return 1
  else
    { nsx r tc qdisc replace dev rb root netem delay "${G8_DELAY}ms" rate "$rate" limit "$G8_LIMIT" ${G8_LOSS:+loss $G8_LOSS}; } > "$out" 2>&1 || rc=$?
    if [[ $rc == 0 ]]; then nsx r tc qdisc replace dev ra root netem delay "${G8_DELAY}ms" rate "$rate" limit "$G8_LIMIT" > "$out" 2>&1 || rc=$?; fi
    if [[ $rc != 0 ]]; then
      {
        echo "== tc qdisc ... netem: код $rc (вывод выше)"
        echo "== uname -r: $(uname -r)"
        echo "== /proc/config.gz: netem и модули"
        zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_NET_SCH_NETEM|CONFIG_MODULES( |=)|CONFIG_NET_SCH_FQ( |=)' || echo "(нет /proc/config.gz)"
        echo "== /lib/modules: $(ls /lib/modules 2>&1 | head -1)"
        echo "== доступные в ядре qdisc из конфига (=y)"
        zcat /proc/config.gz 2>/dev/null | grep -E '^CONFIG_NET_SCH_.*=y'
      } >> "$out"
      return 1
    fi
  fi
  { nsx r tc qdisc show dev rb; nsx r tc qdisc show dev ra; } > "$G8DIR/netem.txt"
}

# Один прогон: строка в runs.tsv. Аргументы: имя-строки win streams cc rep
g8_run() {
  local row="$1" win="$2" streams="$3" cc="$4" rep="$5" src="$6" srcsha="$7"
  local p="$G8DIR/run-$row-$rep" rxdir="$SHM/rx" size
  size="$(stat -c %s "$src")"
  rm -rf "$rxdir"; mkdir -p "$rxdir"
  spk_bg "$p.recv" "$G8_RNS" recv --listen "$G8_LISTEN" --pairs "$STATE" --out-dir "$rxdir" --max-bytes $((size + 1)) --win "$win" --cc "$cc"
  local rreal="$BG_REAL" rwrap="$BG_WRAP"
  wait_bound "$p.recv.log" 5 || { log "recv не поднялся: $(cat "$p.recv.err")"; bg_stop "$rreal" "$rwrap"; echo -e "$row\t$rep\tfail_recv" >> "$G8DIR/runs.tsv"; return 0; }
  [[ $G8_RATE != 0 ]] && { nsx r tc -s qdisc show dev rb > "$p.tc-before.txt"; nsx r tc -s qdisc show dev ra >> "$p.tc-before.txt"; }
  local rcv0 rcv1 st0 st1 w0 w1 rc=0
  rcv0="$(udp_rcvbuf_errors "$G8_RNS")"
  st0="$(proc_stat)"; w0="$(date +%s.%N)"
  timeout 60 ip netns exec "chv-$G8_SNS" env -i PATH="$PATH" RUST_LOG=warn "$SPK" send --connect "$G8_TARGET" --pairs "$STATE" --pair 1 \
    --file "$src" --streams "$streams" --win "$win" --cc "$cc" --reconnect-deadline-s 5 > "$p.send.log" 2> "$p.send.err" || rc=$?
  w1="$(date +%s.%N)"; st1="$(proc_stat)"
  # дать получателю завершиться
  local i; for i in $(seq 1 30); do kill -0 "$rreal" 2>/dev/null || break; sleep 0.1; done
  rcv1="$(udp_rcvbuf_errors "$G8_RNS")"
  [[ $G8_RATE != 0 ]] && { nsx r tc -s qdisc show dev rb > "$p.tc-after.txt"; nsx r tc -s qdisc show dev ra >> "$p.tc-after.txt"; }
  bg_stop "$rreal" "$rwrap"
  local status="ok" cmpres="-" shaeq="-" mbps="-" ms="-" bytes
  bytes="$(evl "$p.recv.log" xfer_progress | tail -1 | kv bytes)"; bytes="${bytes:-0}"
  local dline; dline="$(evl "$p.recv.log" xfer_done)"
  if [[ $rc != 0 || -z "$dline" ]]; then
    status="timeout"
    local avg; avg="$(awk -v b="$bytes" -v t="$(awk -v a="$w0" -v b2="$w1" 'BEGIN{print b2-a}')" 'BEGIN{printf "%.1f", b*8/t/1e6}')"
    mbps="$avg"; ms="$(awk -v a="$w0" -v b2="$w1" 'BEGIN{printf "%d", (b2-a)*1000}')"
  else
    bytes="$(echo "$dline" | kv bytes)"; ms="$(echo "$dline" | kv ms)"
    mbps="$(awk -v b="$bytes" -v m="$ms" 'BEGIN{ if (m>0) printf "%.1f", b*8/m/1000; else print 0 }')"
    local rx; rx="$(ls "$rxdir"/rx-*.bin 2>/dev/null | head -1)"
    if [[ -n "$rx" ]] && cmp -s "$src" "$rx"; then cmpres=OK; else cmpres=DIFF; status="cmpfail"; fi
    if [[ -n "$rx" ]]; then
      [[ "$(sha256sum < "$rx" | cut -d' ' -f1)" == "$srcsha" ]] && shaeq=eq || { shaeq=NE; status="cmpfail"; }
    fi
  fi
  rm -rf "$rxdir"
  local hs auth s_t0 s_t1 r_t0 r_t1 s_cpu r_cpu
  hs="$(evl "$p.send.log" auth_ok | grep 'side=c' | head -1 | kv hs_ms)"; auth="$(evl "$p.send.log" auth_ok | grep 'side=c' | head -1 | kv auth_ms)"
  s_t0="$(evl "$p.send.log" cpu_ticks | grep 'phase=start' | head -1 | kv ticks)"; s_t1="$(evl "$p.send.log" cpu_ticks | grep 'phase=end' | head -1 | kv ticks)"
  r_t0="$(evl "$p.recv.log" cpu_ticks | grep 'phase=start' | head -1 | kv ticks)"; r_t1="$(evl "$p.recv.log" cpu_ticks | grep 'phase=end' | head -1 | kv ticks)"
  s_cpu="-"; r_cpu="-"
  [[ -n "$s_t0" && -n "$s_t1" ]] && s_cpu="$(awk -v a="$s_t0" -v b="$s_t1" -v m="$ms" -v h="$CLK_TCK" 'BEGIN{ if (m>0) printf "%.0f", (b-a)/h/(m/1000)*100; else print "-" }')"
  [[ -n "$r_t0" && -n "$r_t1" ]] && r_cpu="$(awk -v a="$r_t0" -v b="$r_t1" -v m="$ms" -v h="$CLK_TCK" 'BEGIN{ if (m>0) printf "%.0f", (b-a)/h/(m/1000)*100; else print "-" }')"
  local sys_cores
  sys_cores="$(awk -v a="${st0% *}" -v b="${st1% *}" -v w0="$w0" -v w1="$w1" -v h="$CLK_TCK" 'BEGIN{ printf "%.2f", (b-a)/h/(w1-w0) }')"
  local q; q="$(evl "$p.send.log" qstats | tail -1)"
  local minrtt rtt cwnd lost sent cong mtu
  minrtt="$(echo "$q" | kv min_rtt_ms)"; rtt="$(echo "$q" | kv rtt_ms)"; cwnd="$(echo "$q" | kv cwnd)"; lost="$(echo "$q" | kv lost_packets)"
  sent="$(echo "$q" | kv sent_packets)"; cong="$(echo "$q" | kv congestion_events)"; mtu="$(echo "$q" | kv mtu)"
  local sendres; sendres="$(evl "$p.send.log" send_result | tail -1)"
  # контроли
  local ctl=""
  if [[ $status == ok ]]; then
    if [[ $G8_RATE != 0 ]]; then
      awk -v m="$mbps" -v r="$G8_RATE" 'BEGIN{exit !(m <= 1.05*r)}' || ctl+="speed>1.05*rate "
    fi
    if [[ $G8_RTT != 0 ]]; then
      awk -v m="${minrtt:-0}" -v r="$G8_RTT" 'BEGIN{exit !(m >= 0.75*r && m <= 1.25*r)}' || ctl+="min_rtt=${minrtt:-?}ms_вне_±25%_от_${G8_RTT} "
    fi
    if [[ -n "$G8_LOSS" ]]; then
      awk -v l="${lost:-0}" -v s="${sent:-1}" 'BEGIN{f=l/s*100; exit !(f >= 0.25 && f <= 1.0)}' || ctl+="loss_share=$(awk -v l="${lost:-0}" -v s="${sent:-1}" 'BEGIN{printf "%.2f%%", l/s*100}')_вне_[0.25,1]% "
    fi
  fi
  echo -e "$row\t$rep\t$status\t$mbps\t$ms\t$bytes\t${hs:--}\t${auth:--}\t$s_cpu\t$r_cpu\t$sys_cores\t${minrtt:--}\t${rtt:--}\t${cwnd:--}\t${lost:--}\t${sent:--}\t${cong:--}\t${mtu:--}\t$cmpres\t$shaeq\t$((rcv1 - rcv0))\t${ctl:-ok}" >> "$G8DIR/runs.tsv"
  log "G8 $G8_NAME $row #$rep: $status $mbps Мбит/с ms=$ms cmp=$cmpres sha=$shaeq ctl=${ctl:-ok} ${sendres}"
}

stats() { sort -n | awk '{a[NR]=$1} END{ if(NR==0){print "med=- min=- max=-"; exit} m=(NR%2)?a[(NR+1)/2]:(a[NR/2]+a[NR/2+1])/2; printf "med=%.1f min=%.1f max=%.1f", m, a[1], a[NR]}'; }

g8_iperf() {
  local p="$G8DIR/iperf3"
  bg_start "$p.srv.pid" "$G8_RNS" sh -c 'exec iperf3 -s -1 > "$0" 2>&1' "$p.srv.txt"
  local sr="$BG_REAL" sw="$BG_WRAP"
  sleep 1
  nsx "$G8_SNS" timeout 30 iperf3 -c "${G8_IPERF_TO}" -t 10 -f m > "$p.cli.txt" 2>&1 || true
  sleep 0.5; bg_stop "$sr" "$sw"
  local r; r="$(grep -E 'receiver' "$p.cli.txt" | awk '{for(i=1;i<=NF;i++) if ($i=="Mbits/sec") {print $(i-1); exit}}')"
  echo "${r:--}"
}

g8() {
  local scen="$ARG"
  g8_params "$scen" || return 2
  G8_NAME="$scen"
  G8DIR="$G8D/$scen"; rm -rf "$G8DIR"; mkdir -p "$G8DIR"
  ensure_stand_g8
  header_txt "$G8DIR/header.txt"
  local nftsnap="$G8DIR/nft-host-before.txt"; host_nft_snapshot "$nftsnap"
  trap 'bash "$RUNSH" teardown b >/dev/null 2>&1 || true' EXIT
  bash "$RUNSH" setup b >&2
  ensure_keys
  local rows=("W0x1 W0 1 cubic" "W1x1 W1 1 cubic" "W1x4 W1 4 cubic")
  [[ $scen == R3 ]] && rows+=("W1x1-bbr W1 1 bbr")
  [[ -z "${G8_DEBUG_TBF:-}" ]] || SUMMARY="$G8DIR/debug-summary.txt"
  if [[ $scen == R* ]] && ! g8_netem; then
    local r0
    for r0 in "${rows[@]}"; do
      verdict G8 "$scen/${r0%% *}" INCONCLUSIVE "$G8DIR/netem-unavailable.txt" "netem недоступен в ядре стенда (tc: Specified qdisc kind is unknown; CONFIG_NET_SCH_NETEM не задан, модулей нет): задержка и потери эмулировать нечем, прогон не выполнялся"
    done
    bash "$RUNSH" teardown b >&2
    trap - EXIT
    host_nft_check "$nftsnap" "g8 $scen" || true
    stand_clean_check "g8 $scen" || true
    return 0
  fi
  local src; src="$(gen_file "$G8_MIB")" || return 1
  local srcsha; srcsha="$(sha256sum < "$src" | cut -d' ' -f1)"
  echo "$srcsha  $src" > "$G8DIR/src.sha256"
  local ctl_ok=0; cmp_control "$src" && ctl_ok=1
  echo "cmp_control_detects_changed_byte=$ctl_ok" > "$G8DIR/cmp-control.txt"
  if [[ $ctl_ok != 1 ]]; then
    verdict G8 "$scen" INCONCLUSIVE "$G8DIR/cmp-control.txt" "положительный контроль cmp не сработал"; return 0
  fi
  : > "$G8DIR/runs.tsv"
  local rep r
  for rep in $(seq 1 "$G8_REPS"); do
    for r in "${rows[@]}"; do
      # shellcheck disable=SC2086
      g8_run ${r%% *} ${r#* } "$rep" "$src" "$srcsha"
    done
  done
  local iperf="-"
  [[ $G8_IPERF == 1 ]] && iperf="$(g8_iperf)"
  echo "iperf3_receiver_mbps=$iperf" > "$G8DIR/iperf3.txt"
  [[ $G8_RATE != 0 ]] && { nsx r tc -s qdisc show dev rb; nsx r tc -s qdisc show dev ra; } > "$G8DIR/tc-final.txt"
  # сводка по строкам
  local row stline n_ok n_to n_cmp n_ctl ctlmsg v reason pct
  : > "$G8DIR/rows.txt"
  for r in "${rows[@]}"; do
    row="${r%% *}"
    local tsv; tsv="$(awk -F'\t' -v r="$row" '$1==r' "$G8DIR/runs.tsv")"
    n_ok="$(echo "$tsv" | awk -F'\t' '$3=="ok"' | wc -l)"
    n_to="$(echo "$tsv" | awk -F'\t' '$3=="timeout"' | wc -l)"
    n_cmp="$(echo "$tsv" | awk -F'\t' '$3=="cmpfail"' | wc -l)"
    ctlmsg="$(echo "$tsv" | awk -F'\t' '$3=="ok" && $22!="ok" {printf "#%s:%s ", $2, $22}')"
    local speeds cpus_s cpus_r syscores minr
    speeds="$(echo "$tsv" | awk -F'\t' '$3=="ok" {print $4}' | stats)"
    cpus_s="$(echo "$tsv" | awk -F'\t' '$3=="ok" && $9!="-" {print $9}' | stats)"
    cpus_r="$(echo "$tsv" | awk -F'\t' '$3=="ok" && $10!="-" {print $10}' | stats)"
    syscores="$(echo "$tsv" | awk -F'\t' '$3=="ok" {print $11}' | stats)"
    minr="$(echo "$tsv" | awk -F'\t' '$3=="ok" && $12!="-" {print $12}' | stats)"
    local med; med="$(echo "$speeds" | sed -n 's/.*med=\([^ ]*\).*/\1/p')"
    pct="-"; [[ $G8_RATE != 0 && "$med" != "-" ]] && pct="$(awk -v m="$med" -v r="$G8_RATE" 'BEGIN{printf "%.0f%%", m/r*100}')"
    local lostsent; lostsent="$(echo "$tsv" | awk -F'\t' '$3=="ok" {printf "%s/%s ", $15, $16}')"
    local rcvb; rcvb="$(echo "$tsv" | awk -F'\t' '{printf "%s ", $21}')"
    local cmps; cmps="$(echo "$tsv" | awk -F'\t' '{printf "%s/%s ", $19, $20}')"
    stline="Мбит/с[$speeds] от_rate=$pct iperf3=${iperf} CPU_отпр%[$cpus_s] CPU_получ%[$cpus_r] система_ядер[$syscores] min_rtt_мс[$minr] lost/sent[$lostsent] udp_rcvbuf_err[$rcvb] cmp/sha[$cmps] ok=$n_ok/$G8_REPS"
    if [[ $n_cmp -gt 0 ]]; then v=NO; reason="CMP/SHA РАСХОЖДЕНИЕ (находка, стоп) $stline"
    elif [[ $n_to -gt 0 ]]; then v=NO; reason="не уложилось в 60 с в $n_to из $G8_REPS; $(echo "$tsv" | awk -F'\t' '$3=="timeout" {printf "#%s:принято %s Б, средняя %s Мбит/с ", $2, $6, $4}') | $stline"
    elif [[ $n_ok -lt $G8_REPS ]]; then v=INCONCLUSIVE; reason="прогоны не завершились штатно ($(echo "$tsv" | awk -F'\t' '$3!="ok" {printf "%s ", $3}')) $stline"
    elif [[ -n "$ctlmsg" ]]; then v=INCONCLUSIVE; reason="контроль эмуляции не прошёл: $ctlmsg| $stline"
    else v=OK; reason="$stline"; fi
    echo "$v $row $reason" >> "$G8DIR/rows.txt"
    verdict G8 "$scen/$row" "$v" "$G8DIR/runs.tsv" "$reason"
    [[ $n_cmp -gt 0 ]] && STOP_CMP=1
  done
  rm -f "$SHM/rx" 2>/dev/null || true
  bash "$RUNSH" teardown b >&2
  trap - EXIT
  host_nft_check "$nftsnap" "g8 $scen" || true
  stand_clean_check "g8 $scen" || true
  [[ -z "${STOP_CMP:-}" ]] || { log "СТОП: cmp нашёл расхождение"; return 3; }
}
ensure_stand_g8() { [[ -x "$SPK" ]] || do_build; }

main() {
  case "$CMD" in
    install) do_install ;;
    build) do_build ;;
    g8) g8 ;;
    teardown) bash "$RUNSH" teardown b ;;
    *) echo "использование: run8.sh <install|build|g8 СЦЕНАРИЙ|g5|g7|natcheck|g6|g4a|g4b|teardown>" >&2; exit 2 ;;
  esac
}
main
