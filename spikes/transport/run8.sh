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

# ---------------------------------------------------------------- стенд NAT (части 2-5), все ns с префиксом chv8-
NS8=(i na na2 nb cg nc w m ha ha2 hb hc)
nsx8() { local ns="$1"; shift; ip netns exec "chv8-$ns" "$@"; }
spk8() { local ns="$1"; shift; nsx8 "$ns" env -i PATH="$PATH" RUST_LOG=warn "$@"; }
ipn() { local ns="$1"; shift; ip -n "chv8-$ns" "$@"; }
# bg-запуск в ns chv8-*
bg8() { # pidfile ns cmd...
  local pf="$1" ns="$2"; shift 2
  rm -f "$pf"
  nsx8 "$ns" sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$pf" "$@" &
  BG_WRAP=$!
  local i; for i in $(seq 1 50); do [[ -s "$pf" ]] && break; sleep 0.05; done
  BG_REAL="$(cat "$pf" 2>/dev/null || true)"
}
spk8_bg() { # префикс ns args...
  local p="$1" ns="$2"; shift 2
  bg8 "$p.pid" "$ns" sh -c 'exec env -i PATH="$PATH" RUST_LOG=warn "$@" >"$0.log" 2>"$0.err"' "$p" "$SPK" "$@"
}

nat_teardown() {
  local _e=0; [[ $- == *e* ]] && _e=1
  set +e
  local n
  for n in "${NS8[@]}"; do
    if ip netns list 2>/dev/null | grep -q "^chv8-$n\b"; then ip netns pids "chv8-$n" 2>/dev/null | xargs -r kill 2>/dev/null; fi
  done
  sleep 0.5
  for n in "${NS8[@]}"; do ip netns del "chv8-$n" 2>/dev/null; rm -rf "/etc/netns/chv8-$n"; done
  rmdir /etc/netns 2>/dev/null
  [[ $_e == 1 ]] && set -e
  return 0
}

vl() { # ns1 if1 ns2 if2
  ip link add "$2" netns "chv8-$1" type veth peer name "$4" netns "chv8-$3"
}

nat_setup() {
  nat_teardown
  local n; for n in "${NS8[@]}"; do ip netns add "chv8-$n"; ipn "$n" link set lo up; done
  ipn i link add core0 type bridge
  vl na wan i ia;   vl na2 wan i ia2;  vl nb wan i ib;  vl cg wan i icg;  vl w eth0 i iw;  vl m eth0 i im
  local p; for p in ia ia2 ib icg iw im; do ipn i link set "$p" master core0; ipn i link set "$p" up; done
  ipn i link set core0 up
  ipn na addr add "$CORE.10/24" dev wan; ipn na2 addr add "$CORE.20/24" dev wan; ipn nb addr add "$CORE.30/24" dev wan
  ipn cg addr add "$CORE.40/24" dev wan; ipn w addr add "$CORE.50/24" dev eth0
  ipn m addr add "$CORE.100/24" dev eth0; ipn m addr add "$CORE.101/24" dev eth0
  # LAN за na: мост lan с ha и ha2; за na2: прямой линк к eth1 ноутбука; за nb: hb; CGNAT: cg - nc - hc
  ipn na link add lan type bridge
  vl na lna ha eth0;  vl na lna2 ha2 eth0
  ipn na link set lna master lan; ipn na link set lna2 master lan
  vl na2 lan ha eth1
  vl nb lan hb eth0
  vl cg lan nc wan
  vl nc lan hc eth0
  ipn na addr add 192.168.10.1/24 dev lan; ipn na2 addr add 192.168.20.1/24 dev lan; ipn nb addr add 192.168.30.1/24 dev lan
  ipn cg addr add 100.64.0.1/10 dev lan; ipn nc addr add 100.64.0.2/10 dev wan; ipn nc addr add 192.168.40.1/24 dev lan
  ipn ha addr add 192.168.10.2/24 dev eth0; ipn ha2 addr add 192.168.10.3/24 dev eth0
  ipn ha addr add 192.168.20.2/24 dev eth1
  ipn hb addr add 192.168.30.2/24 dev eth0; ipn hc addr add 192.168.40.2/24 dev eth0
  for n in na na2 nb cg nc w m ha ha2 hb hc; do
    local ifs; ifs="$(ipn "$n" -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$')"
    for p in $ifs; do ipn "$n" link set "$p" up; done
  done
  ipn ha link set eth1 down   # второй интерфейс ноутбука выключен до G7
  ipn ha route add default via 192.168.10.1; ipn ha2 route add default via 192.168.10.1
  ipn hb route add default via 192.168.30.1; ipn hc route add default via 192.168.40.1
  ipn nc route add default via 100.64.0.1
  for n in na na2 nb cg nc; do nsx8 "$n" sysctl -qw net.ipv4.ip_forward=1; done
  nsx8 ha sysctl -qw net.ipv4.conf.all.promote_secondaries=1 net.ipv4.conf.eth0.promote_secondaries=1
  nsx8 w sysctl -qw net.ipv4.conf.all.promote_secondaries=1 net.ipv4.conf.eth0.promote_secondaries=1
  for n in ha ha2 hb hc w; do mkdir -p "/etc/netns/chv8-$n"; echo "nameserver 192.0.2.53" > "/etc/netns/chv8-$n/resolv.conf"; done
  nat_flush_all
}

# Правила NAT для ns. Типы: PR AR FC SYM; параметры: ns тип L(lan-подсеть) H(внутренний host:port для dnat) [upnp]
nat_load() {
  local ns="$1" type="$2" L="$3" H="$4" upnp="${5:-}"
  local masq="masquerade" set_decl="" fwd_upd="" pre_rule="" jumps_f="" jumps_p="" jumps_q="" extra=""
  case "$type" in
    PR) ;;
    AR)
      set_decl='set seen { type ipv4_addr; flags dynamic,timeout; timeout 120s; }'
      fwd_upd='iifname "lan" oifname "wan" udp sport 4433 update @seen { ip daddr }'
      pre_rule="iifname \"wan\" udp dport 4433 ip saddr @seen dnat ip to $H" ;;
    FC) pre_rule="iifname \"wan\" udp dport 4433 dnat ip to $H" ;;
    SYM) masq="masquerade fully-random" ;;
    *) echo "тип NAT: $type" >&2; return 1 ;;
  esac
  if [[ -n "$upnp" ]]; then
    # miniupnpd (nft-бэкенд): таблица nat8, цепочки miniupnpd / prerouting_miniupnpd / postrouting_miniupnpd, вызываются через jump
    jumps_f='jump miniupnpd'; jumps_p='jump prerouting_miniupnpd'; jumps_q='jump postrouting_miniupnpd'
    extra=$'chain miniupnpd {\n  }\n  chain prerouting_miniupnpd {\n  }\n  chain postrouting_miniupnpd {\n  }'
  fi
  nsx8 "$ns" nft flush ruleset
  nsx8 "$ns" nft -f - <<NFT
table $UPNP_FAMILY nat8 {
  $set_decl
  chain pre {
    type nat hook prerouting priority dstnat;
    $jumps_p
    $pre_rule
  }
  chain post {
    type nat hook postrouting priority srcnat;
    $jumps_q
    oifname "wan" ip saddr $L $masq
  }
  chain fwd8 {
    type filter hook forward priority filter; policy drop;
    $jumps_f
    $fwd_upd
    iifname "lan" oifname "wan" accept
    iifname "wan" ct state established,related accept
    iifname "wan" ct status dnat accept
  }
  chain inp8 {
    type filter hook input priority filter;
    iifname "wan" drop
  }
  $extra
}
NFT
}

UPNP_FAMILY="${UPNP_FAMILY:-inet}"   # miniupnpd 2.3.4 (nft) работает с таблицей семейства inet; в ip-таблице add_port даёт 501
# Тип по умолчанию на каждом NAT (свежее состояние); conntrack -F во всех NAT-ns
nat_flush_all() {
  nat_load na PR 192.168.10.0/24 192.168.10.2:4433
  nat_load na2 PR 192.168.20.0/24 192.168.20.2:4433
  nat_load nb PR 192.168.30.0/24 192.168.30.2:4433
  nat_load cg PR 100.64.0.0/10 100.64.0.2:4433
  nat_load nc PR 192.168.40.0/24 192.168.40.2:4433
  nat_ct_flush
}
nat_ct_flush() { local n; for n in na na2 nb cg nc; do nsx8 "$n" conntrack -F >/dev/null 2>&1 || true; done; }

# nft-счётчики выхода хоста (как nft_host этапа 7): ssdp, gw, peer, dns, other
nft_host8() { # ns gw peer-ip
  nsx8 "$1" nft -f - <<NFT
table inet chv8h {
  counter ssdp { }
  counter gw { }
  counter peer { }
  counter dns { }
  counter mcast_kernel { }
  counter other { }
  chain output {
    type filter hook output priority 0; policy accept;
    th dport { 53, 853 } counter name "dns"
    oifname "lo" accept
    ip daddr 239.255.255.250 udp dport 1900 counter name "ssdp" accept
    ip daddr $2 counter name "gw" accept
    ip daddr $3 counter name "peer" accept
    ip protocol igmp counter name "mcast_kernel" accept
    counter name "other" accept
  }
}
NFT
}
cnt() { # файл-счётчиков имя
  awk -v n="$2" '$1 == "counter" && $2 == n { f = 1 } f && $1 == "packets" { print $2; exit }' "$1"
}

nat_clean() { # вызывается в конце части
  nat_teardown
}
# ---------------------------------------------------------------- часть 2: G5 (UPnP, igd-next против miniupnpd)
G5D="$L8/g5"
g5_conf() { # файл ext lan-ip/маска lan-подсеть lease_file uuid
  cat > "$1" <<CONF
# G5: miniupnpd 2.3.4 (nft-бэкенд), конфиг вне /etc; PCP/NAT-PMP не включаем (enable_pcp_pmp по умолчанию no)
ext_ifname=wan
listening_ip=$2
http_port=5000
uuid=$5
enable_upnp=yes
secure_mode=yes
system_uptime=yes
upnp_table_name=nat8
upnp_nat_table_name=nat8
lease_file=$4
allow 1024-65535 $3 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
CONF
}

upnp_up() { # ns conf log   → MPD_REAL/MPD_WRAP
  local ns="$1" conf="$2" lg="$3"
  bg8 "$lg.pid" "$ns" sh -c 'exec miniupnpd -d -f "$1" -P "$2" >"$3" 2>&1' sh "$conf" "$lg.mpid" "$lg"
  MPD_REAL="$BG_REAL"; MPD_WRAP="$BG_WRAP"
  local i; for i in $(seq 1 50); do grep -qiE 'HTTP listening on port|SSDP|listening' "$lg" 2>/dev/null && break; kill -0 "$MPD_REAL" 2>/dev/null || break; sleep 0.1; done
  sleep 0.5
}
upnp_down() { kill "$MPD_REAL" 2>/dev/null || true; { wait "$MPD_WRAP"; } 2>/dev/null || true; }

# recv в ns на 4433; send из ns на адрес с дедлайном; результат: SEND_RC, лог-префикс p
g5_try() { # префикс recv_ns send_ns адрес file deadline
  local p="$1" rns="$2" sns="$3" to="$4" f="$5" dl="$6" rc=0
  rm -rf "$SHM/g5rx"; mkdir -p "$SHM/g5rx"
  spk8_bg "$p.recv" "$rns" recv --listen 0.0.0.0:4433 --pairs "$STATE" --out-dir "$SHM/g5rx" --max-bytes 17000000
  local rr="$BG_REAL" rw="$BG_WRAP"
  wait_bound "$p.recv.log" 5 || true
  timeout $((dl + 20)) ip netns exec "chv8-$sns" env -i PATH="$PATH" RUST_LOG=warn "$SPK" send --connect "$to" --pairs "$STATE" --pair 1 --file "$f" \
    --streams 1 --reconnect-deadline-s "$dl" > "$p.send.log" 2> "$p.send.err" || rc=$?
  SEND_RC=$rc
  local i; for i in $(seq 1 20); do kill -0 "$rr" 2>/dev/null || break; sleep 0.1; done
  kill "$rr" 2>/dev/null || true; { wait "$rw"; } 2>/dev/null || true
  RX_CMP="-"
  local rx; rx="$(ls "$SHM/g5rx"/rx-*.bin 2>/dev/null | head -1)"
  if [[ $rc == 0 && -n "$rx" ]]; then cmp -s "$f" "$rx" && RX_CMP=OK || RX_CMP=DIFF; fi
  rm -rf "$SHM/g5rx"
  RX_INCOMING="$(grep -c '^EVENT server_spki_issued ' "$p.recv.log" 2>/dev/null || true)"
}

g5() {
  set +e   # серия измерений: сбой отдельной команды фиксируется в строке, а не прерывает часть
  local D="$G5D"; rm -rf "$D"; mkdir -p "$D"
  [[ -x "$SPK" ]] || do_build
  header_txt "$D/header.txt"
  local nftsnap="$D/nft-host-before.txt"; host_nft_snapshot "$nftsnap"
  trap 'nat_teardown' EXIT
  local uuid1="81c5ab36-606c-44f1-a3b0-5814b1dd5001" uuid2="81c5ab36-606c-44f1-a3b0-5814b1dd5002"
  local core_note="CORE=$CORE"
  # miniupnpd отказывается работать с «зарезервированным» внешним адресом (TEST-NET-2): разрешённая спецификацией замена CORE на 11.0.0 (в netns, наружу не маршрутизируется)
  g5_stand_up() { # → поднимает стенд и miniupnpd на na
    nat_setup
    ensure_keys
    nft_host8 ha 192.168.10.1 "$CORE.50"
    g5_conf "$D/miniupnpd.conf" 192.168.10.1/24 192.168.10.0/24 "$D/upnp.leases" "$uuid1"
    nat_load na PR 192.168.10.0/24 192.168.10.2:4433 upnp
    nsx8 na nft list ruleset > "$D/nft-na-initial.txt"
    upnp_up na "$D/miniupnpd.conf" "$D/miniupnpd.log"
  }
  g5_stand_up
  if grep -q 'Reserved / private IP address' "$D/miniupnpd.log"; then
    cp "$D/miniupnpd.log" "$D/attempt1-core-${CORE}-refused.log"
    log "miniupnpd отказал для CORE=$CORE: $(grep -m1 'Reserved / private' "$D/miniupnpd.log")"
    upnp_down
    CORE_FIRST="$CORE"; CORE="11.0.0"
    core_note="CORE=$CORE (замена: miniupnpd 2.3.4 отказал при $CORE_FIRST.x: 'Reserved / private IP address', лог attempt1-core-${CORE_FIRST}-refused.log)"
    g5_stand_up
  fi
  echo "$core_note" > "$D/core.txt"
  local f16; f16="$(gen_file 16)"
  if ! kill -0 "$MPD_REAL" 2>/dev/null; then
    local why; why="$(tr '\n' ' ' < "$D/miniupnpd.log" | cut -c1-300)"
    verdict G5 open INCONCLUSIVE "$D/miniupnpd.log" "miniupnpd не завёлся ($core_note): $why"
    for k in reach close lease traffic cgnat; do verdict G5 "$k" INCONCLUSIVE "$D/miniupnpd.log" "miniupnpd не завёлся"; done
    nat_teardown; trap - EXIT; return 0
  fi
  # захват и счётчики в ha
  bg8 "$D/cap-ha.pid" ha sh -c 'exec tcpdump -U -nn -i any -s 128 -w "$0" 2>"$0.err"' "$D/cap-ha.pcap"
  local cap_real="$BG_REAL" cap_wrap="$BG_WRAP"
  sleep 1
  nsx8 ha nft reset counters > /dev/null
  # (1) open
  nsx8 na nft list ruleset > "$D/nft-na-before-map.txt"
  spk8 ha "$SPK" upnp map --internal 192.168.10.2:4433 --ext-port 4433 --lease 120 > "$D/map.log" 2> "$D/map.err" || true
  nsx8 na nft list ruleset > "$D/nft-na-after-map.txt"
  spk8 ha "$SPK" upnp info --internal 192.168.10.2:4433 > "$D/info-after-map.log" 2> "$D/info-after-map.err" || true
  local mapped gw extip nat_added
  mapped="$(grep -c '^EVENT upnp_mapped ' "$D/map.log" || true)"
  gw="$(grep '^EVENT upnp_gateway ' "$D/map.log" | kv addr)"; extip="$(grep '^EVENT upnp_ext_ip ' "$D/map.log" | kv ip)"
  nat_added="$(diff "$D/nft-na-before-map.txt" "$D/nft-na-after-map.txt" | grep -c '^>' || true)"
  local lease_seen; lease_seen="$(grep '^EVENT upnp_entry ' "$D/info-after-map.log" | head -1)"
  if [[ "$mapped" == 1 && "$nat_added" -gt 0 ]]; then
    verdict G5 open OK "$D/map.log" "igd-next нашёл шлюз $gw, внешний IP $extip, add_port UDP 4433->192.168.10.2:4433 lease 120 принят; в na добавлено строк nft: $nat_added (nft-na-after-map.txt); запись: ${lease_seen#EVENT }"
  else
    verdict G5 open NO "$D/map.log" "mapped=$mapped nft_added=$nat_added: $(grep -h 'upnp_error' "$D/map.log" | head -2 | tr '\n' ' ')"
  fi
  # (2) reach
  g5_try "$D/reach" ha w "$CORE.10:4433" "$f16" 15
  local peer_ok; peer_ok="$(grep -c "^EVENT auth_ok .*side=s peer=$CORE.50:" "$D/reach.recv.log" || true)"
  if [[ $SEND_RC == 0 && $RX_CMP == OK && $peer_ok -ge 1 ]]; then
    verdict G5 reach OK "$D/reach.send.log" "w ($CORE.50) -> $CORE.10:4433 дошло до ha по маппингу: 16 МиБ, cmp OK, auth_ok у ha от $CORE.50; $(grep '^EVENT send_result' "$D/reach.send.log" | sed 's/EVENT //')"
  else
    verdict G5 reach NO "$D/reach.send.log" "send_rc=$SEND_RC cmp=$RX_CMP peer_auth=$peer_ok"
  fi
  # (3) close
  spk8 ha "$SPK" upnp unmap --internal 192.168.10.2:4433 --ext-port 4433 > "$D/unmap.log" 2> "$D/unmap.err" || true
  nsx8 na nft list ruleset > "$D/nft-na-after-unmap.txt"
  g5_try "$D/closed" ha w "$CORE.10:4433" "$f16" 10
  local unm; unm="$(grep -c '^EVENT upnp_unmapped ' "$D/unmap.log" || true)"
  local nat_left; nat_left="$(diff "$D/nft-na-before-map.txt" "$D/nft-na-after-unmap.txt" | grep -c '^[<>]' || true)"
  if [[ "$unm" == 1 && $SEND_RC != 0 && "$RX_INCOMING" == 0 ]]; then
    verdict G5 close OK "$D/closed.send.log" "remove_port принят, правила na вернулись к исходным (отличий nft: $nat_left), send с дедлайном 10 с не прошёл (rc=$SEND_RC), у ha входящих рукопожатий: $RX_INCOMING"
  else
    verdict G5 close NO "$D/closed.send.log" "unmapped=$unm send_rc=$SEND_RC incoming=$RX_INCOMING nft_diff=$nat_left"
  fi
  # (4) lease: аренда 30 с, процесс убит без unmap, ждём 90 с
  local mp_pre="$D/lease-map"
  bg8 "$mp_pre.pid" ha sh -c 'exec env -i PATH="$PATH" "$@" >"$0.log" 2>"$0.err"' "$mp_pre" "$SPK" upnp map --internal 192.168.10.2:4433 --ext-port 4433 --lease 30 --hold-s 600
  local mp_real="$BG_REAL" mp_wrap="$BG_WRAP"
  sleep 3
  nsx8 na nft list ruleset > "$D/nft-na-lease-t3.txt"
  spk8 ha "$SPK" upnp info --internal 192.168.10.2:4433 > "$D/info-lease-t3.log" 2> /dev/null || true
  kill -9 "$mp_real" 2>/dev/null || true; { wait "$mp_wrap"; } 2>/dev/null || true
  local t_kill; t_kill="$(date +%s)"
  sleep 90
  nsx8 na nft list ruleset > "$D/nft-na-lease-t90.txt"
  spk8 ha "$SPK" upnp info --internal 192.168.10.2:4433 > "$D/info-lease-t90.log" 2> /dev/null || true
  g5_try "$D/lease" ha w "$CORE.10:4433" "$f16" 10
  local e3 e90 r3 r90
  e3="$(grep -c '^EVENT upnp_entry ' "$D/info-lease-t3.log" || true)"; e90="$(grep -c '^EVENT upnp_entry ' "$D/info-lease-t90.log" || true)"
  r3="$(diff "$D/nft-na-before-map.txt" "$D/nft-na-lease-t3.txt" | grep -c '^>' || true)"; r90="$(diff "$D/nft-na-before-map.txt" "$D/nft-na-lease-t90.txt" | grep -c '^[<>]' || true)"
  local lease_entry; lease_entry="$(grep '^EVENT upnp_entry ' "$D/info-lease-t3.log" | head -1 | sed 's/EVENT //')"
  if [[ "$e3" -ge 1 && "$r3" -gt 0 && "$e90" == 0 && "$r90" == 0 && $SEND_RC != 0 && "$RX_INCOMING" == 0 ]]; then
    verdict G5 lease OK "$D/info-lease-t90.log" "аренда 30 с, процесс убит без unmap: через 3 с запись есть (${lease_entry}), через 90 с записей get_generic_port_mapping_entry: $e90, правил nft добавлено/осталось: $r3/$r90, send не прошёл (rc=$SEND_RC)"
  else
    verdict G5 lease NO "$D/info-lease-t90.log" "entries_t3=$e3 nft_added_t3=$r3 entries_t90=$e90 nft_diff_t90=$r90 send_rc=$SEND_RC incoming=$RX_INCOMING (${lease_entry:-нет записи})"
  fi
  # трафик ha
  cap_stop8() { kill -INT "$cap_real" 2>/dev/null || true; { wait "$cap_wrap"; } 2>/dev/null || true; }
  sleep 0.7; cap_stop8
  nsx8 ha nft list counters > "$D/nft-ha.txt"
  tcpdump -nn -q -r "$D/cap-ha.pcap" 2>/dev/null | awk '$3=="Out" && $4=="IP" { d=$7; sub(/:$/,"",d); n=split(d,b,"."); dip=b[1]"."b[2]"."b[3]"."b[4]; pr=$8; sub(/,$/,"",pr); print "-> " dip ":" b[n] " " pr }' | sort | uniq -c | sort -rn > "$D/ha-tuples.txt" || true
  local c_ssdp c_gw c_peer c_dns c_other c_mc
  c_ssdp="$(cnt "$D/nft-ha.txt" ssdp)"; c_gw="$(cnt "$D/nft-ha.txt" gw)"; c_peer="$(cnt "$D/nft-ha.txt" peer)"
  c_dns="$(cnt "$D/nft-ha.txt" dns)"; c_other="$(cnt "$D/nft-ha.txt" other)"; c_mc="$(cnt "$D/nft-ha.txt" mcast_kernel)"
  if [[ "$c_dns" == 0 && "$c_other" == 0 ]]; then v=OK; else v=NO; fi
  verdict G5 traffic "$v" "$D/nft-ha.txt" "пакеты ha за шаги 1-4: ssdp=$c_ssdp gw=$c_gw peer=$c_peer dns=$c_dns other=$c_other mcast_kernel=$c_mc (ssdp: 239.255.255.250:1900, gw: 192.168.10.1, peer: $CORE.50); кортежи в ha-tuples.txt"
  upnp_down
  nsx8 na nft list ruleset > "$D/nft-na-final.txt"
  # (5) G5.5: miniupnpd на nc (домашний роутер за CGNAT)
  g5_conf "$D/miniupnpd-nc.conf" 192.168.40.1/24 192.168.40.0/24 "$D/upnp-nc.leases" "$uuid2"
  nat_load nc PR 192.168.40.0/24 192.168.40.2:4433 upnp
  nsx8 nc nft list ruleset > "$D/nft-nc-initial.txt"
  nsx8 cg nft list ruleset > "$D/nft-cg-initial.txt"
  nft_host8 hc 192.168.40.1 "$CORE.50"
  upnp_up nc "$D/miniupnpd-nc.conf" "$D/miniupnpd-nc.log"
  local nc_alive=0; kill -0 "$MPD_REAL" 2>/dev/null && nc_alive=1
  spk8 hc "$SPK" upnp info --internal 192.168.40.2:4433 > "$D/cg-info.log" 2> "$D/cg-info.err" || true
  spk8 hc "$SPK" upnp map --internal 192.168.40.2:4433 --ext-port 4433 --lease 120 > "$D/cg-map.log" 2> "$D/cg-map.err" || true
  nsx8 nc nft list ruleset > "$D/nft-nc-after-map.txt"
  nsx8 cg nft list ruleset > "$D/nft-cg-after-map.txt"
  g5_try "$D/cgnat" hc w "$CORE.40:4433" "$f16" 10
  local cg_gw cg_ip cg_mapped cg_err
  cg_gw="$(grep -h '^EVENT upnp_gateway ' "$D/cg-info.log" | kv addr)"; cg_ip="$(grep -h '^EVENT upnp_ext_ip ' "$D/cg-info.log" | kv ip)"
  cg_mapped="$(grep -c '^EVENT upnp_mapped ' "$D/cg-map.log" || true)"
  cg_err="$(grep -h '^EVENT upnp_error' "$D/cg-info.log" "$D/cg-map.log" | sed 's/EVENT upnp_error t=[0-9]* //; s/msg=Request Error. Invalid response from gateway:.*/msg=пустой NewExternalIPAddress (XML в cg-info.log)/' | awk '!s[$0]++' | tr '\n' ';')"
  nsx8 hc nft list counters > "$D/nft-hc.txt"
  local hc_c; hc_c="ssdp=$(cnt "$D/nft-hc.txt" ssdp) gw=$(cnt "$D/nft-hc.txt" gw) peer=$(cnt "$D/nft-hc.txt" peer) dns=$(cnt "$D/nft-hc.txt" dns) other=$(cnt "$D/nft-hc.txt" other)"
  echo "hc: $hc_c" > "$D/hc-counters.txt"
  verdict G5 cgnat DONE "$D/cg-info.log" "miniupnpd на nc (WAN 100.64.0.2): igd-next шлюз=${cg_gw:-нет}, внешний IP по UPnP=${cg_ip:-нет}, add_port принят=$cg_mapped, ошибки: ${cg_err:-нет}; send из w на $CORE.40:4433 rc=$SEND_RC (входящих у hc: $RX_INCOMING), nc_alive=$nc_alive; счётчики hc: $hc_c"
  upnp_down
  nat_teardown; trap - EXIT
  rm -f "$f16.tmp"
  host_nft_check "$nftsnap" "g5" || true
  stand_clean_check "g5" || true
}

# ---------------------------------------------------------------- часть 3: G7 (смена IP посреди передачи)
G7D="$L8/g7"
# Формирование канала: спецификация требует netem (100 Мбит/с, 10 мс) в chv8-i на порту к w и в w на выходе.
# mode=netem: как в спецификации; mode=tbf: ВНЕ спецификации (в ядре стенда нет netem), только 100 Мбит/с без задержки.
g7_shape() { # mode out-файл
  local mode="$1" out="$2" rc=0
  if [[ $mode == netem ]]; then
    { nsx8 i tc qdisc replace dev iw root netem delay 10ms rate 100mbit && nsx8 w tc qdisc replace dev eth0 root netem delay 10ms rate 100mbit; } > "$out" 2>&1 || rc=$?
  else
    { nsx8 i tc qdisc replace dev iw root tbf rate 100mbit burst 64k latency 50ms && nsx8 w tc qdisc replace dev eth0 root tbf rate 100mbit burst 64k latency 50ms; } > "$out" 2>&1 || rc=$?
  fi
  { nsx8 i tc qdisc show dev iw; nsx8 w tc qdisc show dev eth0; } >> "$out" 2>&1
  return $rc
}

g7_event() { # случай
  case "$1" in
    7.1) ipn ha link set eth1 up; ipn ha route replace default via 192.168.20.1 dev eth1
         ipn ha addr flush dev eth0; ipn ha link set eth0 down ;;
    7.2) ipn ha link set eth0 down; sleep 15; ipn ha link set eth0 up; ipn ha route replace default via 192.168.10.1 dev eth0 ;;
    7.3) ipn w addr add "$CORE.51/24" dev eth0; ipn w addr del "$CORE.50/24" dev eth0 ;;
    *) : ;;
  esac
}

# наибольший простой: максимальный интервал (мс) между изменениями bytes в xfer_progress получателя
g7_stall() { # recv.log
  awk '/^EVENT xfer_progress / { t=$3; sub(/t=/,"",t); b=$4; sub(/bytes=/,"",b);
         if (b+0 > 0 && !st) { st=1; last=t; pb=b; next }
         if (st) { if (b != pb) { g=t-last; if (g>m) m=g; last=t; pb=b } } }
       END { if (st) { printf "%d", m } else print "-" }' "$1" | head -1
}

# один случай: номер tag(G7|G7tbf) mode
g7_case() {
  local n="$1" tag="$2" mode="$3"
  local d="$G7D/$tag-$n"; mkdir -p "$d"
  local p="$d/run"
  nat_setup; ensure_keys
  g7_shape "$mode" "$d/shape.txt" || { echo "shape-fail" > "$d/status.txt"; return 1; }
  local f; f="$(gen_file 128)"
  local size; size="$(stat -c %s "$f")"
  local srcsha; srcsha="$(sha256sum < "$f" | cut -d' ' -f1)"
  rm -rf "$SHM/g7rx"; mkdir -p "$SHM/g7rx"
  spk8_bg "$p.recv" w recv --listen 0.0.0.0:4433 --pairs "$STATE" --out-dir "$SHM/g7rx" --max-bytes $((size + 1)) --win W1 --keepalive-s 2 --idle-s 10
  local rreal="$BG_REAL" rwrap="$BG_WRAP"
  wait_bound "$p.recv.log" 5
  bg8 "$p.cap.pid" w sh -c 'exec tcpdump -U -nn -i any -s 128 -w "$0" udp port 4433 2>"$0.err"' "$d/cap-w.pcap"
  local creal="$BG_REAL" cwrap="$BG_WRAP"
  sleep 1
  local conn="$CORE.50:4433"; [[ $n == 7.3 ]] && conn="$CORE.50:4433,$CORE.51:4433"
  spk8_bg "$p.send" ha send --connect "$conn" --pairs "$STATE" --pair 1 --file "$f" --streams 1 --win W1 --keepalive-s 2 --idle-s 10 --reconnect-deadline-s 60
  local sreal="$BG_REAL" swrap="$BG_WRAP"
  local i started=0
  for i in $(seq 1 400); do grep -q 'phase=start' "$p.recv.log" 2>/dev/null && { started=1; break; }; sleep 0.05; done
  local t_ev=""
  if [[ $started == 1 && $n != 7.0 ]]; then
    sleep 4
    t_ev="$(awk '{print $1}' /proc/uptime)"
    echo "event $n at uptime=$t_ev: $(date -u +%T.%N)" > "$d/event.txt"
    g7_event "$n"
  fi
  # ждём завершения отправителя (до 100 с)
  for i in $(seq 1 1000); do kill -0 "$sreal" 2>/dev/null || break; sleep 0.1; done
  local timed_out=0
  if kill -0 "$sreal" 2>/dev/null; then timed_out=1; kill "$sreal" 2>/dev/null; fi
  { wait "$swrap"; } 2>/dev/null || true
  for i in $(seq 1 30); do kill -0 "$rreal" 2>/dev/null || break; sleep 0.1; done
  kill "$rreal" 2>/dev/null || true; { wait "$rwrap"; } 2>/dev/null || true
  sleep 0.5
  kill -INT "$creal" 2>/dev/null || true; { wait "$cwrap"; } 2>/dev/null || true
  tcpdump -nn -q -r "$d/cap-w.pcap" 2>/dev/null | awk '$3=="In" && $4=="IP" { s=$5; k=split(s,a,"."); print a[1]"."a[2]"."a[3]"."a[4]; }' | sort | uniq -c > "$d/w-sources.txt" || true
  # итог
  local rx; rx="$(ls "$SHM/g7rx"/rx-*.bin 2>/dev/null | head -1)"
  local cmpres="-" shaeq="-"
  local dline; dline="$(evl "$p.recv.log" xfer_done)"
  if [[ -n "$dline" && -n "$rx" ]]; then
    cmp -s "$f" "$rx" && cmpres=OK || cmpres=DIFF
    [[ "$(sha256sum < "$rx" | cut -d' ' -f1)" == "$srcsha" ]] && shaeq=eq || shaeq=NE
  fi
  local rcv_bytes; rcv_bytes="$(evl "$p.recv.log" xfer_progress | tail -1 | kv bytes)"
  rm -rf "$SHM/g7rx"
  local total_ms conns_r conns_s app resume ratio chg stall nrec lost
  total_ms="$(echo "$dline" | kv ms)"; conns_r="$(echo "$dline" | kv conns)"
  local sd; sd="$(evl "$p.send.log" send_done | tail -1)"; conns_s="$(echo "$sd" | kv conns)"; app="$(echo "$sd" | kv app_bytes_sent)"
  local sr; sr="$(evl "$p.send.log" send_result | tail -1)"; resume="$(echo "$sr" | kv max_resume_from)"
  ratio="-"; [[ -n "$app" ]] && ratio="$(awk -v a="$app" -v s="$size" 'BEGIN{printf "%.2f", a/s}')"
  chg="$(grep '^EVENT peer_addr_change ' "$p.recv.log" | sed 's/EVENT peer_addr_change t=[0-9]* //' | tr '\n' ';')"
  stall="$(g7_stall "$p.recv.log")"
  nrec="$(grep -c '^EVENT reconnect ' "$p.send.log" || true)"
  lost="$(grep '^EVENT conn_lost ' "$p.send.log" | sed 's/EVENT conn_lost t=[0-9]* //' | cut -c1-120 | tr '\n' ';')"
  local srcs; srcs="$(awk '{printf "%s(%s) ", $2, $1}' "$d/w-sources.txt")"
  {
    echo "case=$n tag=$tag mode=$mode size=$size timed_out=$timed_out started=$started"
    echo "arrived=$([[ -n $dline ]] && echo 1 || echo 0) recv_bytes=${rcv_bytes:-0} cmp=$cmpres sha=$shaeq"
    echo "total_ms=${total_ms:--} conns_recv=${conns_r:--} conns_send=${conns_s:--} app_bytes_sent=${app:--} ratio=$ratio max_resume_from=${resume:--}"
    echo "peer_addr_change=${chg:-нет} stall_ms=$stall reconnects=$nrec"
    echo "conn_lost=${lost:-нет}"
    echo "sources_seen_by_w=$srcs"
  } > "$d/result.txt"
  # классификация механизма
  local mech
  if [[ -z "$dline" ]]; then mech="файл не дошёл (принято ${rcv_bytes:-0} из $size Б)"
  elif [[ "${conns_s:-0}" == 1 && -n "$chg" ]]; then mech="миграция QUIC в одном соединении (conns=1, peer_addr_change: $chg)"
  elif [[ "${conns_s:-0}" == 1 ]]; then mech="одно соединение без смены пути (conns=1)"
  elif [[ "${conns_s:-0}" -ge 2 && "${resume:-0}" -gt 0 ]] && awk -v r="$ratio" 'BEGIN{exit !(r < 1.5)}'; then mech="докачка (conns=${conns_s}, RESUME=${resume} Б, app/size=$ratio)"
  else mech="≥2 соединений, но докачка не подтверждена (conns=${conns_s:-?}, RESUME=${resume:--}, app/size=$ratio)"; fi
  G7_TOTAL[$n]="${total_ms:--}"
  local v=OK; [[ -n "$dline" && $cmpres == OK && $shaeq == eq ]] || v=NO
  G7_V[$n]="$v"
  G7_TXT[$n]="$mech; cmp=$cmpres sha=$shaeq; conns=${conns_s:--}; peer_addr_change=${chg:-нет}; stall=${stall}мс; общее время=${total_ms:--}мс; app/size=$ratio; reconnect=$nrec; источники у w: $srcs"
  [[ $cmpres == DIFF || $shaeq == NE ]] && G7_STOP=1
  log "$tag $n: $v $mech | stall=${stall} мс total=${total_ms:--} мс"
  nat_teardown
  return 0
}

g7() {
  set +e
  local D="$G7D"; rm -rf "$D"; mkdir -p "$D"
  [[ -x "$SPK" ]] || do_build
  header_txt "$D/header.txt"
  local nftsnap="$D/nft-host-before.txt"; host_nft_snapshot "$nftsnap"
  trap 'nat_teardown' EXIT
  declare -gA G7_TOTAL G7_V G7_TXT
  # какой режим формирования канала доступен
  nat_setup
  local mode=netem
  g7_shape netem "$D/shape-probe.txt" || mode=none
  if [[ $mode == none ]]; then
    { cat "$D/shape-probe.txt"; echo "== /proc/config.gz"; zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_NET_SCH_NETEM|CONFIG_MODULES( |=)'; } > "$D/netem-unavailable.txt"
  fi
  nat_teardown
  local n tag
  if [[ $mode == netem ]]; then
    tag=G7
    for n in 7.0 7.1 7.2 7.3; do g7_case "$n" G7 netem; done
  else
    for n in 7.0 7.1 7.2 7.3; do
      verdict G7 "$n" INCONCLUSIVE "$D/netem-unavailable.txt" "netem недоступен в ядре стенда (CONFIG_NET_SCH_NETEM не задан, модулей нет): канал 100 Мбит/с с задержкой 10 мс по спецификации не построить, прогон по спецификации не выполнялся"
    done
    # ВНЕ СПЕЦИФИКАЦИИ, только для справки и проверки кода: tbf 100 Мбит/с без задержки (RTT около 0)
    tag=G7tbf
    for n in 7.0 7.1 7.2 7.3; do g7_case "$n" G7tbf tbf; done
  fi
  local base="${G7_TOTAL[7.0]:--}" r
  for n in 7.0 7.1 7.2 7.3; do
    [[ -n "${G7_V[$n]:-}" ]] || continue
    r="-"; [[ "$base" != "-" && "${G7_TOTAL[$n]}" != "-" ]] && r="$(awk -v a="${G7_TOTAL[$n]}" -v b="$base" 'BEGIN{printf "%.2f", a/b}')"
    local vv="${G7_V[$n]}"
    if [[ $tag == G7tbf ]]; then
      verdict G7tbf "$n" "$vv" "$D/$tag-$n/result.txt" "ВНЕ СПЕЦИФИКАЦИИ (tbf 100 Мбит/с без задержки вместо netem 100 Мбит/с + 10 мс; в вердикт G7 не входит): ${G7_TXT[$n]}; время/7.0=$r"
    else
      verdict G7 "$n" "$vv" "$D/$tag-$n/result.txt" "${G7_TXT[$n]}; время/7.0=$r"
    fi
  done
  trap - EXIT
  nat_teardown
  host_nft_check "$nftsnap" "g7" || true
  stand_clean_check "g7" || true
  [[ -z "${G7_STOP:-}" ]] || { log "СТОП: cmp нашёл расхождение"; return 3; }
  return 0
}

# ---------------------------------------------------------------- части 4-5: типы NAT, G6, G4
NATD="$L8/natcheck"
G6D="$L8/g6"
G4D="$L8/g4"

wait_ev() { # лог имя-события [сек]
  local i; for i in $(seq 1 $((${3:-5} * 10))); do grep -q "^EVENT $2 " "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1
}

nat_lh() { # ns → NAT_L NAT_H (lan-подсеть, внутренний хост:порт)
  case "$1" in
    na) NAT_L=192.168.10.0/24; NAT_H=192.168.10.2:4433 ;;
    nb) NAT_L=192.168.30.0/24; NAT_H=192.168.30.2:4433 ;;
    *) NAT_L=; NAT_H= ;;
  esac
}

# Применить тип к NAT: тип (FC|AR|PR|SYM|CG-EIM|CG-SYM|-) ns. Остальные NAT остаются PR (nat_flush_all).
nat_apply() {
  local t="$1" ns="$2"
  case "$t" in
    -) : ;;
    CG-EIM) nat_load cg PR 100.64.0.0/10 100.64.0.2:4433 ;;
    CG-SYM) nat_load cg SYM 100.64.0.0/10 100.64.0.2:4433 ;;
    *) nat_lh "$ns"; nat_load "$ns" "$t" "$NAT_L" "$NAT_H" ;;
  esac
}

nat_expect() {
  case "$1" in
    FC) echo EIM/EIF ;; AR) echo EIM/ADF ;; PR) echo EIM/APDF ;; SYM) echo EDM/APDF ;;
    CG-EIM) echo EIM/APDF ;; CG-SYM) echo EDM/APDF ;; *) echo "?" ;;
  esac
}

# ключ типа: ТИП@узел; узел: na|nb (хост ha|hb) или hc (CG: тип на cg, зонд из hc)
key_host() { case "$1" in *@na) echo ha ;; *@nb) echo hb ;; *@hc) echo hc ;; esac; }
key_type() { echo "${1%@*}"; }
key_ns() { local n="${1#*@}"; [[ "$n" == hc ]] && echo cg || echo "$n"; }

nat8_prepare() { # каталог логов
  nat_setup; ensure_keys
  spk8_bg "$1/reflect" m reflect --bind "$CORE.100:7001,$CORE.100:7002,$CORE.101:7001"
  REFL_REAL="$BG_REAL"; REFL_WRAP="$BG_WRAP"
  wait_ev "$1/reflect.log" reflect_bound 5 || log "отражатель не поднялся: $(cat "$1/reflect.err" 2>/dev/null)"
}
nat8_finish() { # nftsnap метка
  kill "$REFL_REAL" 2>/dev/null || true; { wait "$REFL_WRAP"; } 2>/dev/null || true
  nat_teardown; trap - EXIT
  host_nft_check "$1" "$2" || true
  stand_clean_check "$2" || true
}

types_get() { # ключ поле
  grep "^$1 " "$NATD/types.txt" 2>/dev/null | sed -n "s/.* $2=\([^ ]*\).*/\1/p" | head -n1
}

# ---- часть 4a: контроль эмуляции типов NAT
natcheck() {
  set +e
  local D="$NATD"; rm -rf "$D"; mkdir -p "$D"
  [[ -x "$SPK" ]] || do_build
  header_txt "$D/header.txt"
  local nftsnap="$D/nft-host-before.txt"; host_nft_snapshot "$nftsnap"
  trap 'nat_teardown' EXIT
  nat8_prepare "$D"
  : > "$D/types.txt"
  local key
  for key in FC@na AR@na PR@na SYM@na FC@nb AR@nb PR@nb SYM@nb CG-EIM@hc CG-SYM@hc; do
    local t ns host exp got ok=0 att line mapping filtering
    t="$(key_type "$key")"; ns="$(key_ns "$key")"; host="$(key_host "$key")"; exp="$(nat_expect "$t")"
    got="-"; line=""
    for att in 1 2; do
      nat_flush_all; nat_apply "$t" "$ns"
      nsx8 "$ns" nft list ruleset > "$D/nft-$key-$att.txt" 2>&1
      spk8 "$host" "$SPK" natprobe --local 0.0.0.0:4433 --r1a "$CORE.100:7001" --r1b "$CORE.100:7002" --r2 "$CORE.101:7001" > "$D/probe-$key-$att.log" 2> "$D/probe-$key-$att.err"
      line="$(grep '^EVENT nat_probe ' "$D/probe-$key-$att.log" | head -1)"
      mapping="$(echo "$line" | kv mapping)"; filtering="$(echo "$line" | kv filtering)"
      got="${mapping:--}/${filtering:--}"
      # правда с NAT: conntrack (внешний NAT) после зонда
      nsx8 "$ns" conntrack -L -p udp > "$D/ct-$key-$att.txt" 2>&1
      if [[ "$got" == "$exp" ]]; then ok=1; break; fi
    done
    local ext r1b r2 rb r2r
    ext="$(echo "$line" | kv ext)"; r1b="$(echo "$line" | kv ext_r1b)"; r2="$(echo "$line" | kv ext_r2)"
    rb="$(echo "$line" | kv r1b_reply)"; r2r="$(echo "$line" | kv r2_reply)"
    echo "$key host=$host expected=$exp got=$got ok=$ok attempts=$att ext=${ext:--} ext_r1b=${r1b:--} ext_r2=${r2:--} r1b_reply=${rb:--} r2_reply=${r2r:--}" >> "$D/types.txt"
    local note="ожидали $exp, получили $got, попыток $att; внешний адрес хоста по R1a: ${ext:--} (R1b ${r1b:--}, R2 ${r2:--}); ответ с R1b: ${rb:--}, с R2: ${r2r:--}"
    if [[ $key == FC@* ]]; then note+="; FC = проброс одного порта на одного хоста (не общий full cone)"; fi
    if [[ $ok == 1 ]]; then verdict NAT "$key" OK "$D/probe-$key-$att.log" "контроль типа прошёл: $note"
    else verdict NAT "$key" INCONCLUSIVE "$D/probe-$key-$att.log" "контроль типа НЕ прошёл дважды, строки G4/G6 с этим типом INCONCLUSIVE: $note"; fi
  done
  cp "$D/types.txt" "$D/types.final.txt"
  nat8_finish "$nftsnap" natcheck
}

# ---- часть 4b: G6 наблюдаемый адрес
ct_reply_ext() { # файл conntrack, внешний-адрес-пира → ip:port адрес, под которым пир видит хоста (reply dst:dport)
  awk -v peer="$2" '
    { n=0; m=0; split("",D); split("",P);
      for (i=1;i<=NF;i++) { if ($i ~ /^dst=/) { n++; D[n]=substr($i,5) } if ($i ~ /^dport=/) { m++; P[m]=substr($i,7) } }
      if (n>=2 && D[1]==peer && P[1]==4433) { print D[2] ":" P[2]; exit } }' "$1"
}

g6() {
  set +e
  local D="$G6D"; rm -rf "$D"; mkdir -p "$D"
  [[ -x "$SPK" ]] || do_build
  [[ -s "$NATD/types.txt" ]] || { log "нет $NATD/types.txt: сначала run8.sh natcheck"; return 1; }
  header_txt "$D/header.txt"
  local nftsnap="$D/nft-host-before.txt"; host_nft_snapshot "$nftsnap"
  trap 'nat_teardown' EXIT
  nat8_prepare "$D"
  mkdir -p "$SHM/g6rx"
  spk8_bg "$D/recv" w recv --listen 0.0.0.0:4433 --pairs "$STATE" --out-dir "$SHM/g6rx" --max-bytes 1000000
  local rr="$BG_REAL" rw="$BG_WRAP"
  wait_bound "$D/recv.log" 5 || log "recv не поднялся"
  local key
  for key in FC@na AR@na PR@na SYM@na CG-EIM@hc CG-SYM@hc; do
    local t ns host ok M
    t="$(key_type "$key")"; ns="$(key_ns "$key")"; host="$(key_host "$key")"
    ok="$(types_get "$key" ok)"; M="$(types_get "$key" ext)"
    if [[ "$ok" != 1 ]]; then
      verdict G6 "$key" INCONCLUSIVE "$NATD/types.txt" "контроль типа NAT $key не прошёл (natcheck), G6 для него не оценивается"; continue
    fi
    nat_flush_all; nat_apply "$t" "$ns"
    spk8 "$host" "$SPK" hello --connect "$CORE.50:4433" --local 0.0.0.0:4433 --pairs "$STATE" --pair 1 > "$D/hello-$key.log" 2> "$D/hello-$key.err"
    local O; O="$(grep '^EVENT observed_by_peer ' "$D/hello-$key.log" | kv addr)"
    nsx8 "$ns" conntrack -L -p udp > "$D/ct-$key.txt" 2>&1
    local E; E="$(ct_reply_ext "$D/ct-$key.txt" "$CORE.50")"
    local iface_addr="192.168.10.2" wan_home="-" ct_in=""
    if [[ $host == hc ]]; then
      iface_addr="192.168.40.2"; wan_home="100.64.0.2"
      nsx8 nc conntrack -L -p udp > "$D/ct-$key-nc.txt" 2>&1
      ct_in="$(ct_reply_ext "$D/ct-$key-nc.txt" "$CORE.50")"
    fi
    local om="нет"; [[ -n "$O" && "$O" == "$M" ]] && om="да"
    local txt="O (адрес хоста, как видит пир w)=${O:--}; E (conntrack внешнего NAT ${ns})=${E:--}; M (маппинг к отражателю m, из natcheck)=${M:--}; O=M: $om; адрес интерфейса хоста $iface_addr"
    [[ $host == hc ]] && txt+="; WAN домашнего роутера nc=$wan_home (conntrack nc: ответный адрес ${ct_in:--})"
    if [[ -n "$O" && "$O" == "$E" ]]; then verdict G6 "$key" OK "$D/hello-$key.log" "$txt"
    else verdict G6 "$key" INCONCLUSIVE "$D/hello-$key.log" "O != E (или нет данных), доклад: $txt"; fi
  done
  kill "$rr" 2>/dev/null || true; { wait "$rw"; } 2>/dev/null || true
  rm -rf "$SHM/g6rx"
  nat8_finish "$nftsnap" g6
}

# ---- часть 5: G4 одновременное открытие
# Описание строки: A (звонящий первым, t0) и B (старт на 7 с позже). Поля: хост, ns NAT, тип, порт, ключ типа.
g4_def() {
  AH=ha; AN=na; AT=PR; AP=4433; AK=PR@na; BH=hb; BN=nb; BT=PR; BP=4433; BK=PR@nb; B_EXT_FIXED=""; NEED=""
  case "$1" in
    PR-W) BH=w; BN=-; BT=-; BK=W@w; B_EXT_FIXED="$CORE.50:4433" ;;
    FC-FC) AT=FC; AK=FC@na; BT=FC; BK=FC@nb ;;
    AR-AR) AT=AR; AK=AR@na; BT=AR; BK=AR@nb ;;
    PR-PR) : ;;
    PR-FC) BT=FC; BK=FC@nb ;;
    CGEIM-PR) AH=hc; AN=cg; AT=CG-EIM; AK=CG-EIM@hc ;;
    SYM-FC) AT=SYM; AK=SYM@na; BT=FC; BK=FC@nb ;;
    SYM-AR) AT=SYM; AK=SYM@na; BT=AR; BK=AR@nb ;;
    SYM-PR) AT=SYM; AK=SYM@na; BT=PR; BK=PR@nb ;;
    SYM-SYM) AT=SYM; AK=SYM@na; BT=SYM; BK=SYM@nb ;;
    CGSYM-PR) AH=hc; AN=cg; AT=CG-SYM; AK=CG-SYM@hc ;;
    hairpin) BH=ha2; BN=na; BT=PR; BP=4434; BK=PR@na; B_EXT_FIXED="HAIRPIN" ;;
    *) return 1 ;;
  esac
  NEED="$AK"
  if [[ "$BK" != W@w ]]; then NEED="$NEED $BK"; fi
  return 0
}

g4_attempt() { # режим строка повтор → G4_ST G4_MS G4_DIR G4_NOTE
  local mode="$1" row="$2" rep="$3" p="$G4D/$mode-$row-$rep"
  nat_flush_all; nat_apply "$AT" "$AN"
  [[ $row == hairpin ]] || nat_apply "$BT" "$BN"
  local aext bext
  aext="$(types_get "$AK" ext)"; bext="$(types_get "$BK" ext)"
  [[ -n "$B_EXT_FIXED" && "$B_EXT_FIXED" != HAIRPIN ]] && bext="$B_EXT_FIXED"
  [[ "$B_EXT_FIXED" == HAIRPIN ]] && bext="$CORE.10:4434"
  local ahostlabel="$AH" aargs bargs tag rdvr="" rdvw=""
  tag="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  if [[ $mode == sync ]]; then
    spk8_bg "$p.rdv" m rdv --listen "$CORE.100:7100"
    rdvr="$BG_REAL"; rdvw="$BG_WRAP"
    wait_ev "$p.rdv.log" rdv_bound 5 || true
    aargs=(--mode sync --rdv "$CORE.100:7100" --tag "$tag" --side 1)
    bargs=(--mode sync --rdv "$CORE.100:7100" --tag "$tag" --side 2)
  else
    aargs=(--mode periodic --peer "$bext" --interval-s 5 --attempt-s 10 --deadline-s 40)
    bargs=(--mode periodic --peer "$aext" --interval-s 5 --attempt-s 10 --deadline-s 40)
  fi
  : > "$p.cap-note"
  spk8_bg "$p.A" "$AH" punch --local "0.0.0.0:$AP" --pairs "$STATE" --pair 1 "${aargs[@]}"
  local areal="$BG_REAL" awrap="$BG_WRAP"
  sleep 7
  spk8_bg "$p.B" "$BH" punch --local "0.0.0.0:$BP" --pairs "$STATE" --pair 2 "${bargs[@]}"
  local breal="$BG_REAL" bwrap="$BG_WRAP" i
  for i in $(seq 1 800); do
    kill -0 "$areal" 2>/dev/null || kill -0 "$breal" 2>/dev/null || break
    sleep 0.1
  done
  kill "$areal" "$breal" 2>/dev/null || true
  { wait "$awrap"; } 2>/dev/null || true; { wait "$bwrap"; } 2>/dev/null || true
  if [[ -n "$rdvr" ]]; then kill "$rdvr" 2>/dev/null || true; { wait "$rdvw"; } 2>/dev/null || true; fi
  nsx8 na conntrack -L -p udp > "$p.ct-na.txt" 2>&1; nsx8 nb conntrack -L -p udp > "$p.ct-nb.txt" 2>&1
  local aok bok afail bfail as bs
  aok="$(grep '^EVENT punch_ok ' "$p.A.log" | head -1)"; bok="$(grep '^EVENT punch_ok ' "$p.B.log" | head -1)"
  afail="$(grep -c '^EVENT punch_fail ' "$p.A.log")"; bfail="$(grep -c '^EVENT punch_fail ' "$p.B.log")"
  as="$(grep '^EVENT punch_start ' "$p.A.log" | kv epoch_ms)"; bs="$(grep '^EVENT punch_start ' "$p.B.log" | kv epoch_ms)"
  local att_a att_b; att_a="$(grep -c '^EVENT punch_attempt ' "$p.A.log")"; att_b="$(grep -c '^EVENT punch_attempt ' "$p.B.log")"
  G4_NOTE="известные адреса: A видит B как $bext, B видит A как $aext; попыток A/B: $att_a/$att_b"
  if [[ -n "$aok" || -n "$bok" ]]; then
    local ams adir bms bdir
    ams="$(echo "$aok" | kv ms)"; adir="$(echo "$aok" | kv dir)"; bms="$(echo "$bok" | kv ms)"; bdir="$(echo "$bok" | kv dir)"
    if [[ $mode == periodic ]]; then
      # от старта B: первый auth_ok с любой стороны
      G4_MS="$(awk -v as="${as:-0}" -v am="${ams:--1}" -v bs="${bs:-0}" -v bm="${bms:--1}" 'BEGIN{ best=-1;
        if (am>=0) { t=as+am-bs; best=t } if (bm>=0) { t=bm; if (best<0 || t<best) best=t } printf "%d", best }')"
    else
      local ga gb da db
      da="$(grep '^EVENT punch_go ' "$p.A.log" | kv delay_ms)"; db="$(grep '^EVENT punch_go ' "$p.B.log" | kv delay_ms)"
      G4_MS="$(awk -v am="${ams:--1}" -v bm="${bms:--1}" -v da="${da:-0}" -v db="${db:-0}" 'BEGIN{ best=-1;
        if (am>=0) best=am+da; if (bm>=0 && (best<0 || bm+db<best)) best=bm+db; printf "%d", best }')"
    fi
    local ab=0 ba=0
    [[ "$adir" == out || "$adir" == both || "$bdir" == in || "$bdir" == both ]] && ab=1
    [[ "$bdir" == out || "$bdir" == both || "$adir" == in || "$adir" == both ]] && ba=1
    if [[ $ab == 1 && $ba == 1 ]]; then G4_DIR=both; elif [[ $ab == 1 ]]; then G4_DIR=AB; else G4_DIR=BA; fi
    G4_ST=OK; G4_NOTE="$G4_NOTE; A dir=${adir:--} ms=${ams:--}, B dir=${bdir:--} ms=${bms:--}"
  elif [[ $afail -ge 1 && $bfail -ge 1 ]]; then
    G4_ST=NO; G4_MS="-"; G4_DIR="-"
  else
    G4_ST=ERR; G4_MS="-"; G4_DIR="-"
    G4_NOTE="$G4_NOTE; сбой запуска: A.err=$(head -c 150 "$p.A.err" | tr '\n' ' ') B.err=$(head -c 150 "$p.B.err" | tr '\n' ' ')"
  fi
}

# serie: список строк, повторы, режимы periodic и sync
g4_run() { # часть(a|b) повторы строки...
  set +e
  local part="$1" reps="$2"; shift 2
  local rows=("$@")
  local D="$G4D/$part"; G4D_BASE="$G4D"; rm -rf "$D"; mkdir -p "$D"
  [[ -x "$SPK" ]] || do_build
  [[ -s "$NATD/types.txt" ]] || { log "нет $NATD/types.txt: сначала run8.sh natcheck"; return 1; }
  header_txt "$D/header.txt"
  local nftsnap="$D/nft-host-before.txt"; host_nft_snapshot "$nftsnap"
  trap 'nat_teardown' EXIT
  local t_all0; t_all0="$(date +%s)"
  nat8_prepare "$D"
  local saveG4D="$G4D"; G4D="$D"
  : > "$D/results.tsv"
  local row mode rep
  for row in "${rows[@]}"; do
    g4_def "$row" || { log "строка $row?"; continue; }
    local gate="" k
    for k in $NEED; do [[ "$(types_get "$k" ok)" == 1 ]] || gate+="$k "; done
    for mode in periodic sync; do
      if [[ -n "$gate" ]]; then
        verdict G4 "$mode/$row" INCONCLUSIVE "$NATD/types.txt" "контроль типа NAT не прошёл: $gate(natcheck), строка не прогонялась"; continue
      fi
      local elapsed=$(( $(date +%s) - t_all0 ))
      if [[ $elapsed -gt 520 ]]; then
        verdict G4 "$mode/$row" INCONCLUSIVE "$D/results.tsv" "не уложились в 600 с подкоманды (прошло $elapsed с): строка не прогонялась"; continue
      fi
      local st_list="" ms_list="" dir_list="" nok=0 nno=0 nerr=0 note=""
      for rep in $(seq 1 "$reps"); do
        g4_attempt "$mode" "$row" "$rep"
        if [[ $G4_ST == ERR ]]; then nat_flush_all >/dev/null 2>&1; g4_attempt "$mode" "$row" "${rep}r"; fi
        echo -e "$mode\t$row\t$rep\t$G4_ST\t$G4_MS\t$G4_DIR" >> "$D/results.tsv"
        case "$G4_ST" in OK) nok=$((nok+1)); ms_list+="${G4_MS}мс/${G4_DIR} " ;; NO) nno=$((nno+1)); ms_list+="NO " ;; *) nerr=$((nerr+1)); ms_list+="ERR " ;; esac
        note="$G4_NOTE"
        log "G4 $mode/$row #$rep: $G4_ST $G4_MS $G4_DIR"
      done
      local unit="от старта B"; [[ $mode == sync ]] && unit="от GO (с задержкой 500 мс)"
      local path="$D/$mode-$row-1.A.log"
      if [[ $nerr -gt 0 ]]; then verdict G4 "$mode/$row" INCONCLUSIVE "$path" "сбой стенда в $nerr из $reps; результаты: $ms_list| $note"
      elif [[ $nok == "$reps" ]]; then verdict G4 "$mode/$row" OK "$path" "OK [$ms_list] время $unit; повторов $reps; $note"
      elif [[ $nno == "$reps" ]]; then verdict G4 "$mode/$row" NO "$path" "NO во всех $reps; $note"
      else verdict G4 "$mode/$row" DONE "$path" "нестабильно: OK $nok из $reps [$ms_list] время $unit; $note"; fi
    done
  done
  G4D="$saveG4D"
  nat8_finish "$nftsnap" "g4$part"
}
g4a() { g4_run a 2 PR-W FC-FC AR-AR PR-PR PR-FC CGEIM-PR; }
g4b() { g4_run b 1 SYM-FC SYM-AR SYM-PR SYM-SYM CGSYM-PR hairpin; }

main() {
  case "$CMD" in
    install) do_install ;;
    build) do_build ;;
    g8) g8 ;;
    g5) g5 ;;
    g7) g7 ;;
    natcheck) natcheck ;;
    g6) g6 ;;
    g4a) g4a ;;
    g4b) g4b ;;
    natup) nat_setup; echo "стенд NAT поднят (отладка)" >&2 ;;
    natdown) nat_teardown ;;
    teardown) bash "$RUNSH" teardown b ;;
    *) echo "использование: run8.sh <install|build|g8 СЦЕНАРИЙ|g5|g7|natcheck|g6|g4a|g4b|teardown>" >&2; exit 2 ;;
  esac
}
[[ -n "${RUN8_SOURCE:-}" ]] && return 0
main
