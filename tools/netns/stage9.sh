#!/usr/bin/env bash
# Стенд netns этапов 9 и 9б: повтор G1 (нет трафика к третьим сторонам) и G12 (что видит наблюдатель) на адаптере
# chervo-transport-quinn, сценарий knock (порт молчит для чужих). Использование:
#   sudo bash tools/netns/stage9.sh <g1|g12|knock|all|teardown>
# Каталог логов можно сменить: CHV_LOGS=/путь (по умолчанию tools/netns/logs).
# Функции стенда (do_teardown, veth, addr4, addr6, route6, do_setup, nft_router, nft_host, bg_start, bg_stop,
# cap_start, cap_stop, gate_begin, gate_end, cnt, evl, evn, kv, net_fail, peer_zero, verdict) скопированы из
# spikes/transport/run.sh@1528c43 без изменений, кроме пути к analyze_g1.sh ($ANALYZE вместо $ROOT/analyze_g1.sh).
# spikes/** не правится: analyze_g1.sh и g12-observe вызываются как есть.
# Бинарники запускаются только внутри ns (env -i), cargo build только вне ns. Ключи стенда лежат вне репозитория
# (CHV_STATE, по умолчанию /tmp/chervo-stage9-state, режим 0700, файлы 0600).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
SPIKE="$REPO/spikes/transport"
ANALYZE="$SPIKE/analyze_g1.sh"
OBS="$SPIKE/target/spike-bin/g12-observe"
STATE="${CHV_STATE:-/tmp/chervo-stage9-state}"
LOGS="${CHV_LOGS:-$ROOT/logs}"
BIN="$STATE/bin"
NETCHECK="$BIN/netcheck"
PORT=4433
V=chervo
SUMMARY="$LOGS/summary.txt"
BGPIDS=()
CMD="${1:-}"
# IPv6 в ядре может быть выключен: тогда шаги IPv6 пропускаются, а проверки, которым нужен IPv6, получают INCONCLUSIVE.
if [[ -e /proc/net/if_inet6 ]]; then HAVE6=1; else HAVE6=0; fi

log() { echo "[stage9.sh] $*" >&2; }
nsx() { local ns="$1"; shift; ip netns exec "chv-$ns" "$@"; }
# Запуск в ns с чистым окружением (без прокси-переменных).
spk_in() { local ns="$1"; shift; nsx "$ns" env -i PATH="$PATH" "$@"; }

CAP_REAL=(); CAP_WRAP=()
BG_REAL=""; BG_WRAP=""
GD=""
LISTEN="0.0.0.0:$PORT"
mkdirs() { mkdir -p "$LOGS"; }

# ---------------------------------------------------------------- сборка
do_build() {
  log "cargo build (вне ns)"
  ( cd "$REPO"
    cargo build --release --locked -p chervo-transport-quinn --example netcheck
  ) >&2
  mkdir -p "$BIN"
  cp "$REPO/target/release/examples/netcheck" "$NETCHECK"
}

do_teardown() {
  set +e
  for n in a b c r; do
    if ip netns list 2>/dev/null | grep -q "^chv-$n\b"; then
      ip netns pids "chv-$n" 2>/dev/null | xargs -r kill 2>/dev/null
    fi
  done
  sleep 0.5
  for n in a b c r; do
    ip netns del "chv-$n" 2>/dev/null
    rm -rf "/etc/netns/chv-$n"
  done
  rmdir /etc/netns 2>/dev/null
  set -e
}

veth() { # ns1 if1 ns2 if2
  ip link add "$2" type veth peer name "$4"
  ip link set "$2" netns "chv-$1"
  ip link set "$4" netns "chv-$3"
}

addr4() { ip -n "chv-$1" addr add "$3" dev "$2"; }

addr6() { [[ $HAVE6 == 1 ]] || return 0; ip -n "chv-$1" addr add "$3" dev "$2" nodad; }

route6() { [[ $HAVE6 == 1 ]] || return 0; ip -n "chv-$1" -6 route add default via "$2"; }

do_setup() {
  do_teardown
  log "setup netns"
  for n in a b c r; do
    ip netns add "chv-$n"
    ip -n "chv-$n" link set lo up
  done
  veth a a0 r ra
  veth b b0 r rb
  veth c c0 r rc
  veth a a1 r la   # LAN: a1 <-> la
  veth b b1 r lb   # LAN: b1 <-> lb
  addr4 a a0 10.77.1.2/24; addr6 a a0 fd77:1::2/64
  addr4 r ra 10.77.1.1/24; addr6 r ra fd77:1::1/64
  addr4 b b0 10.77.2.2/24; addr6 b b0 fd77:2::2/64
  addr4 r rb 10.77.2.1/24; addr6 r rb fd77:2::1/64
  for h in 10 11 12 20; do addr4 c c0 "10.77.3.$h/24"; done
  addr6 c c0 fd77:3::10/64
  addr4 r rc 10.77.3.1/24; addr6 r rc fd77:3::1/64
  ip -n chv-r link add br0 type bridge
  ip -n chv-r link set la master br0
  ip -n chv-r link set lb master br0
  addr4 a a1 10.77.0.2/24; addr6 a a1 fd77::2/64
  addr4 b b1 10.77.0.3/24; addr6 b b1 fd77::3/64
  for l in "a a0" "a a1" "b b0" "b b1" "c c0" "r ra" "r rb" "r rc" "r la" "r lb" "r br0"; do
    # shellcheck disable=SC2086
    set -- $l; ip -n "chv-$1" link set "$2" up
  done
  ip -n chv-a route add default via 10.77.1.1
  route6 a fd77:1::1
  ip -n chv-b route add default via 10.77.2.1
  route6 b fd77:2::1
  ip -n chv-c route add default via 10.77.3.1
  route6 c fd77:3::1
  # DNS-заглушка: TEST-NET-1, маршрут ведёт в chv-r через несуществующего соседа и режется там.
  ip -n chv-r route add 192.0.2.0/24 via 10.77.3.99 dev rc
  nsx r sysctl -qw net.ipv4.ip_forward=1
  [[ $HAVE6 == 1 ]] && nsx r sysctl -qw net.ipv6.conf.all.forwarding=1
  # Смена адреса в G1: без этого удаление основного адреса снесёт и вторичный.
  nsx a sysctl -qw net.ipv4.conf.all.promote_secondaries=1 net.ipv4.conf.a0.promote_secondaries=1
  for n in a b c; do
    mkdir -p "/etc/netns/chv-$n"
    echo "nameserver 192.0.2.53" > "/etc/netns/chv-$n/resolv.conf"
  done
  nft_router
  nft_host a "10.77.2.2, 10.77.0.3" "fd77:2::2, fd77::3" 10.77.1.1
  nft_host b "10.77.1.2, 10.77.1.3, 10.77.0.2" "fd77:1::2, fd77::2" 10.77.2.1
  # ping в среде нет: связность проверяют сами ворота (peer>0, иначе INCONCLUSIVE).
  if [[ $HAVE6 != 1 ]]; then
    log "ВНИМАНИЕ: IPv6 в ядре выключен (нет /proc/net/if_inet6), IPv6-часть стенда пропущена"
  fi
  log "стенд готов"
}

nft_router() {
  local R6FWD=""
  [[ $HAVE6 == 1 ]] && R6FWD='ip6 saddr fd77::/16 ip6 daddr fd77::/16 counter name "fwd_ok" accept'
  nsx r nft -f - <<NFT
table inet chv {
  counter fwd_ok { }
  counter fwd_drop { }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ip saddr 10.77.0.0/16 ip daddr 10.77.0.0/16 counter name "fwd_ok" accept
    $R6FWD
    counter name "fwd_drop" drop
  }
}
NFT
}

nft_host() { # ns peers4 peers6 gateway
  local ns="$1" p4="$2" p6="$3" gw="$4"
  local S6="" P6="" ND6="" M6="" PM6=""
  if [[ $HAVE6 == 1 ]]; then
    S6="set peers6 { type ipv6_addr; elements = { $p6 } }"
    P6='ip6 daddr @peers6 counter name "peer" accept'
    ND6='icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } counter name "nd" accept'
    M6='icmpv6 type mld2-listener-report counter name "mcast_kernel" accept'
    PM6='ip6 daddr { ff02::c, ff05::c } udp dport 1900 counter name "portmap" accept'
  fi
  nsx "$ns" nft -f - <<NFT
table inet chv {
  set peers4 { type ipv4_addr; elements = { $p4 } }
  $S6
  counter dns { }
  counter peer { }
  counter nd { }
  counter mcast_kernel { }
  counter portmap { }
  counter other { }
  chain output {
    type filter hook output priority 0; policy accept;
    th dport { 53, 853 } counter name "dns"
    oifname "lo" accept
    ip daddr @peers4 counter name "peer" accept
    $P6
    $ND6
    $M6
    ip protocol igmp counter name "mcast_kernel" accept
    ip daddr $gw udp dport 5351 counter name "portmap" accept
    ip daddr 239.255.255.250 udp dport 1900 counter name "portmap" accept
    $PM6
    counter name "other" accept
  }
}
NFT
}

bg_start() { # pidfile ns cmd...
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

cap_start() { # ns файл args...
  local ns="$1" f="$2" i; shift 2
  bg_start "$f.pid" "$ns" sh -c 'exec tcpdump -U -nn "$@" 2>"$0"' "$f.err" "$@" -w "$f"
  CAP_REAL+=("$BG_REAL"); CAP_WRAP+=("$BG_WRAP")
  for i in $(seq 1 50); do
    grep -q listening "$f.err" 2>/dev/null && return 0
    sleep 0.1
  done
  log "tcpdump не запустился: $f"; return 1
}

cap_stop() {
  local i
  sleep 0.7
  for i in "${!CAP_REAL[@]}"; do bg_stop "${CAP_REAL[$i]}" "${CAP_WRAP[$i]}" INT; done
  CAP_REAL=(); CAP_WRAP=()
}

gate_begin() { # имя-подкаталога
  GD="$LOGS/$1"; rm -rf "$GD"; mkdir -p "$GD"
  local ns
  for ns in a b r; do nsx "$ns" nft reset counters >/dev/null; done
  cap_start a "$GD/cap-a.pcap" -i any -s 128
  cap_start b "$GD/cap-b.pcap" -i any -s 128
}

gate_end() {
  cap_stop
  local ns
  for ns in a b r; do nsx "$ns" nft list counters > "$GD/nft-$ns.txt"; done
  for ns in a b; do tcpdump -nn -q -r "$GD/cap-$ns.pcap" > "$GD/cap-$ns.txt" 2>/dev/null || true; done
}

cnt() { # файл-счётчиков имя
  awk -v n="$2" '$1 == "counter" && $2 == n { f = 1 } f && $1 == "packets" { print $2; exit }' "$1"
}

evl() { grep "^EVENT $2 " "$1" 2>/dev/null || true; }          # строки события

evn() { grep -c "^EVENT $2 " "$1" 2>/dev/null || true; }       # число событий

kv() { sed -n "s/.* $2=\([^ ]*\).*/\1/p" | head -n1; }        # значение ключа из строки (stdin)

net_fail() { # каталог allow_portmap
  local d="$1" pm="$2" ns v
  for ns in a b; do
    v="$(cnt "$d/nft-$ns.txt" dns)"; [[ "$v" == 0 ]] || echo "dns@$ns=$v"
    v="$(cnt "$d/nft-$ns.txt" other)"; [[ "$v" == 0 ]] || echo "other@$ns=$v"
    if [[ "$pm" != 1 ]]; then v="$(cnt "$d/nft-$ns.txt" portmap)"; [[ "$v" == 0 ]] || echo "portmap@$ns=$v"; fi
  done
  v="$(cnt "$d/nft-r.txt" fwd_drop)"; [[ "$v" == 0 ]] || echo "fwd_drop=$v"
  "$ANALYZE" "$d/cap-a.pcap" "10.77.2.2,10.77.0.3,fd77:2::2,fd77::3" 10.77.1.1 "$pm" > "$d/analysis-a.txt" || true
  "$ANALYZE" "$d/cap-b.pcap" "10.77.1.2,10.77.1.3,10.77.0.2,fd77:1::2,fd77::2" 10.77.2.1 "$pm" > "$d/analysis-b.txt" || true
  grep -q '^VIOLATIONS 0$' "$d/analysis-a.txt" || echo "tuples@a=$(grep -c '^VIOLATION ' "$d/analysis-a.txt")"
  grep -q '^VIOLATIONS 0$' "$d/analysis-b.txt" || echo "tuples@b=$(grep -c '^VIOLATION ' "$d/analysis-b.txt")"
}

peer_zero() { # каталог → непусто, если peer==0 на любой стороне
  local d="$1" ns
  for ns in a b; do [[ "$(cnt "$d/nft-$ns.txt" peer)" -gt 0 ]] || echo "peer@$ns=0"; done
}

verdict() { # G1 PASS evidence reason
  mkdirs; touch "$SUMMARY"
  grep -v "^$1 " "$SUMMARY" > "$SUMMARY.tmp" || true
  mv "$SUMMARY.tmp" "$SUMMARY"
  echo "$1 $2 ${3#"$ROOT"/} $4" >> "$SUMMARY"
  log "$1 $2: $4"
}

# ---------------------------------------------------------------- общие помощники этапа 9
ensure_ready_knock() {
  [[ -x "$NETCHECK" ]] || do_build
  ip netns list | grep -q '^chv-r\b' || do_setup
  if [[ ! -f "$STATE/needles.txt" ]]; then
    mkdir -p "$STATE"; chmod 700 "$STATE"
    spk_in a "$NETCHECK" keygen --dir "$STATE" > /dev/null
  fi
}

ensure_ready() {
  [[ -x "$NETCHECK" ]] || do_build
  [[ -x "$OBS" ]] || { log "нет $OBS: g12-observe собирается в spikes/transport (cargo build --release --locked)"; exit 3; }
  ip netns list | grep -q '^chv-r\b' || do_setup
  if [[ ! -f "$STATE/needles.txt" ]]; then
    mkdir -p "$STATE"; chmod 700 "$STATE"
    spk_in a "$NETCHECK" keygen --dir "$STATE" > /dev/null
  fi
}

# Сервер (listen) в ns: pid пишется после exec; ждёт `EVENT bound`.
SRV_PID=""; SRV_WRAP=""
srv_start() { # лог ns
  local lf="$1" ns="$2" i
  bg_start "$lf.pid" "$ns" sh -c 'exec env -i PATH="$PATH" "$@" >"$0" 2>"$0.err"' "$lf" "$NETCHECK" listen --dir "$STATE" --listen "$LISTEN"
  SRV_PID="$BG_REAL"; SRV_WRAP="$BG_WRAP"
  for i in $(seq 1 100); do
    grep -q '^EVENT bound' "$lf" 2>/dev/null && return 0
    kill -0 "$SRV_PID" 2>/dev/null || { log "сервер завершился: $(cat "$lf.err" 2>/dev/null)"; return 1; }
    sleep 0.1
  done
  log "сервер не поднялся"; return 1
}
srv_stop() {
  bg_stop "$SRV_PID" "$SRV_WRAP"
  SRV_PID=""; SRV_WRAP=""
}

cli() { # лог ns args... — клиент на переднем плане
  local lf="$1" ns="$2"; shift 2
  spk_in "$ns" "$NETCHECK" connect --dir "$STATE" "$@" >"$lf" 2>"$lf.err" || true
}

# ---------------------------------------------------------------- G1
g1() {
  ensure_ready
  rm -rf "$LOGS/g1"
  local tgt="10.77.2.2:$PORT" i
  gate_begin g1
  srv_start "$GD/server.log" b
  bg_start "$GD/client.pid" a sh -c 'exec env -i PATH="$PATH" "$@" >"$0" 2>"$0.err"' \
    "$GD/client.log" "$NETCHECK" connect --dir "$STATE" --to "$tgt" --pair 1 --bytes 65536 --duration 60 --idle-s 30 --change-addr-at 30
  local cl_wrap="$BG_WRAP"
  for i in $(seq 1 600); do grep -q '^EVENT addr_change_mark' "$GD/client.log" 2>/dev/null && break; sleep 0.1; done
  ip -n chv-a addr add 10.77.1.3/24 dev a0
  ip -n chv-a addr del 10.77.1.2/24 dev a0
  echo "addr_change at client t=$(evl "$GD/client.log" addr_change_mark | kv x t) ms: 10.77.1.2 -> 10.77.1.3" > "$GD/addr_change.txt"
  { wait "$cl_wrap"; } 2>/dev/null || true
  ip -n chv-a addr add 10.77.1.2/24 dev a0
  ip -n chv-a addr del 10.77.1.3/24 dev a0
  sleep 1
  srv_stop
  gate_end
  local f z
  f="$(net_fail "$GD" 0 | tr '\n' ' ')"
  z="$(peer_zero "$GD" | tr '\n' ' ')"
  evl "$GD/client.log" auth_ok | grep -q 'side=c' || f+="client_no_auth_ok "
  evl "$GD/client.log" app_ok | grep -q 'echo_eq=1' || f+="no_echo_eq "
  evl "$GD/client.log" after_idle | grep -q 'conn_alive=1 probe_ok=1' || f+="no_alive_after_idle "
  [[ "$(evn "$GD/server.log" addr_changed)" -ge 1 ]] || f+="server_no_addr_changed "
  {
    for ns in a b r; do echo "-- nft $ns"; grep -E "counter|packets" "$GD/nft-$ns.txt" | paste - - | awk '{print $2 "=" $5}' | tr '\n' ' '; echo; done
    echo "-- analysis a"; cat "$GD/analysis-a.txt"
    echo "-- analysis b"; cat "$GD/analysis-b.txt"
    echo "-- client"; evl "$GD/client.log" auth_ok; evl "$GD/client.log" app_ok; evl "$GD/client.log" after_idle; evl "$GD/client.log" client_result
    echo "-- server"; evl "$GD/server.log" auth_ok; evl "$GD/server.log" addr_changed
    echo "fails=[$f] inconclusive=[$z]"
  } > "$GD/result.txt"
  if [[ -n "${f// /}" ]]; then verdict G1 FAIL "$GD" "$f"
  elif [[ -n "${z// /}" ]]; then verdict G1 INCONCLUSIVE "$GD" "$z"
  else verdict G1 PASS "$GD" "dns=0 other=0 portmap=0 fwd_drop=0, кортежи вне списка пусты, peer>0 у обеих сторон, auth_ok side=c, app_ok echo_eq=1, after_idle conn_alive=1 probe_ok=1, addr_changed>=1 у сервера"
  fi
}

# ---------------------------------------------------------------- G12
g12() {
  ensure_ready
  GD="$LOGS/g12"; rm -rf "$GD"; mkdir -p "$GD"
  local tgt="10.77.2.2:$PORT"
  cap_start r "$GD/g12.pcap" -i rb -s 0 udp
  srv_start "$GD/server.log" b
  cli "$GD/c-1.log" a --to "$tgt" --pair 1 --bytes 4096 --duration 1
  cli "$GD/c-2.log" a --to "$tgt" --pair 2 --bytes 4096 --duration 1
  sleep 1
  srv_stop
  cap_stop
  cp "$STATE/needles.txt" "$GD/needles.txt"
  echo "uname_n str $(uname -n)" >> "$GD/needles.txt"
  nsx r env -i PATH="$PATH" "$OBS" --pcap "$GD/g12.pcap" --needles "$GD/needles.txt" --alpn chervo/1 --version 1 > "$GD/observe.txt" || true
  local res; res="$(grep '^RESULT ' "$GD/observe.txt" || true)"
  local sz; sz="$(stat -c %s "$GD/g12.pcap")"
  echo "размер захвата: $sz байт" >> "$GD/observe.txt"
  local a1 a2
  a1="$(evl "$GD/c-1.log" auth_ok | grep -c 'side=c' || true)"; a2="$(evl "$GD/c-2.log" auth_ok | grep -c 'side=c' || true)"
  if [[ "$a1" != 1 || "$a2" != 1 ]]; then
    verdict G12 INCONCLUSIVE "$GD/observe.txt" "оба соединения должны пройти (auth_ok c1=$a1 c2=$a2)"; return
  fi
  case "$res" in
    "RESULT PASS"*) verdict G12 PASS "$GD/observe.txt" "${res#RESULT PASS }" ;;
    "RESULT FAIL"*) verdict G12 FAIL "$GD/observe.txt" "${res#RESULT FAIL }" ;;
    *) verdict G12 INCONCLUSIVE "$GD/observe.txt" "${res:-g12-observe не дал результата}" ;;
  esac
}

# ---------------------------------------------------------------- KNOCK (этап 9б)
# Захват на veth b0: пакеты с адреса сервера B (udp, src host B) за время действий «чужого» и друга.
B_IP="10.77.2.2"
srv_start_opts() { # лог ns [доп. аргументы listen]
  local lf="$1" ns="$2" i; shift 2
  bg_start "$lf.pid" "$ns" sh -c 'exec env -i PATH="$PATH" "$@" >"$0" 2>"$0.err"' "$lf" "$NETCHECK" listen --dir "$STATE" --listen "$LISTEN" "$@"
  SRV_PID="$BG_REAL"; SRV_WRAP="$BG_WRAP"
  for i in $(seq 1 100); do
    grep -q '^EVENT bound' "$lf" 2>/dev/null && return 0
    kill -0 "$SRV_PID" 2>/dev/null || { log "сервер завершился: $(cat "$lf.err" 2>/dev/null)"; return 1; }
    sleep 0.1
  done
  log "сервер не поднялся"; return 1
}

b_packets() { # pcap → число пакетов udp с адреса B
  tcpdump -r "$1" -nn "udp and src host $B_IP" 2>/dev/null | wc -l
}

knock() {
  ensure_ready_knock
  KD="$LOGS/knock"; rm -rf "$KD"; mkdir -p "$KD"
  local tgt="$B_IP:$PORT" mode n f="" z="" cap
  # 1. сервер со стуком; чужой по очереди во всех режимах, на каждый режим свой захват
  srv_start_opts "$KD/server.log" b
  for mode in noise stranger stale replay flood; do
    cap="$KD/cap-$mode.pcap"
    cap_start b "$cap" -i b0 -s 128 udp
    spk_in a "$NETCHECK" probe --dir "$STATE" --to "$tgt" --mode "$mode" > "$KD/probe-$mode.log" 2> "$KD/probe-$mode.err" || true
    cap_stop
    n="$(b_packets "$cap")"
    echo "mode=$mode b_packets=$n" >> "$KD/result.txt"
    [[ "$n" == 0 ]] || f+="${mode}_b_packets=$n "
    evl "$KD/probe-$mode.log" probe_done | grep -q "connect=TimedOut" || f+="${mode}_connect_not_timedout "
  done
  # 2. друг соединяется (он же положительный контроль захвата: пакеты B видны)
  cap="$KD/cap-friend.pcap"
  cap_start b "$cap" -i b0 -s 128 udp
  cli "$KD/friend.log" a --to "$tgt" --pair 1 --bytes 4096 --duration 1
  sleep 0.5
  cap_stop
  n="$(b_packets "$cap")"
  echo "friend b_packets=$n" >> "$KD/result.txt"
  [[ "$n" -gt 0 ]] || z+="friend_capture_empty "
  evl "$KD/friend.log" auth_ok | grep -q 'side=c' || f+="friend_no_auth_ok "
  evl "$KD/friend.log" app_ok | grep -q 'echo_eq=1' || f+="friend_no_echo_eq "
  sleep 1
  { evl "$KD/server.log" stats | tail -n 1; } > "$KD/server-stats-last.txt"
  srv_stop
  # 3. положительный контроль: при --no-knock те же действия получают ответ
  srv_start_opts "$KD/server-noknock.log" b --no-knock
  cap="$KD/cap-control.pcap"
  cap_start b "$cap" -i b0 -s 128 udp
  spk_in a "$NETCHECK" probe --dir "$STATE" --to "$tgt" --mode noise > "$KD/probe-control.log" 2> "$KD/probe-control.err" || true
  cap_stop
  n="$(b_packets "$cap")"
  echo "control(no-knock, noise) b_packets=$n" >> "$KD/result.txt"
  [[ "$n" -gt 0 ]] || z+="control_no_reply "
  srv_stop
  if [[ -n "${f// /}" ]]; then verdict KNOCK FAIL "$KD/result.txt" "$f"
  elif [[ -n "${z// /}" ]]; then verdict KNOCK INCONCLUSIVE "$KD/result.txt" "$z"
  else verdict KNOCK PASS "$KD/result.txt" "ноль пакетов с адреса сервера при noise, stranger, stale, replay, flood (захват на veth b); друг: auth_ok side=c, app_ok echo_eq=1; контроль при --no-knock: ответы есть"
  fi
}

# ---------------------------------------------------------------- вход
need_privs() {
  [[ "$(id -u)" == 0 ]] || { echo "INCONCLUSIVE: нужен root (netns, nftables)" >&2; exit 3; }
  command -v ip >/dev/null && command -v nft >/dev/null && command -v tcpdump >/dev/null \
    || { echo "INCONCLUSIVE: нужны ip, nft, tcpdump" >&2; exit 3; }
}

trap 'for p in "${BGPIDS[@]}"; do kill "$p" 2>/dev/null || true; done' EXIT
case "$CMD" in
  teardown) need_privs; do_teardown ;;
  g1) need_privs; g1 ;;
  g12) need_privs; g12 ;;
  knock) need_privs; mkdirs; knock ;;
  all) need_privs; g1; g12; knock; echo "--- $SUMMARY"; cat "$SUMMARY" ;;
  *) echo "использование: stage9.sh <g1|g12|knock|all|teardown>" >&2; exit 2 ;;
esac
