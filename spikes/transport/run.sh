#!/usr/bin/env bash
# Стенд спайка транспорта (этап 7): netns, nftables, захват, ворота G1-G3, G9-G12, решение.
# Использование: run.sh <setup|teardown|g1|g2|g3|g9|g10|g11|g12|all|decide> <a|b>
# Бинарники запускаются только внутри ns (env -i), cargo build только вне ns.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CMD="${1:-}"
V="${2:-a}"
case "$V" in a|b) ;; *) echo "вариант должен быть a или b" >&2; exit 2 ;; esac
STATE="$ROOT/state/$V"
LOGS="$ROOT/logs/$V"
BIN="$ROOT/target/spike-bin"
PORT=4433
SPK="$BIN/spike-$V"
SPK_PM="$BIN/spike-a-pm"
OBS="$BIN/g12-observe"
SUMMARY="$LOGS/summary.txt"
BGPIDS=()
# IPv6 в ядре может быть выключен (ipv6.disable=1): тогда все шаги IPv6 пропускаются, а
# проверки, которым IPv6 нужен, получают INCONCLUSIVE (не PASS и не FAIL).
if [[ -e /proc/net/if_inet6 ]]; then HAVE6=1; else HAVE6=0; fi

log() { echo "[run.sh $V] $*" >&2; }
nsx() { local ns="$1"; shift; ip netns exec "chv-$ns" "$@"; }
# Запуск бинарника спайка в ns с чистым окружением (без прокси-переменных).
spk_in() { local ns="$1"; shift; nsx "$ns" env -i PATH="$PATH" RUST_LOG=warn "$@"; }

# ---------------------------------------------------------------- сборка
do_build() {
  log "cargo build (вне ns)"
  ( cd "$ROOT"
    cargo build --release --locked
    mkdir -p "$BIN"
    cp target/release/spike-a target/release/spike-b target/release/g12-observe "$BIN/"
    cargo build --release --locked --features iroh-portmapper
    cp target/release/spike-a "$BIN/spike-a-pm"
    cargo build --release --locked
  ) >&2
}

# ---------------------------------------------------------------- стенд
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

# ---------------------------------------------------------------- общие помощники
CLK_TCK="$(getconf CLK_TCK)"
LISTEN="0.0.0.0:$PORT"
[[ $HAVE6 == 1 ]] && LISTEN="$LISTEN,[::]:$PORT"
CAP_PIDS=()
SRV_PID=""
GD=""

mkdirs() { mkdir -p "$LOGS"; }
verdict() { # G1 PASS evidence reason
  mkdirs; touch "$SUMMARY"
  grep -v "^$1 " "$SUMMARY" > "$SUMMARY.tmp" || true
  mv "$SUMMARY.tmp" "$SUMMARY"
  echo "$1 $2 ${3#"$ROOT"/} $4" >> "$SUMMARY"
  log "$1 $2: $4"
}

ensure_ready() {
  [[ -x "$SPK" && -x "$OBS" ]] || do_build
  ip netns list | grep -q '^chv-r\b' || do_setup
  if [[ ! -f "$STATE/needles.hex" ]]; then
    mkdir -p "$STATE"
    spk_in a "$SPK" keygen --dir "$STATE" > /dev/null
  fi
}

# Фоновый запуск в ns: реальный pid (после exec) пишется в pidfile, pid обёртки остаётся в BG_WRAP.
BG_REAL=""; BG_WRAP=""
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

CAP_REAL=(); CAP_WRAP=()
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

SRV_WRAP=""
srv_start() { # лог ns бинарник args...  → SRV_PID
  local lf="$1" ns="$2" bin="$3" i; shift 3
  bg_start "$lf.pid" "$ns" sh -c 'exec env -i PATH="$PATH" RUST_LOG=warn "$@" >"$0" 2>"$0.err"' "$lf" "$bin" server --pairs "$STATE" "$@"
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

cli() { # лог ns бинарник args... — клиент на переднем плане
  local lf="$1" ns="$2" bin="$3"; shift 3
  spk_in "$ns" "$bin" client --pairs "$STATE" "$@" >"$lf" 2>"$lf.err" || true
}

cnt() { # файл-счётчиков имя
  awk -v n="$2" '$1 == "counter" && $2 == n { f = 1 } f && $1 == "packets" { print $2; exit }' "$1"
}
evl() { grep "^EVENT $2 " "$1" 2>/dev/null || true; }          # строки события
evn() { grep -c "^EVENT $2 " "$1" 2>/dev/null || true; }       # число событий
kv() { sed -n "s/.* $2=\([^ ]*\).*/\1/p" | head -n1; }        # значение ключа из строки (stdin)

# Критерии счётчиков G1 для одного прогона. Пишет причины провала в stdout (пусто = ок).
net_fail() { # каталог allow_portmap
  local d="$1" pm="$2" ns v
  for ns in a b; do
    v="$(cnt "$d/nft-$ns.txt" dns)"; [[ "$v" == 0 ]] || echo "dns@$ns=$v"
    v="$(cnt "$d/nft-$ns.txt" other)"; [[ "$v" == 0 ]] || echo "other@$ns=$v"
    if [[ "$pm" != 1 ]]; then v="$(cnt "$d/nft-$ns.txt" portmap)"; [[ "$v" == 0 ]] || echo "portmap@$ns=$v"; fi
  done
  v="$(cnt "$d/nft-r.txt" fwd_drop)"; [[ "$v" == 0 ]] || echo "fwd_drop=$v"
  "$ROOT/analyze_g1.sh" "$d/cap-a.pcap" "10.77.2.2,10.77.0.3,fd77:2::2,fd77::3" 10.77.1.1 "$pm" > "$d/analysis-a.txt" || true
  "$ROOT/analyze_g1.sh" "$d/cap-b.pcap" "10.77.1.2,10.77.1.3,10.77.0.2,fd77:1::2,fd77::2" 10.77.2.1 "$pm" > "$d/analysis-b.txt" || true
  grep -q '^VIOLATIONS 0$' "$d/analysis-a.txt" || echo "tuples@a=$(grep -c '^VIOLATION ' "$d/analysis-a.txt")"
  grep -q '^VIOLATIONS 0$' "$d/analysis-b.txt" || echo "tuples@b=$(grep -c '^VIOLATION ' "$d/analysis-b.txt")"
}
peer_zero() { # каталог → непусто, если peer==0 на любой стороне
  local d="$1" ns
  for ns in a b; do [[ "$(cnt "$d/nft-$ns.txt" peer)" -gt 0 ]] || echo "peer@$ns=0"; done
}

rand_hex32() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# ---------------------------------------------------------------- G11
g11() {
  ensure_ready
  if [[ $V != a ]]; then log "G11 для B = пункты 1-2 G9 (часть 2)"; return 2; fi
  GD="$LOGS/g11"; rm -rf "$GD"; mkdir -p "$GD"
  local src; src="$(echo ~/.cargo/registry/src/*/iroh-1.3.0/src)"
  local ev="$GD/evidence.txt"
  {
    echo "== (1) статически: pub fn в iroh-1.3.0 endpoint/quic.rs и endpoint.rs =="
    grep -n "pub fn" "$src/endpoint/quic.rs" "$src/endpoint.rs" | sed "s|$src/||"
  } > "$GD/pub_fn.txt"
  # кандидаты: публичные методы про крипто/ключи/резолвер/TLS на уровне iroh
  grep -E "pub fn" "$src/endpoint/quic.rs" "$src/endpoint.rs" "$src/endpoint/connection.rs" \
    | grep -iE "resolver|cert|crypto|rustls|secret|identity|tls|server_config|key" | sed "s|$src/||" > "$GD/candidates.txt"
  # известные неподходящие (проверено чтением исходника, см. разд. 4 SPIKE_TRANSPORT.md)
  local known='crypto_buffer_size|set_token_key|secret_key|dns_resolver|ca_tls_config|ca_roots_config|keylog|max_tls_tickets|crypto_provider|tls_config|create_server_config_builder|peer_identity|export_keying_material'
  grep -vE "fn ($known)\b" "$GD/candidates.txt" > "$GD/candidates-unknown.txt" || true
  {
    echo "== методы ServerConfigBuilder (endpoint/quic.rs, set_*): настройки транспорта и токенов, крипто-ключа нет =="
    sed -n '/impl ServerConfigBuilder/,/^}/p' "$src/endpoint/quic.rs" | grep -n "pub fn"
    echo "== где iroh берёт ключ сервера TLS (tls/resolver.rs): один Arc<CertifiedKey> из SecretKey endpoint =="
    grep -n "ResolveRawPublicKeyCert::new\|secret_key" "$src/tls.rs" "$src/endpoint.rs" | grep -n "Resolve\|resolver" | head -5
  } > "$GD/server_config_builder.txt"
  local api_found=0
  [[ -s "$GD/candidates-unknown.txt" ]] && api_found=1
  # (2) G3(а): клиент с верным адресом и случайным id
  start_srv_g3a "$GD"
  # (3) второй сервер на тот же порт
  local rc=0
  # первый сервер поднят в start_srv_g3a и ещё работает; второй на тот же порт
  bg_start "$GD/server2.pid" b sh -c 'exec env -i PATH="$PATH" RUST_LOG=warn "$@" >"$0" 2>"$0.err"' \
    "$GD/server2.log" "$SPK" server --pairs "$STATE" --listen "$LISTEN"
  local p2="$BG_WRAP" p2r="$BG_REAL"
  sleep 3
  if kill -0 "$p2r" 2>/dev/null; then rc=0; bg_stop "$p2r" "$p2"
  else wait "$p2" || rc=$?; fi
  srv_stop
  local bind_err=0
  if [[ $rc -ne 0 ]] && grep -qi "bind\|in use\|address" "$GD/server2.log.err"; then bind_err=1; fi
  {
    echo "api_found_unknown_candidate=$api_found"
    echo "g3a_client_result: $(evl "$GD/client-wrongid.log" client_result)"
    echo "g3a_server_hs_done_from_a: $(grep -c 'hs_done peer=10.77.1.2:' "$GD/server.log" || true)"
    echo "second_server_exit_code=$rc bind_error=$bind_err stderr: $(head -c 300 "$GD/server2.log.err")"
  } > "$ev"
  local hs_err; hs_err="$(evl "$GD/client-wrongid.log" client_result | grep -c 'hs_error' || true)"
  if [[ $api_found == 1 ]]; then
    verdict G11 INCONCLUSIVE "$GD/evidence.txt" "найден неизвестный публичный метод крипто/ключа (candidates-unknown.txt), нужен разбор architect"
  elif [[ $hs_err -ge 1 && $bind_err == 1 && "$(grep -c 'hs_done peer=10.77.1.2:' "$GD/server.log" || true)" == 0 ]]; then
    verdict G11 FAIL "$GD/evidence.txt" "публичного API нового ключа сервера на соединение на одном сокете нет; клиент без ключа сервера не соединяется; второй bind на порт отвергнут"
  else
    verdict G11 INCONCLUSIVE "$GD/evidence.txt" "статика: нет API, но динамические проверки (2)/(3) не подтвердили ожидание: hs_err=$hs_err bind_err=$bind_err"
  fi
}

start_srv_g3a() { # каталог: поднимает сервер (с лимитом) и гоняет клиента со случайным id
  local d="$1"
  srv_start "$d/server.log" b "$SPK" --listen "$LISTEN"
  cli "$d/client-wrongid.log" a "$SPK" --connect "10.77.2.2:$PORT" --id "$(cat "$STATE/mitm_ep.id")" --pair 1 --mode ok --bytes 1024
  sleep 1
}

# ---------------------------------------------------------------- G10
# Ожидаемые причины отказа сервера по режимам клиента.
declare -A EXPECT=([bad-sig]=sig [wrong-pair]=pair [wrong-key]=sig [other-conn]=sig [wrong-role]=role [timeout]=timeout [too-long]=len [early-app]=timeout)
MODES=(bad-sig wrong-pair wrong-key other-conn wrong-role timeout too-long early-app)

g10() {
  ensure_ready
  GD="$LOGS/g10"; rm -rf "$GD"; mkdir -p "$GD"
  local fails="" tgt="10.77.2.2:$PORT" idarg=()
  cap_start a "$GD/cap-a.pcap" -i any -s 128
  cap_start b "$GD/cap-b.pcap" -i any -s 128
  # (1) ok дважды
  srv_start "$GD/server.log" b "$SPK" --listen "$LISTEN" --no-limit
  cli "$GD/c-ok1.log" a "$SPK" --connect "$tgt" --pair 1 --mode ok --bytes 4096
  cli "$GD/c-ok2.log" a "$SPK" --connect "$tgt" --pair 1 --mode ok --bytes 4096
  sleep 1
  local c1 c2 s1 s2
  c1="$(evl "$GD/c-ok1.log" ekm | grep 'side=c' | kv x ekm)"; c2="$(evl "$GD/c-ok2.log" ekm | grep 'side=c' | kv x ekm)"
  s1="$(evl "$GD/server.log" ekm | grep 'side=s conn=1 ' | kv x ekm)"; s2="$(evl "$GD/server.log" ekm | grep 'side=s conn=2 ' | kv x ekm)"
  {
    echo "ok1: client_ekm=$c1 server_ekm=$s1"
    echo "ok2: client_ekm=$c2 server_ekm=$s2"
  } > "$GD/part1.txt"
  [[ -n "$c1" && "$c1" == "$s1" ]] || fails+="p1:ekm1_mismatch "
  [[ -n "$c2" && "$c2" == "$s2" ]] || fails+="p1:ekm2_mismatch "
  [[ -n "$c1" && "$c1" != "$c2" ]] || fails+="p1:ekm_same_across_conns "
  evl "$GD/c-ok1.log" client_result | grep -q ' ok ' || fails+="p1:ok1_not_ok "
  # (2) режимы атак
  : > "$GD/part2.txt"
  local m n0 slice exp res
  for m in "${MODES[@]}"; do
    n0="$(wc -l < "$GD/server.log")"
    cli "$GD/c-$m.log" a "$SPK" --connect "$tgt" --pair 1 --mode "$m" --bytes 4096
    sleep 1.5
    slice="$(tail -n +$((n0 + 1)) "$GD/server.log")"
    exp="${EXPECT[$m]}"
    res=ok
    echo "$slice" | grep '^EVENT auth_fail ' | grep -q "reason=$exp app_bytes_read=0" || res="server_no_auth_fail_$exp"
    evl "$GD/c-$m.log" client_result | grep -q 'app_bytes_received=0' || res="${res}+client_got_data"
    echo "$m expect=$exp result=$res | server: $(echo "$slice" | grep '^EVENT auth_fail ' | head -n1) | client: $(evl "$GD/c-$m.log" client_result)" >> "$GD/part2.txt"
    [[ "$res" == ok ]] || fails+="p2:$m:$res "
  done
  srv_stop
  # (3) сервер с --bad-auth2
  srv_start "$GD/server-bad2.log" b "$SPK" --listen "$LISTEN" --no-limit --bad-auth2
  cli "$GD/c-bad-auth2.log" a "$SPK" --connect "$tgt" --pair 1 --mode ok --bytes 4096
  sleep 1
  srv_stop
  {
    evl "$GD/c-bad-auth2.log" auth_fail; evl "$GD/c-bad-auth2.log" client_result
  } > "$GD/part3.txt"
  grep -q 'reason=peer_sig' "$GD/part3.txt" || fails+="p3:no_peer_sig "
  grep -q 'app_bytes_sent=0' "$GD/part3.txt" || fails+="p3:app_sent "
  # (4) MITM
  srv_start "$GD/server-mitm.log" b "$SPK" --listen "$LISTEN" --no-limit
  bg_start "$GD/mitm.pid" c sh -c 'exec env -i PATH="$PATH" RUST_LOG=warn "$@" >"$0" 2>"$0.err"' \
    "$GD/mitm.log" "$SPK" mitm --pairs "$STATE" --listen "0.0.0.0:$PORT" --upstream "$tgt"
  local mitm_real="$BG_REAL" mitm_wrap="$BG_WRAP" i
  for i in $(seq 1 100); do grep -q '^EVENT bound' "$GD/mitm.log" 2>/dev/null && break; sleep 0.1; done
  [[ $V == a ]] && idarg=(--id "$(cat "$STATE/mitm_ep.id")")
  cli "$GD/c-mitm.log" a "$SPK" --connect "10.77.3.20:$PORT" ${idarg[@]+"${idarg[@]}"} --pair 1 --mode ok --bytes 4096
  sleep 1.5
  bg_stop "$mitm_real" "$mitm_wrap"
  srv_stop
  local md mu
  md="$(evl "$GD/mitm.log" ekm | grep 'side=md' | kv x ekm)"; mu="$(evl "$GD/mitm.log" ekm | grep 'side=mu' | kv x ekm)"
  {
    echo "mitm ekm down=$md up=$mu"
    evl "$GD/server-mitm.log" auth_fail
    evl "$GD/c-mitm.log" client_result
  } > "$GD/part4.txt"
  [[ -n "$md" && -n "$mu" && "$md" != "$mu" ]] || fails+="p4:mitm_ekm "
  grep -q 'auth_fail.*reason=sig' "$GD/server-mitm.log" || fails+="p4:server_no_sig_fail "
  grep -q 'app_bytes_received=0 app_bytes_sent=0' "$GD/c-mitm.log" || fails+="p4:client_data "
  gate_end_simple
  if [[ -z "$fails" ]]; then
    verdict G10 PASS "$GD" "ekm совпадает и различается между соединениями; 8 режимов отказа до прикладных данных; peer_sig; MITM с разными ekm отвергнут (sig)"
  else
    verdict G10 FAIL "$GD" "сбои: $fails"
  fi
}

gate_end_simple() { # завершение без анализа счётчиков G1
  cap_stop
  local ns
  for ns in a b r; do nsx "$ns" nft list counters > "$GD/nft-$ns.txt"; done
}

# ---------------------------------------------------------------- G3
cpu_ticks() { awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

g3() {
  ensure_ready
  GD="$LOGS/g3"; rm -rf "$GD"; mkdir -p "$GD"
  local fails="" tgt="10.77.2.2:$PORT" t0 t1
  cap_start b "$GD/cap-b.pcap" -i any -s 128
  # (а) неверный id (только A)
  srv_start "$GD/server.log" b "$SPK" --listen "$LISTEN"
  if [[ $V == a ]]; then
    cli "$GD/client-wrongid.log" a "$SPK" --connect "$tgt" --id "$(cat "$STATE/mitm_ep.id")" --pair 1 --mode ok --bytes 1024
    sleep 1
    evl "$GD/client-wrongid.log" client_result | grep -q 'hs_error' || fails+="a:no_hs_error "
    [[ "$(grep -c 'hs_done peer=10.77.1.2:' "$GD/server.log" || true)" == 0 ]] || fails+="a:server_hs_done "
  fi
  # (в) лимит: простой, затем флуд из chv-c + друг из chv-a
  t0="$(cpu_ticks "$SRV_PID")"; sleep 30; t1="$(cpu_ticks "$SRV_PID")"
  local cpu_idle=$((t1 - t0))
  bg_start "$GD/flood.pid" c sh -c 'exec env -i PATH="$PATH" RUST_LOG=warn "$@" >"$0" 2>"$0.err"' \
    "$GD/flood.log" "$SPK" flood --pairs "$STATE" --target "$tgt" --src 10.77.3.10,10.77.3.11,10.77.3.12 --rate 20 --duration 30
  local fl_real="$BG_REAL" fl_wrap="$BG_WRAP"
  t0="$(cpu_ticks "$SRV_PID")"
  sleep 5
  cli "$GD/friend.log" a "$SPK" --connect "$tgt" --pair 1 --mode ok --bytes 1024 --repeat 5
  sleep 26
  t1="$(cpu_ticks "$SRV_PID")"
  local cpu_flood=$((t1 - t0))
  { wait "$fl_wrap"; } 2>/dev/null || true
  sleep 1
  srv_stop
  # проверки
  local retry; retry="$(grep -c 'action=retry' "$GD/server.log" || true)"
  [[ "$retry" -gt 0 ]] || fails+="c:retry=0 "
  local ip maxwin
  : > "$GD/windows.txt"
  for ip in 10.77.3.10 10.77.3.11 10.77.3.12; do
    maxwin="$(grep "^EVENT hs_done " "$GD/server.log" | grep "peer=$ip:" | sed -n 's/^EVENT hs_done t=\([0-9]*\) .*/\1/p' \
      | awk '{t[NR]=$1} END{m=0; for(i=1;i<=NR;i++){c=0; for(j=i;j<=NR&&t[j]-t[i]<10000;j++)c++; if(c>m)m=c} print m+0}')"
    echo "ip=$ip hs_done_total=$(grep "^EVENT hs_done " "$GD/server.log" | grep -c "peer=$ip:" || true) max_in_10s_window=$maxwin" >> "$GD/windows.txt"
    [[ "$maxwin" -le 6 ]] || fails+="c:$ip:window=$maxwin "
  done
  local ok5 slow
  ok5="$(evl "$GD/friend.log" auth_ok | grep -c 'side=c' || true)"
  slow="$(evl "$GD/friend.log" auth_ok | sed -n 's/.* dur_ms=\([0-9]*\).*/\1/p' | awk '$1+0>2000{n++} END{print n+0}')"
  evl "$GD/friend.log" auth_ok > "$GD/friend-auth.txt"
  [[ "$ok5" == 5 ]] || fails+="c:friend_auth_ok=$ok5 "
  [[ "$slow" == 0 ]] || fails+="c:friend_slow=$slow "
  # CPU без лимита (отдельный сервер)
  srv_start "$GD/server-nolimit.log" b "$SPK" --listen "$LISTEN" --no-limit
  t0="$(cpu_ticks "$SRV_PID")"
  bg_start "$GD/flood2.pid" c sh -c 'exec env -i PATH="$PATH" RUST_LOG=warn "$@" >"$0" 2>"$0.err"' \
    "$GD/flood-nolimit.log" "$SPK" flood --pairs "$STATE" --target "$tgt" --src 10.77.3.10,10.77.3.11,10.77.3.12 --rate 20 --duration 30
  fl_wrap="$BG_WRAP"
  sleep 31
  t1="$(cpu_ticks "$SRV_PID")"
  local cpu_nolimit=$((t1 - t0))
  { wait "$fl_wrap"; } 2>/dev/null || true
  sleep 1
  local hs_nolimit; hs_nolimit="$(grep -c '^EVENT hs_done ' "$GD/server-nolimit.log" || true)"
  srv_stop
  {
    echo "CPU сервера (тики процесса utime+stime за 30 с, CLK_TCK=$CLK_TCK; 100 тиков = 100% одного ядра в секунду):"
    echo "idle: ticks=$cpu_idle -> $(awk -v t=$cpu_idle -v h=$CLK_TCK 'BEGIN{printf "%.2f%%", t/h/30*100}') одного ядра"
    echo "flood_with_limit: ticks=$cpu_flood -> $(awk -v t=$cpu_flood -v h=$CLK_TCK 'BEGIN{printf "%.2f%%", t/h/30*100}')"
    echo "flood_no_limit: ticks=$cpu_nolimit -> $(awk -v t=$cpu_nolimit -v h=$CLK_TCK 'BEGIN{printf "%.2f%%", t/h/30*100}') (hs_done=$hs_nolimit)"
    echo "retry_events_with_limit=$retry ignore_events=$(grep -c 'action=ignore' "$GD/server.log" || true)"
    echo "flood: $(evl "$GD/flood.log" flood_done)"
    echo "flood_nolimit: $(evl "$GD/flood-nolimit.log" flood_done)"
  } > "$GD/cpu.txt"
  {
    echo "== сервер с лимитом: события incoming по действиям и IP (полный server.log не коммитится, он большой) =="
    grep '^EVENT incoming ' "$GD/server.log" | sed -n 's/.* peer=\([0-9.]*\):[0-9]* validated=\([01]\) action=\([a-z]*\).*/\1 validated=\2 \3/p' | sort | uniq -c
    echo "== hs_done по IP =="
    grep '^EVENT hs_done ' "$GD/server.log" | sed -n 's/.* peer=\([0-9.]*\):.*/\1/p' | sort | uniq -c
    echo "== сервер без лимита: hs_done по IP =="
    grep '^EVENT hs_done ' "$GD/server-nolimit.log" | sed -n 's/.* peer=\([0-9.]*\):.*/\1/p' | sort | uniq -c
  } > "$GD/incoming-stats.txt"
  gate_end_simple
  if [[ -z "$fails" ]]; then
    verdict G3 PASS "$GD" "(а) неверный id: hs_error без hs_done; (в) retry=$retry, окно ≤6 на IP, друг 5/5 ≤2 с; CPU в $GD/cpu.txt"
  else
    verdict G3 FAIL "$GD" "сбои: $fails"
  fi
}

# ---------------------------------------------------------------- G12
g12() {
  ensure_ready
  GD="$LOGS/g12"; rm -rf "$GD"; mkdir -p "$GD"
  local tgt="10.77.2.2:$PORT"
  cap_start r "$GD/g12-$V.pcap" -i rb -s 0 udp
  srv_start "$GD/server.log" b "$SPK" --listen "$LISTEN"
  cli "$GD/c-1.log" a "$SPK" --connect "$tgt" --pair 1 --mode ok --bytes 4096
  cli "$GD/c-2.log" a "$SPK" --connect "$tgt" --pair 2 --mode ok --bytes 4096
  sleep 1
  srv_stop
  cap_stop
  cp "$STATE/needles.hex" "$GD/needles.txt"
  echo "uname_n str $(uname -n)" >> "$GD/needles.txt"
  nsx r env -i PATH="$PATH" "$OBS" --pcap "$GD/g12-$V.pcap" --needles "$GD/needles.txt" --alpn chervo-spike/1 --version 1 > "$GD/observe.txt" || true
  local res; res="$(grep '^RESULT ' "$GD/observe.txt" || true)"
  local sz; sz="$(stat -c %s "$GD/g12-$V.pcap")"
  echo "размер захвата: $sz байт" >> "$GD/observe.txt"
  case "$res" in
    "RESULT PASS"*) verdict G12 PASS "$GD/observe.txt" "${res#RESULT PASS }" ;;
    "RESULT FAIL"*) verdict G12 FAIL "$GD/observe.txt" "${res#RESULT FAIL }" ;;
    *) verdict G12 INCONCLUSIVE "$GD/observe.txt" "${res:-g12-observe не дал результата}" ;;
  esac
}

# ---------------------------------------------------------------- G1
g1_run() { # подкаталог бинарник allow_portmap
  local sub="$1" bin="$2" pm="$3" tgt="10.77.2.2:$PORT" i
  gate_begin "g1/$sub"
  srv_start "$GD/server.log" b "$bin" --listen "$LISTEN"
  bg_start "$GD/client.pid" a sh -c 'exec env -i PATH="$PATH" RUST_LOG=warn "$@" >"$0" 2>"$0.err"' \
    "$GD/client.log" "$bin" client --pairs "$STATE" --connect "$tgt" --pair 1 --mode ok --bytes 65536 --duration 60 --idle-s 30 --change-addr-at 30
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
  f="$(net_fail "$GD" "$pm" | tr '\n' ' ')"
  z="$(peer_zero "$GD" | tr '\n' ' ')"
  if ! evl "$GD/client.log" auth_ok | grep -q 'side=c'; then z+="client_no_auth_ok "; fi
  {
    echo "sub=$sub allow_portmap=$pm"
    for ns in a b r; do echo "-- nft $ns"; grep -E "counter|packets" "$GD/nft-$ns.txt" | paste - - | awk '{print $2 "=" $5}' | tr '\n' ' '; echo; done
    echo "-- analysis a"; cat "$GD/analysis-a.txt"
    echo "-- analysis b"; cat "$GD/analysis-b.txt"
    echo "-- client"; evl "$GD/client.log" app_ok; evl "$GD/client.log" after_idle; evl "$GD/client.log" app_error; evl "$GD/client.log" client_result
    echo "fails=[$f] inconclusive=[$z]"
  } > "$GD/result.txt"
  G1_FAILS+="$f"; G1_INC+="$z"
}

g1() {
  ensure_ready
  G1_FAILS=""; G1_INC=""
  rm -rf "$LOGS/g1"
  if [[ $V == a ]]; then
    g1_run nopm "$SPK" 0
    g1_run pm "$SPK_PM" 1
  else
    g1_run main "$SPK" 0
  fi
  if [[ -n "${G1_FAILS// /}" ]]; then verdict G1 FAIL "$LOGS/g1" "$G1_FAILS"
  elif [[ -n "${G1_INC// /}" ]]; then verdict G1 INCONCLUSIVE "$LOGS/g1" "$G1_INC"
  else verdict G1 PASS "$LOGS/g1" "dns=0 other=0 fwd_drop=0, кортежи вне списка пусты, peer>0; без порт-маппера portmap=0"
  fi
}

# ---------------------------------------------------------------- G2
g2() {
  ensure_ready
  gate_begin g2
  srv_start "$GD/server.log" b "$SPK" --listen "$LISTEN"
  local names=(lan4 routed4) addrs=("10.77.0.3:$PORT" "10.77.2.2:$PORT") i ok=0 total=0 skipped=""
  if [[ $HAVE6 == 1 ]]; then names+=(lan6 routed6); addrs+=("[fd77::3]:$PORT" "[fd77:2::2]:$PORT"); else skipped="lan6 routed6 (IPv6 в ядре выключен)"; fi
  local errs=""
  for i in "${!names[@]}"; do
    cli "$GD/c-${names[$i]}.log" a "$SPK" --connect "${addrs[$i]}" --pair 1 --mode ok --bytes 1048576
    total=$((total + 1))
    if evl "$GD/c-${names[$i]}.log" auth_ok | grep -q 'side=c' && evl "$GD/c-${names[$i]}.log" app_ok | grep -q 'echo_eq=1'; then ok=$((ok + 1)); fi
    if grep -qiE 'lookup|discover|relay|dns|resolve' "$GD/c-${names[$i]}.log"; then errs+="${names[$i]}:lookup/relay-строка "; fi
    sleep 0.5
  done
  srv_stop
  gate_end
  local f z; f="$(net_fail "$GD" 0 | tr '\n' ' ')"; z="$(peer_zero "$GD" | tr '\n' ' ')"
  {
    echo "ok=$ok из $total запущенных; пропущено: ${skipped:-нет}"
    for i in "${!names[@]}"; do echo "-- ${names[$i]}: $(evl "$GD/c-${names[$i]}.log" app_ok) $(evl "$GD/c-${names[$i]}.log" client_result)"; done
    for ns in a b r; do echo "-- nft $ns"; grep -E "counter|packets" "$GD/nft-$ns.txt" | paste - - | awk '{print $2 "=" $5}' | tr '\n' ' '; echo; done
    echo "net_fail=[$f] peer_zero=[$z] lookup_errs=[$errs]"
  } > "$GD/result.txt"
  if [[ "$ok" != "$total" || -n "${f// /}" || -n "$errs" ]]; then
    verdict G2 FAIL "$GD" "ok=$ok/$total net_fail=[$f] lookup=[$errs]"
  elif [[ -n "${z// /}" ]]; then
    verdict G2 INCONCLUSIVE "$GD" "peer=0: $z"
  elif [[ -n "$skipped" ]]; then
    verdict G2 INCONCLUSIVE "$GD" "IPv4: $ok/$total ok, счётчики чисты; IPv6-соединения (2 из 4) не запускались: IPv6 в ядре стенда выключен (ipv6.disable=1)"
  else
    verdict G2 PASS "$GD" "4/4 auth_ok и echo_eq=1, счётчики чисты"
  fi
}

# ---------------------------------------------------------------- G9 (только B), all, decide
g9() { log "G9 (вариант B) реализуется в части 2 этапа 7"; return 2; }

do_all() {
  trap do_teardown EXIT
  do_build
  do_setup
  mkdirs; : > "$SUMMARY"
  mkdir -p "$STATE"
  spk_in a "$SPK" keygen --dir "$STATE" > /dev/null
  if [[ $V == a ]]; then
    g11; g1; g2; g3; g10; g12
  else
    log "вариант B реализуется в части 2 этапа 7"; return 2
  fi
}

do_decide() {
  local sa="$ROOT/logs/a/summary.txt" sb="$ROOT/logs/b/summary.txt"
  [[ -s "$sa" ]] || { echo "нет $sa: сначала run.sh all a" >&2; exit 2; }
  local need_a="G1 G2 G3 G10 G11 G12" g
  for g in $need_a; do grep -q "^$g " "$sa" || { echo "в $sa нет $g" >&2; exit 2; }; done
  local fa ia
  fa="$(grep -cE '^G[0-9]+ FAIL ' "$sa" || true)"; ia="$(grep -cE '^G[0-9]+ INCONCLUSIVE ' "$sa" || true)"
  if [[ "$fa" == 0 && "$ia" == 0 ]]; then echo "DECISION A"; return 0; fi
  if [[ "$fa" == 0 ]]; then
    echo "INCONCLUSIVE у A: $(grep -E '^G[0-9]+ INCONCLUSIVE ' "$sa" | cut -d' ' -f1 | tr '\n' ' ')- не переход на B, стоп и доклад"
    echo "DECISION STOP"; return 0
  fi
  echo "у A есть FAIL: $(grep -E '^G[0-9]+ FAIL ' "$sa" | cut -d' ' -f1 | tr '\n' ' ')"
  if [[ ! -s "$sb" ]]; then
    echo "прогон B не выполнен (часть 2 этапа 7): запустите run.sh all b" >&2
    echo "DECISION B-PENDING"; return 0
  fi
  local fb ib
  fb="$(grep -cE '^G[0-9]+ (FAIL|INCONCLUSIVE) ' "$sb" || true)"
  for g in G1 G2 G3 G9 G10 G12; do grep -q "^$g " "$sb" || { echo "в $sb нет $g" >&2; echo "DECISION STOP"; return 0; }; done
  if [[ "$fb" == 0 ]]; then echo "DECISION B"; else echo "DECISION STOP"; fi
}

# ---------------------------------------------------------------- запуск
main() {
  case "$CMD" in
    setup) do_setup ;;
    teardown) do_teardown ;;
    build) do_build ;;
    g1) g1 ;; g2) g2 ;; g3) g3 ;; g9) g9 ;; g10) g10 ;; g11) g11 ;; g12) g12 ;;
    all) do_all ;;
    decide) do_decide ;;
    *) echo "использование: run.sh <setup|teardown|g1|g2|g3|g9|g10|g11|g12|all|decide> <a|b>" >&2; exit 2 ;;
  esac
}
main
