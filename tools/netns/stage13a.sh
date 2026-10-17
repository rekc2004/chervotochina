#!/usr/bin/env bash
# Стенд netns этапа 13а (часть U4): собственный клиент UPnP IGD (chervo-upnp, пример upnp_probe) против
# настоящего miniupnpd в пространствах имён Linux.
# Использование:
#   sudo bash tools/netns/stage13a.sh <map|renew|release|kill|restart|cgnat|doublenat|ambiguous|spoof|all|teardown>
# Требуется Linux, root, ip, nft, miniupnpd (пакет miniupnpd-nftables), cargo (сборка идёт вне ns), python3 (строка spoof),
# curl (необязательно: точное значение аренды через GetSpecificPortMappingEntry; без него берётся lease_file).
# Переменные: CHV_LOGS=/путь (по умолчанию tools/netns/logs13a), CORE=11.0.0 (адресное пространство «интернета» стенда;
# miniupnpd отказывается работать с «зарезервированным» внешним адресом, поэтому не документационный префикс),
# CHV_PROBE, CHV_PROBE_SHORT (готовые бинарники upnp_probe: обычный и с арендой 60 с; иначе собираются),
# CHV_KEEP=1 (не сносить стенд при выходе).
#
# НЕ ЗАПУСКАЛСЯ. Написан на Windows-машине, проверен только `bash -n`. Ожидания строк ниже взяты из спецификации
# docs/specs/stage-13a-upnp.md и памяти о miniupnpd 2.3.x ([D]: имена опций и текст журнала не сверены с исходником).
#
# Свои пространства имён: префикс chv13a- (стенды chv13-, chv8-, chv9- не затрагиваются). Все nft и sysctl
# выполняются только через `ip netns exec`; на хосте не меняется ничего, кроме создания и удаления своих ns и
# каталога /etc/netns/chv13a-* (файл resolv.conf-заглушка).
#
# Топология (CORE=11.0.0):
#   i : ядро «интернета» (мост core0, 11.0.0.254, маршрутизирует)
#   w : белый хост 11.0.0.50 (+ 192.168.77.5/32 на lo: «дальний IGD» строки spoof, на два перехода от клиента)
#   r : домашний роутер: wan 11.0.0.10 (в ядре), мост lan 192.168.10.1 (h и x), NAT и miniupnpd
#   o : внешний NAT для строки doublenat (r.wan подключается к o.lan 192.168.100.0/24, o.wan 11.0.0.20 в ядре)
#   h : клиент 192.168.10.2 (upnp_probe), x : второй хост LAN 192.168.10.3 (двойник роутера или подделыватель SSDP)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
PFX="chv13a-"
STATE="${CHV_STATE:-/tmp/chervo-stage13a-state}"
LOGS="${CHV_LOGS:-$ROOT/logs13a}"
BIN="$STATE/bin"
PROBE="${CHV_PROBE:-$BIN/upnp_probe}"
PROBE_SHORT="${CHV_PROBE_SHORT:-$BIN/upnp_probe_short}"
CORE="${CORE:-11.0.0}"
PORT=40123
UUID="81c5ab36-606c-44f1-a3b0-5814b1dd7a01"
UDN="uuid:$UUID"
SUMMARY="$LOGS/summary13a.txt"
CMD="${1:-}"
NSL=(i w r o h x)
RD=""
declare -A MPD_REAL=() MPD_WRAP=()
BG_REAL=""; BG_WRAP=""
PB_REAL=""; PB_WRAP=""

log() { echo "[stage13a.sh] $*" >&2; }
nsx() { local ns="$1"; shift; ip netns exec "$PFX$ns" "$@"; }
ipn() { local ns="$1"; shift; ip -n "$PFX$ns" "$@"; }
mkdirs() { mkdir -p "$LOGS"; }

# ---------------------------------------------------------------- сборка
do_build() {
  mkdir -p "$BIN"
  if [[ -z "${CHV_PROBE:-}" ]]; then
    log "cargo build upnp_probe (вне ns)"
    ( cd "$REPO" && cargo build --release --locked -p chervo-upnp --example upnp_probe ) >&2
    cp "$REPO/target/release/examples/upnp_probe" "$PROBE"
  fi
  if [[ -z "${CHV_PROBE_SHORT:-}" ]]; then
    # тестовая сборка: аренда 60 с, нижняя граница продления 10 с (продление на 30 с). Правится копия исходников.
    local src="$STATE/short-src"
    log "cargo build upnp_probe с арендой 60 с (копия в $src)"
    rm -rf "$src"; mkdir -p "$src"
    cp -r "$REPO/crates" "$REPO/Cargo.toml" "$REPO/Cargo.lock" "$REPO/rust-toolchain.toml" "$src/"
    sed -i \
      -e 's/^pub(crate) const LEASE_SECS: u32 = 3600;/pub(crate) const LEASE_SECS: u32 = 60;/' \
      -e 's/^pub(crate) const MIN_RENEW: Duration = Duration::from_secs(60);/pub(crate) const MIN_RENEW: Duration = Duration::from_secs(10);/' \
      "$src/crates/chervo-upnp/src/limits.rs"
    grep -q 'LEASE_SECS: u32 = 60;' "$src/crates/chervo-upnp/src/limits.rs" \
      && grep -q 'MIN_RENEW: Duration = Duration::from_secs(10);' "$src/crates/chervo-upnp/src/limits.rs" \
      || { echo "не удалось подменить константы в limits.rs" >&2; return 1; }
    ( cd "$src" && CARGO_TARGET_DIR="$STATE/short-target" cargo build --release --locked -p chervo-upnp --example upnp_probe ) >&2
    cp "$STATE/short-target/release/examples/upnp_probe" "$PROBE_SHORT"
  fi
}

# ---------------------------------------------------------------- стенд
ns_exists() { ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$PFX$1"; }

do_teardown() {
  set +e
  local n
  for n in "${NSL[@]}"; do
    if ns_exists "$n"; then
      ip netns pids "$PFX$n" 2>/dev/null | xargs -r kill 2>/dev/null
    fi
  done
  sleep 0.5
  for n in "${NSL[@]}"; do
    ns_exists "$n" && ip netns del "$PFX$n" 2>/dev/null
    rm -rf "/etc/netns/${PFX}${n}"
  done
  rmdir /etc/netns 2>/dev/null
  set -e
}

vl() { # ns1 if1 ns2 if2
  ip link add "$2" netns "$PFX$1" type veth peer name "$4" netns "$PFX$3"
}

# NAT и межсетевой экран роутера r. Цепочки miniupnpd создаются заранее (miniupnpd вызывается через jump), как в
# stage 8. Имя цепочки forward не fwd (ключевое слово nft); каждая однострочная цепочка заканчивается `;` перед `}`.
nat_load_r() {
  nsx r nft flush ruleset
  nsx r nft -f - <<NFT
table inet nat13a {
  chain pre {
    type nat hook prerouting priority dstnat;
    jump prerouting_miniupnpd
  }
  chain post {
    type nat hook postrouting priority srcnat;
    jump postrouting_miniupnpd
    oifname "wan" ip saddr 192.168.10.0/24 masquerade
  }
  chain fwd13a {
    type filter hook forward priority filter; policy drop;
    jump miniupnpd
    iifname "lan" oifname "wan" accept
    iifname "wan" ct state established,related accept
    iifname "wan" ct status dnat accept
  }
  chain inp13a {
    type filter hook input priority filter;
    iifname "wan" drop
  }
  chain miniupnpd { }
  chain prerouting_miniupnpd { }
  chain postrouting_miniupnpd { }
}
NFT
}

# Внешний NAT o (строка doublenat): без UPnP, обычный masquerade.
nat_load_o() {
  nsx o nft flush ruleset
  nsx o nft -f - <<NFT
table inet nato13a {
  chain post {
    type nat hook postrouting priority srcnat;
    oifname "wan" ip saddr 192.168.100.0/24 masquerade
  }
  chain fwdo13a {
    type filter hook forward priority filter; policy drop;
    iifname "lan" oifname "wan" accept
    iifname "wan" ct state established,related accept
  }
}
NFT
}

# Пустые цепочки miniupnpd для «двойника роутера» на x (его nft-бэкенд ждёт готовую таблицу).
nat_load_x() {
  nsx x nft flush ruleset
  nsx x nft -f - <<NFT
table inet nat13a {
  chain pre {
    type nat hook prerouting priority dstnat;
    jump prerouting_miniupnpd
  }
  chain post {
    type nat hook postrouting priority srcnat;
    jump postrouting_miniupnpd
  }
  chain fwd13a {
    type filter hook forward priority filter; policy accept;
    jump miniupnpd
  }
  chain miniupnpd { }
  chain prerouting_miniupnpd { }
  chain postrouting_miniupnpd { }
}
NFT
}

# Режимы: plain (r.wan = $CORE.10 в ядре), cgnat (r.wan = 100.64.0.2/10), double (r.wan = 192.168.100.2 за NAT o).
do_setup() { # режим
  local mode="$1" n p ifs
  do_teardown
  log "setup netns, режим $mode"
  for n in "${NSL[@]}"; do
    ip netns add "$PFX$n"
    ipn "$n" link set lo up
  done
  ipn i link add core0 type bridge
  vl w wan i p-w; ipn i link set p-w master core0
  ipn w addr add "$CORE.50/24" dev wan
  ipn w addr add 192.168.77.5/32 dev lo
  ipn i addr add "$CORE.254/24" dev core0
  case "$mode" in
    plain|cgnat)
      vl r wan i p-r; ipn i link set p-r master core0
      if [[ "$mode" == plain ]]; then ipn r addr add "$CORE.10/24" dev wan
      else ipn r addr add 100.64.0.2/10 dev wan
      fi
      ;;
    double)
      vl o wan i p-o; ipn i link set p-o master core0
      ipn o addr add "$CORE.20/24" dev wan
      vl o lan r wan
      ipn o addr add 192.168.100.1/24 dev lan
      ipn r addr add 192.168.100.2/24 dev wan
      ;;
    *) echo "режим: $mode" >&2; return 1 ;;
  esac
  # LAN роутера: мост lan (h и x), без IGMP-snooping, чтобы M-SEARCH доходил до всех
  ipn r link add lan type bridge mcast_snooping 0
  vl r lh h eth0; ipn r link set lh master lan
  vl r lx x eth0; ipn r link set lx master lan
  ipn r addr add 192.168.10.1/24 dev lan
  ipn h addr add 192.168.10.2/24 dev eth0
  ipn x addr add 192.168.10.3/24 dev eth0
  for n in "${NSL[@]}"; do
    ifs="$(ipn "$n" -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$' || true)"
    for p in $ifs; do ipn "$n" link set "$p" up; done
  done
  ipn h route add default via 192.168.10.1
  ipn x route add default via 192.168.10.1
  ipn w route add default via "$CORE.254"
  ipn i route add 192.168.77.5/32 via "$CORE.50"
  case "$mode" in
    plain) ipn r route add default via "$CORE.254" ;;
    double) ipn r route add default via 192.168.100.1; ipn o route add default via "$CORE.254" ;;
    *) ;;
  esac
  for n in i r o; do nsx "$n" sysctl -qw net.ipv4.ip_forward=1; done
  # DNS-заглушка на клиенте: любой запрос к резолверу виден счётчиком dns
  mkdir -p "/etc/netns/${PFX}h"
  echo "nameserver 192.0.2.53" > "/etc/netns/${PFX}h/resolv.conf"
  nat_load_r
  nat_load_o
  nat_load_x
  log "стенд готов"
}

# ---------------------------------------------------------------- счётчики
cnt() { # файл-счётчиков имя
  awk -v n="$2" '$1 == "counter" && $2 == n { f = 1 } f && $1 == "packets" { print $2; exit }' "$1"
}

# Счётчики исходящего трафика клиента h: SSDP-группа и порт роутера отдельно от всего прочего, плюс входящие на PORT.
nft_guard_h() {
  local P6="" ND6="" M6=""
  # IPv6 в ядре может быть выключен: тогда правила IPv6 не загружаются (как в stage13.sh)
  if [[ -e /proc/net/if_inet6 ]]; then
    P6='ip6 daddr 2001:db8::1 counter name "probe"'
    ND6='icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } counter name "nd" accept'
    M6='icmpv6 type mld2-listener-report counter name "mcast_kernel" accept'
  fi
  nsx h nft flush ruleset 2>/dev/null || true
  nsx h nft -f - <<NFT
table inet chv13a_h {
  counter dns { }
  counter probe { }
  counter ssdp { }
  counter router { }
  counter nd { }
  counter mcast_kernel { }
  counter other { }
  counter inbound { }
  chain output {
    type filter hook output priority 0; policy accept;
    th dport { 53, 853 } counter name "dns"
    oifname "lo" accept
    ip daddr 192.0.2.1 counter name "probe"
    $P6
    ip daddr 239.255.255.250 udp dport 1900 counter name "ssdp" accept
    ip daddr 192.168.10.1 tcp dport 5000 counter name "router" accept
    ip protocol igmp counter name "mcast_kernel" accept
    $ND6
    $M6
    counter name "other" accept
  }
  chain input {
    type filter hook input priority 0; policy accept;
    udp dport $PORT counter name "inbound"
  }
}
NFT
}

h_counter() { # имя
  nsx h nft list counters > "$RD/nft-h.txt"
  cnt "$RD/nft-h.txt" "$1"
}

# Итог счётчиков клиента: пусто, если dns = probe = other = 0 и ssdp > 0 и router > 0.
guard_fail_h() {
  local v out=""
  nsx h nft list counters > "$RD/nft-h.txt"
  for v in dns probe other; do
    [[ "$(cnt "$RD/nft-h.txt" "$v")" == 0 ]] || out+="$v=$(cnt "$RD/nft-h.txt" "$v") "
  done
  [[ "$(cnt "$RD/nft-h.txt" ssdp)" -gt 0 ]] || out+="ssdp=0 "
  [[ "$(cnt "$RD/nft-h.txt" router)" -gt 0 ]] || out+="router=0 "
  echo "$out"
}

# ---------------------------------------------------------------- процессы
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

# miniupnpd (nft-бэкенд) в ns; конфиг вне /etc
mpd_conf() { # файл ext_if lan-ip/маска lan-подсеть lease_file разрешить_частный(yes|no)
  cat > "$1" <<CONF
ext_ifname=$2
listening_ip=$3
http_port=5000
uuid=$UUID
enable_upnp=yes
secure_mode=yes
system_uptime=yes
upnp_table_name=nat13a
upnp_nat_table_name=nat13a
lease_file=$5
ext_allow_private_ipv4=$6
allow 1024-65535 $4 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
CONF
}

mpd_start() { # ключ ns конфиг журнал
  local key="$1" ns="$2" conf="$3" lg="$4" i
  bg_start "$lg.pid" "$ns" sh -c 'exec miniupnpd -d -f "$1" -P "$2" >"$3" 2>&1' sh "$conf" "$lg.mpid" "$lg"
  MPD_REAL[$key]="$BG_REAL"; MPD_WRAP[$key]="$BG_WRAP"
  for i in $(seq 1 50); do
    grep -qiE 'HTTP listening on port|listening' "$lg" 2>/dev/null && break
    kill -0 "${MPD_REAL[$key]}" 2>/dev/null || break
    sleep 0.1
  done
  sleep 0.5
}
mpd_alive() { [[ -n "${MPD_REAL[$1]:-}" ]] && kill -0 "${MPD_REAL[$1]}" 2>/dev/null; }
mpd_stop() {
  bg_stop "${MPD_REAL[$1]:-}" "${MPD_WRAP[$1]:-}"
  unset "MPD_REAL[$1]" "MPD_WRAP[$1]"
}

# Долгоживущий upnp_probe map: stdin из FIFO (Enter = закрыть проброс и выйти). Одновременно не более одного.
probe_bg() { # бинарник метка [аргументы...]
  local bin="$1" label="$2"; shift 2
  local pf="$RD/$label.pid" in="$RD/$label.in" i
  rm -f "$pf" "$in"; mkfifo "$in"
  nsx h sh -c 'echo $$ > "$1"; shift; exec env -i PATH="$PATH" "$@"' sh "$pf" "$bin" "$@" \
    < "$in" > "$RD/$label.log" 2> "$RD/$label.err" &
  PB_WRAP=$!
  exec 7> "$in"
  for i in $(seq 1 50); do [[ -s "$pf" ]] && break; sleep 0.05; done
  PB_REAL="$(cat "$pf" 2>/dev/null || true)"
}
probe_enter() { # Enter в stdin: закрыть проброс и выйти
  echo >&7 || true
  exec 7>&-
  { wait "$PB_WRAP"; } 2>/dev/null || true
  PB_REAL=""; PB_WRAP=""
}
probe_kill9() {
  [[ -n "$PB_REAL" ]] && kill -9 "$PB_REAL" 2>/dev/null || true
  { wait "$PB_WRAP"; } 2>/dev/null || true
  exec 7>&- || true
  PB_REAL=""; PB_WRAP=""
}

# Разовый запуск (identify | release PORT UDN): вывод в файл, не дольше 60 с.
probe_once() { # бинарник метка аргументы...
  local bin="$1" label="$2"; shift 2
  nsx h env -i PATH="$PATH" timeout 60 "$bin" "$@" < /dev/null > "$RD/$label.log" 2> "$RD/$label.err" || true
}

wait_grep() { # файл regex секунды
  local i
  for i in $(seq 1 "$(( $3 * 5 ))"); do
    grep -Eq "$2" "$1" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

# Первая строка статуса из вывода upnp_probe (Debug варианта MapStatus до двоеточия).
probe_status() { # файл
  sed -nE 's/^(Mapped|MappedPermanent|Off|NotHomeNetwork|NoGateway|Ambiguous|WanUnknown|BehindCgnat|DoubleNat|NeedPermanentConsent|Refused\([0-9]+\)|Failed): .*/\1/p' "$1" 2>/dev/null | head -n 1
}

# Запись проброса в таблице роутера r (правило dnat на PORT)
entry_present() {
  nsx r nft list table inet nat13a 2>/dev/null | grep -Eq "udp dport $PORT .*dnat"
}

# Остаток аренды, секунды: сначала GetSpecificPortMappingEntry через curl с хоста x, иначе lease_file роутера.
entry_lease() {
  local out="" v=""
  if command -v curl >/dev/null 2>&1; then
    out="$(nsx x curl -s -m 5 \
      -H 'Content-Type: text/xml; charset="utf-8"' \
      -H 'SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#GetSpecificPortMappingEntry"' \
      --data "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:GetSpecificPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewRemoteHost></NewRemoteHost><NewExternalPort>$PORT</NewExternalPort><NewProtocol>UDP</NewProtocol></u:GetSpecificPortMappingEntry></s:Body></s:Envelope>" \
      "http://192.168.10.1:5000/ctl/IPConn" 2>/dev/null || true)"
    v="$(sed -n 's/.*<NewLeaseDuration>\([0-9]*\)<.*/\1/p' <<< "$out" | head -n 1)"
  fi
  if [[ -z "$v" && -f "$RD/leases" ]]; then
    # формат lease_file miniupnpd [D]: ПРОТОКОЛ:внешний порт:внутренний адрес:порт:срок_unix:описание
    v="$(awk -F: -v p="$PORT" -v now="$(date +%s)" '$1 == "UDP" && $2 == p && $5 > 0 { print $5 - now; exit }' "$RD/leases")"
  fi
  echo "$v"
}

# w шлёт один UDP-пакет на внешний адрес роутера; true, если он дошёл до h (счётчик inbound вырос)
reach_from_w() {
  local before after
  before="$(h_counter inbound)"
  nsx w bash -c "echo x > /dev/udp/$CORE.10/$PORT" 2>/dev/null || true
  sleep 1
  after="$(h_counter inbound)"
  [[ "$after" -gt "$before" ]]
}

row_begin() { # имя режим
  mkdirs
  RD="$LOGS/$1"; rm -rf "$RD"; mkdir -p "$RD"
  mkdir -p "$STATE"
  [[ -x "$PROBE" && -x "$PROBE_SHORT" ]] || do_build
  do_setup "$2"
}

row_end() {
  local k
  [[ -n "$PB_REAL" ]] && probe_kill9
  for k in "${!MPD_REAL[@]}"; do mpd_stop "$k"; done
}

verdict() { # СТРОКА PASS|FAIL|INCONCLUSIVE|NOTRUN причина
  mkdirs; touch "$SUMMARY"
  grep -v "^$1 " "$SUMMARY" > "$SUMMARY.tmp" || true
  mv "$SUMMARY.tmp" "$SUMMARY"
  echo "$1 $2 ${RD#"$ROOT"/} $3" >> "$SUMMARY"
  log "$1 $2: $3"
}

# Запуск miniupnpd на роутере r; 0 — живой.
start_router_mpd() { # режим_частный(yes|no)
  mpd_conf "$RD/miniupnpd.conf" wan 192.168.10.1/24 192.168.10.0/24 "$RD/leases" "$1"
  mpd_start r r "$RD/miniupnpd.conf" "$RD/miniupnpd.log"
  mpd_alive r
}

# ---------------------------------------------------------------- строки
# MAP + TRAFFIC: identify выдаёт UDN; map открывает порт; запись видна; белый хост достаёт клиента; аренда <= 3600;
# release закрывает; клиент говорит только с 239.255.255.250:1900 и портом роутера (dns, probe, other = 0)
row_map() {
  row_begin map plain
  local f="" t="" lease="" idl=""
  if ! start_router_mpd no; then
    verdict MAP INCONCLUSIVE "miniupnpd не запустился: $(tr '\n' ' ' < "$RD/miniupnpd.log" | cut -c1-200)"
    verdict TRAFFIC INCONCLUSIVE "miniupnpd не запустился"; row_end; return
  fi
  nft_guard_h
  probe_once "$PROBE" identify identify
  idl="$(head -n 1 "$RD/identify.log" 2>/dev/null || true)"
  [[ "$idl" == "$UDN" ]] || f+="identify_udn($idl) "
  probe_bg "$PROBE" map map "$PORT" "$UDN"
  wait_grep "$RD/map.log" '^Mapped: ' 40 || f+="no_Mapped($(probe_status "$RD/map.log")) "
  grep -q "проброс: Some($CORE.10:$PORT)" "$RD/map.log" || f+="no_mapping_line_wan_$CORE.10 "
  entry_present || f+="entry_absent "
  reach_from_w || f+="no_inbound_from_w "
  lease="$(entry_lease)"
  if [[ -z "$lease" ]]; then f+="lease_unknown "
  elif (( lease <= 0 || lease > 3600 )); then f+="lease_$lease "
  fi
  probe_enter
  grep -q 'проброс закрыт' "$RD/map.log" || f+="no_release_line "
  entry_present && f+="entry_left_after_release "
  t="$(guard_fail_h)"
  row_end
  if [[ -n "${f// /}" ]]; then verdict MAP FAIL "$f"
  else verdict MAP PASS "identify=$UDN; Mapped, запись видна, белый хост достаёт клиента, аренда ${lease}s <= 3600, после Enter запись снята"
  fi
  if [[ -n "${t// /}" ]]; then verdict TRAFFIC FAIL "$t"
  else verdict TRAFFIC PASS "клиент: ssdp и порт роутера, dns = probe = other = 0 (identify, map, продление, release)"
  fi
}

# RENEW: сборка с арендой 60 с и продлением на 30 с; запись жива на 90-й секунде, upnp_probe печатает «через 30 с»
row_renew() {
  row_begin renew plain
  local f="" n="" t0 t
  if ! start_router_mpd no; then
    verdict RENEW INCONCLUSIVE "miniupnpd не запустился"; row_end; return
  fi
  t0="$(date +%s)"
  probe_bg "$PROBE_SHORT" map map "$PORT" "$UDN"
  wait_grep "$RD/map.log" '^Mapped: ' 40 || f+="no_Mapped "
  grep -q 'следующая проверка через 30 с' "$RD/map.log" || f+="renew_not_at_half(30s) "
  while t="$(date +%s)"; (( t - t0 < 90 )); do sleep 1; done
  entry_present || f+="entry_absent_at_90s "
  n="$(grep -c '^Mapped: ' "$RD/map.log" || true)"
  (( n >= 3 )) || f+="mapped_lines_$n(<3) "
  probe_enter
  row_end
  if [[ -n "${f// /}" ]]; then verdict RENEW FAIL "$f"
  else verdict RENEW PASS "аренда 60 с: продление каждые 30 с, запись жива на 90-й секунде, строк Mapped: $n"
  fi
}

# RELEASE: после Enter запись снята, входящий пакет с w не доходит
row_release() {
  row_begin release plain
  local f=""
  if ! start_router_mpd no; then
    verdict RELEASE INCONCLUSIVE "miniupnpd не запустился"; row_end; return
  fi
  nft_guard_h
  probe_bg "$PROBE" map map "$PORT" "$UDN"
  wait_grep "$RD/map.log" '^Mapped: ' 40 || f+="no_Mapped "
  entry_present || f+="entry_absent_before "
  reach_from_w || f+="no_inbound_before "
  probe_enter
  entry_present && f+="entry_present_after_release "
  reach_from_w && f+="inbound_after_release "
  row_end
  if [[ -n "${f// /}" ]]; then verdict RELEASE FAIL "$f"
  else verdict RELEASE PASS "после release запись снята и входящий пакет с w не доходит до клиента"
  fi
}

# KILL: kill -9 клиента (аренда 60 с): запись остаётся, исчезает по сроку аренды
row_kill() {
  row_begin kill plain
  local f="" t0 t gone=""
  if ! start_router_mpd no; then
    verdict KILL INCONCLUSIVE "miniupnpd не запустился"; row_end; return
  fi
  probe_bg "$PROBE_SHORT" map map "$PORT" "$UDN"
  wait_grep "$RD/map.log" '^Mapped: ' 40 || f+="no_Mapped "
  t0="$(date +%s)"
  sleep 5
  probe_kill9
  sleep 3
  entry_present || f+="entry_gone_right_after_kill9 "
  while t="$(date +%s)"; (( t - t0 < 120 )); do
    if ! entry_present; then gone="$(( t - t0 ))"; break; fi
    sleep 2
  done
  [[ -n "$gone" ]] || f+="entry_still_present_at_120s "
  row_end
  if [[ -n "${f// /}" ]]; then verdict KILL FAIL "$f"
  else verdict KILL PASS "после kill -9 запись осталась, исчезла по аренде через ${gone} с от старта (ожидалось около 60)"
  fi
}

# RESTART: после kill -9 запись осталась; новый запуск сначала удаляет свою старую запись, затем добавляет
row_restart() {
  row_begin restart plain
  local f="" off=0 seq_
  if ! start_router_mpd no; then
    verdict RESTART INCONCLUSIVE "miniupnpd не запустился"; row_end; return
  fi
  probe_bg "$PROBE" map map1 "$PORT" "$UDN"
  wait_grep "$RD/map1.log" '^Mapped: ' 40 || f+="run1_no_Mapped "
  probe_kill9
  entry_present || f+="entry_gone_after_kill9 "
  off="$(wc -l < "$RD/miniupnpd.log")"
  probe_bg "$PROBE" map map2 "$PORT" "$UDN"
  wait_grep "$RD/map2.log" '^Mapped: ' 40 || f+="run2_no_Mapped "
  entry_present || f+="entry_absent_after_restart "
  # порядок обращений ко второму запуску по журналу miniupnpd [D]: DeletePortMapping раньше AddPortMapping
  seq_="$(tail -n +"$((off + 1))" "$RD/miniupnpd.log" | grep -oE 'DeletePortMapping|AddPortMapping' | uniq | tr '\n' ' ')"
  case "$seq_" in
    "DeletePortMapping AddPortMapping "*) ;;
    *) f+="log_order_not_delete_then_add($seq_) " ;;
  esac
  probe_enter
  row_end
  if [[ -n "${f// /}" ]]; then verdict RESTART FAIL "$f"
  else verdict RESTART PASS "второй запуск: старая запись удалена, затем добавлена (журнал: $seq_)"
  fi
}

# CGNAT: WAN роутера 100.64.0.2/10. Ожидание спецификации: BehindCgnat, AddPortMapping у miniupnpd нет.
# Но miniupnpd 2.3.4 при WAN в 100.64/10 отдаёт ПУСТОЙ внешний адрес (SPIKE_TRANSPORT 9.3), а клиент по решению 8
# спецификации сообщает на пустой адрес WanUnknown; BehindCgnat возможен только если ext_allow_private_ipv4=yes
# заставляет miniupnpd назвать настоящий адрес [D]. Поэтому WanUnknown здесь не PASS, а INCONCLUSIVE с пояснением.
row_cgnat() {
  row_begin cgnat cgnat
  local f="" st=""
  if ! start_router_mpd yes; then
    verdict CGNAT INCONCLUSIVE "miniupnpd не запустился: $(tr '\n' ' ' < "$RD/miniupnpd.log" | cut -c1-200)"; row_end; return
  fi
  probe_once "$PROBE" release release "$PORT" "$UDN"
  st="$(probe_status "$RD/release.log")"
  grep -q 'AddPortMapping' "$RD/miniupnpd.log" && f+="AddPortMapping_in_log "
  entry_present && f+="entry_present "
  row_end
  if [[ -n "${f// /}" ]]; then verdict CGNAT FAIL "status=$st; $f"
  elif [[ "$st" == BehindCgnat ]]; then verdict CGNAT PASS "status=BehindCgnat, AddPortMapping у miniupnpd не было"
  elif [[ "$st" == WanUnknown ]]; then verdict CGNAT INCONCLUSIVE "status=WanUnknown: miniupnpd не назвал адрес 100.64.0.2 (см. комментарий строки); Add не было"
  else verdict CGNAT FAIL "status=${st:-нет}"
  fi
}

# DOUBLENAT: miniupnpd за другим NAT (WAN 192.168.100.2): DoubleNat, Add нет (оговорка как у CGNAT про пустой адрес)
row_doublenat() {
  row_begin doublenat double
  local f="" st=""
  if ! start_router_mpd yes; then
    verdict DOUBLENAT INCONCLUSIVE "miniupnpd не запустился: $(tr '\n' ' ' < "$RD/miniupnpd.log" | cut -c1-200)"; row_end; return
  fi
  probe_once "$PROBE" release release "$PORT" "$UDN"
  st="$(probe_status "$RD/release.log")"
  grep -q 'AddPortMapping' "$RD/miniupnpd.log" && f+="AddPortMapping_in_log "
  entry_present && f+="entry_present "
  row_end
  if [[ -n "${f// /}" ]]; then verdict DOUBLENAT FAIL "status=$st; $f"
  elif [[ "$st" == DoubleNat ]]; then verdict DOUBLENAT PASS "status=DoubleNat, AddPortMapping у miniupnpd не было"
  elif [[ "$st" == WanUnknown ]]; then verdict DOUBLENAT INCONCLUSIVE "status=WanUnknown: miniupnpd не назвал частный внешний адрес (см. комментарий строки CGNAT); Add не было"
  else verdict DOUBLENAT FAIL "status=${st:-нет}"
  fi
}

# AMBIGUOUS: второй хост LAN (x) отвечает как IGD с тем же UDN: два кандидата, порт не открывается
row_ambiguous() {
  row_begin ambiguous plain
  local f="" st=""
  if ! start_router_mpd no; then
    verdict AMBIGUOUS INCONCLUSIVE "miniupnpd на r не запустился"; row_end; return
  fi
  mpd_conf "$RD/miniupnpd-x.conf" eth0 192.168.10.3/24 192.168.10.0/24 "$RD/leases-x" yes
  mpd_start x x "$RD/miniupnpd-x.conf" "$RD/miniupnpd-x.log"
  if ! mpd_alive x; then
    verdict AMBIGUOUS INCONCLUSIVE "miniupnpd на x не запустился: $(tr '\n' ' ' < "$RD/miniupnpd-x.log" | cut -c1-200)"; row_end; return
  fi
  probe_once "$PROBE" release release "$PORT" "$UDN"
  st="$(probe_status "$RD/release.log")"
  [[ "$st" == Ambiguous ]] || f+="status_${st:-нет}(ожидалось_Ambiguous) "
  grep -q 'AddPortMapping' "$RD/miniupnpd.log" && f+="AddPortMapping_on_r "
  grep -q 'AddPortMapping' "$RD/miniupnpd-x.log" && f+="AddPortMapping_on_x "
  entry_present && f+="entry_present "
  row_end
  if [[ -n "${f// /}" ]]; then verdict AMBIGUOUS FAIL "$f"
  else verdict AMBIGUOUS PASS "два ответчика с одним UDN: Ambiguous, SOAP-запросов на добавление не было"
  fi
}

# SPOOF: подделыватель SSDP на x отвечает от имени «дальнего IGD» 192.168.77.5 (на w, два перехода от клиента); роутер r
# молчит (miniupnpd не запущен). TCP-соединение клиента с TTL 1 до w не устанавливается: SYN на w нет, статус NoGateway.
# Контроль: обычное TCP-соединение с h на 192.168.77.5:5000 доходит (счётчик SYN на w растёт), значит маршрут и служба есть.
row_spoof() {
  row_begin spoof plain
  local f="" st="" c0 c1 c2 sent=""
  if ! command -v python3 >/dev/null 2>&1; then
    verdict SPOOF NOTRUN "нет python3 (подделыватель SSDP и сервер на w)"; row_end; return
  fi
  cat > "$STATE/spoof13a.py" <<'PY'
import socket, struct, sys, time
FAR, TARGET, MY, GROUP = "192.168.77.5", "192.168.10.2", "192.168.10.3", "239.255.255.250"
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
rx.bind(("", 1900))
rx.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(GROUP) + socket.inet_aton(MY))
rx.settimeout(1.0)
tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
sent = 0
print("READY", flush=True)
end = time.time() + float(sys.argv[1])
while time.time() < end:
    try:
        data, (ip, port) = rx.recvfrom(2048)
    except socket.timeout:
        continue
    if ip != TARGET or not data.startswith(b"M-SEARCH"):
        continue
    st = ""
    for line in data.decode("ascii", "replace").split("\r\n"):
        if line.upper().startswith("ST:"):
            st = line[3:].strip()
    body = ("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLOCATION: http://%s:5000/rootDesc.xml\r\nST: %s\r\nUSN: uuid:spoof::%s\r\n\r\n" % (FAR, st, st)).encode()
    udp = struct.pack("!HHHH", 1900, port, 8 + len(body), 0) + body
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 0, 0, 0, 64, 17, 0, socket.inet_aton(FAR), socket.inet_aton(TARGET))
    tx.sendto(iph + udp, (TARGET, 0))
    sent += 1
    print("SENT %d" % sent, flush=True)
PY
  nsx w nft flush ruleset 2>/dev/null || true
  nsx w nft -f - <<NFT
table inet chv13a_w {
  counter syn_far { }
  chain input {
    type filter hook input priority 0; policy accept;
    ip daddr 192.168.77.5 tcp dport 5000 tcp flags syn counter name "syn_far"
  }
}
NFT
  bg_start "$RD/far.pid" w python3 -m http.server 5000 --bind 192.168.77.5 --directory "$RD"
  local far_real="$BG_REAL" far_wrap="$BG_WRAP"
  bg_start "$RD/spoof.pid" x python3 "$STATE/spoof13a.py" 30
  local sp_real="$BG_REAL" sp_wrap="$BG_WRAP"
  sleep 1.5
  # контроль: обычный TCP (TTL по умолчанию) с h на «дальний IGD»
  nsx h timeout 3 bash -c 'exec 3<>/dev/tcp/192.168.77.5/5000' 2>/dev/null || f+="control_tcp_failed "
  sleep 0.5
  nsx w nft list counters > "$RD/nft-w0.txt"; c0="$(cnt "$RD/nft-w0.txt" syn_far)"
  [[ "$c0" -ge 1 ]] || f+="control_syn_not_seen_on_w($c0) "
  probe_once "$PROBE" release release "$PORT" "$UDN"
  st="$(probe_status "$RD/release.log")"
  nsx w nft list counters > "$RD/nft-w1.txt"; c1="$(cnt "$RD/nft-w1.txt" syn_far)"
  sent="$(grep -c '^SENT ' "$RD/spoof.log" 2>/dev/null || true)"
  bg_stop "$sp_real" "$sp_wrap"; bg_stop "$far_real" "$far_wrap"
  c2="$(( c1 - c0 ))"
  [[ "$sent" -gt 0 ]] || f+="spoofer_sent_0 "
  [[ "$st" == NoGateway ]] || f+="status_${st:-нет}(ожидалось_NoGateway) "
  [[ "$c2" == 0 ]] || f+="client_syn_reached_far_host($c2) "
  row_end
  if [[ -n "${f// /}" ]]; then verdict SPOOF FAIL "$f"
  else verdict SPOOF PASS "подделано ответов: $sent; клиент NoGateway; SYN клиента на дальний хост: 0 (контроль с обычным TTL: $c0)"
  fi
}

# ---------------------------------------------------------------- вход
need_root() {
  [[ "$(id -u)" == 0 ]] || { echo "INCONCLUSIVE: нужен root (netns, nftables)" >&2; exit 3; }
  command -v ip >/dev/null && command -v nft >/dev/null \
    || { echo "INCONCLUSIVE: нужны ip и nft" >&2; exit 3; }
}
need_privs() {
  need_root
  command -v miniupnpd >/dev/null \
    || { echo "INCONCLUSIVE: нужен miniupnpd (miniupnpd-nftables)" >&2; exit 3; }
}

cleanup() {
  local k
  [[ -n "$PB_REAL" ]] && probe_kill9
  for k in "${!MPD_REAL[@]}"; do mpd_stop "$k"; done
  if [[ "${CHV_KEEP:-0}" != 1 && "$CMD" != teardown ]]; then do_teardown || true; fi
}
trap cleanup EXIT
case "$CMD" in
  teardown) need_root; do_teardown ;;
  map) need_privs; row_map ;;
  renew) need_privs; row_renew ;;
  release) need_privs; row_release ;;
  kill) need_privs; row_kill ;;
  restart) need_privs; row_restart ;;
  cgnat) need_privs; row_cgnat ;;
  doublenat) need_privs; row_doublenat ;;
  ambiguous) need_privs; row_ambiguous ;;
  spoof) need_privs; row_spoof ;;
  all)
    need_privs
    mkdirs
    row_map; row_renew; row_release; row_kill; row_restart; row_cgnat; row_doublenat; row_ambiguous; row_spoof
    echo "--- $SUMMARY"; cat "$SUMMARY"
    ;;
  *) echo "использование: stage13a.sh <map|renew|release|kill|restart|cgnat|doublenat|ambiguous|spoof|all|teardown>" >&2; exit 2 ;;
esac
