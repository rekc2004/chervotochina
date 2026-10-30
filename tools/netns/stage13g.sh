#!/usr/bin/env bash
# Стенд netns этапа 13г: приём и набор по IPv6, двойное гнездо. Строки G6-1..G6-14 по docs/specs/stage-13g-ipv6.md
# (раздел «Стенд L4» и Дополнение 1; где они расходятся, действует Дополнение).
# Использование (root, Linux):
#   sudo CHV_NODE16=/путь/к/node16 bash tools/netns/stage13g.sh <G6-1..G6-14|all|repeat|full|report|teardown>
#   all    : строки G6-1..G6-14 (G6-13 считается по охране строк G6-1, G6-2, G6-7)
#   repeat : повтор стендов stage16.sh (all) и stage13v.sh (all) с тем же узлом (двойное гнездо по умолчанию)
#   full   : all, затем repeat
#   report : отчёт logs13g/report13g.md из summary13g.tsv (адреса заменены ролями; адрес вне карты ролей: отказ)
# Сборка узла (обычный пользователь, вне стенда): cargo build --release -p chervo-transfer --example node16
#   и CHV_NODE16=target/release/examples/node16.
# Нужны: Linux, root, ip, nft, tcpdump, python3, ping; cargo не нужен. ядро с nf_conntrack для IPv6 (экран ip6).
# Переменные: CHV_NODE16 (обязательна), CHV_LOGS (по умолчанию tools/netns/logs13g), CHV_STATE (по умолчанию каталог
#   в домашнем каталоге пользователя sudo), CHV_KEEP=1, CHV_NICE (10), CORE (11.0.0), G64_RETREAT (с до перезапуска B в
#   G6-4, 180), G64_LIMIT (720, предел из спецификации).
#
# НЕ ЗАПУСКАЛСЯ НА LINUX СБОРЩИКОМ (not run on Linux by the builder): на машине сборки (Windows) проверен только `bash -n`
# и pcap13g.py (py_compile, синтетический pcap). Прогон на Linux делает владелец или дирижёр. Строка, которую нельзя
# оценить, получает INCONCLUSIVE, а не PASS.
#
# Безопасность (умный дом на той же машине): только ns chv13g-*; nft, sysctl, tcpdump, python3 с отправкой пакетов и
# ping запускаются через `ip netns exec`; на хосте не меняется ничего, кроме создания и удаления своих ns и каталогов
# /etc/netns/chv13g-*; снимок хоста (nft, ссылки, ns, ip_forward, forwarding и disable_ipv6 для IPv6) до и после каждой
# команды и каждой строки (HOSTSAFE). Рабочий каталог под домашним каталогом. Узлы идут под nice.
# Замечание (ревью security, круг 1): рабочий каталог лежит под домашним каталогом пользователя sudo, и процесс этого
# пользователя может подменить $STATE/bin (скопированный узел), пока стенд идёт под root; это не шире bin_import
# (тот же доверенный пользователь и так задаёт CHV_NODE16). В реальную сеть
# ничего не уходит: адреса только внутри ns (IPv6: 2001:db9:13::/48, это вне спецблоков нашей таблицы, но реальный блок:
# как D11 спецификации 16 он живёт только в netns, а в отчёте заменяется ролями; ULA fd13:6::/126 для временной связи).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
# shellcheck source=lib16.sh
source "$ROOT/lib16.sh"
# lib16.sh хозяйничает с префиксом chv16-: у этого стенда свои пространства имён и свои сообщения
PFX="chv13g-"
NSL=(i na nb ha hb wa wb s)
log() { echo "[stage13g.sh] $*" >&2; }

LOGS="${CHV_LOGS:-$ROOT/logs13g}"
SUMMARY="$LOGS/summary13g.tsv"
GUARDTSV="$LOGS/guard13g.tsv"
HSTSV="$LOGS/hostsafe13g.tsv"
CMD="${1:-}"
G64_RETREAT="${G64_RETREAT:-180}"
G64_LIMIT="${G64_LIMIT:-720}"
STARTED=0
ROW_ID=""
DL=900
PYT=""
STATE_HOME=0
declare -A CAP_REAL=() CAP_WRAP=()

# ---------------------------------------------------------------- адреса стенда
G6P="2001:db9:13"
I6="$G6P::254"; NA6W="$G6P::10"; NB6W="$G6P::30"
WA6="$G6P::50"; WB6="$G6P::51"; S6="$G6P::66"; NEW6="$G6P::52"
EUI6="$G6P:0:211:22ff:fe33:4455"; EUI_TAIL="22ff:fe33:4455"
HA6="$G6P:a::2"; NA6L="$G6P:a::1"; HB6="$G6P:b::2"; NB6L="$G6P:b::1"
SRC_6TO4="2002:db9:13::66"; SRC_TEREDO="2001:0:4136:e378::66"
MEET_X6="fd13:6::1"; MEET_Y6="fd13:6::2"
HA4="192.168.10.2"; NA4L="192.168.10.1"; HB4="192.168.30.2"; NB4L="192.168.30.1"

# ---------------------------------------------------------------- вход, проверки
need_root() {
  [[ "$(id -u)" == 0 ]] || { echo "INCONCLUSIVE: нужен root (netns, nftables)" >&2; exit 3; }
  local t
  for t in ip nft tcpdump python3 ping sha256sum cmp nice; do
    command -v "$t" >/dev/null 2>&1 || { echo "INCONCLUSIVE: нужен $t" >&2; exit 3; }
  done
}

bins_import() {
  bin_import CHV_NODE16 node16 1 || { echo "INCONCLUSIVE: CHV_NODE16 не принят" >&2; exit 3; }
  NODE="$BIN/node16"
  cp -- "$ROOT/pcap13g.py" "$BIN/pcap13g.py" || { echo "INCONCLUSIVE: нет pcap13g.py" >&2; exit 3; }
  chmod 644 -- "$BIN/pcap13g.py"
  PYT="$BIN/pcap13g.py"
}

# Рабочий каталог под домашним каталогом пользователя sudo (а не /tmp), если CHV_STATE не задан.
home_dir() {
  local u="${SUDO_USER:-}" h=""
  if [[ -n "$u" && "$u" != root ]]; then h="$(getent passwd "$u" 2>/dev/null | cut -d: -f6)"; fi
  echo "${h:-${HOME:-/root}}"
}

# ---------------------------------------------------------------- HOSTSAFE
# Снимок lib16 плюс IPv6 sysctl хоста (forwarding и disable_ipv6); адреса хоста не сравниваются: RA и временные адреса
# меняются сами и дали бы ложное расхождение.
snap6() {
  snap_take "$1"
  { sysctl -n net.ipv6.conf.all.forwarding net.ipv6.conf.all.disable_ipv6 2>&1 || true; } >> "$1/sysctl"
}
HS_DIR=""
hostsafe_begin() { HS_DIR="$STATE/hs"; rm -rf -- "$HS_DIR"; snap6 "$HS_DIR/a"; }
hostsafe_check() { # метка
  local d
  [[ -n "$HS_DIR" ]] || return 0
  snap6 "$HS_DIR/b"
  d="$(snap_diff "$HS_DIR/a" "$HS_DIR/b")"
  if [[ -n "${d// /}" ]]; then
    mkdir -p -- "$LOGS"
    rm -rf -- "$LOGS/hostsafe-fail"; cp -r -- "$HS_DIR" "$LOGS/hostsafe-fail" 2>/dev/null || true
    printf '%s\t%s\t%s\t%s\n' "$(date +%F)" "$1" FAIL "$d" >> "$HSTSV"
    vd HOSTSAFE ctl FAIL "хост изменился" "после $1: $d"
    echo "HOSTSAFE FAIL после $1: изменилось на хосте: $d. Остановка, хост не чинится; сообщите дирижёру (logs13g/hostsafe-fail)." >&2
    exit 5
  fi
  return 0
}
hostsafe_end() { # метка команды
  hostsafe_check "$1"
  printf '%s\t%s\t%s\t%s\n' "$(date +%F)" "$1" PASS "-" >> "$HSTSV"
  local n
  n="$(awk -F'\t' '$3 == "PASS"' "$HSTSV" 2>/dev/null | wc -l)"
  vd HOSTSAFE ctl PASS "до и после ${n} команд: nft хоста, ссылки, ns, ip_forward, IPv6 sysctl без изменений" "nft сравнивается без счётчиков и наборов"
}

# ---------------------------------------------------------------- топология
# i : «интернет» (мост core0, 11.0.0.254 и 2001:db9:13::254), na, nb : домашние роутеры (wan в core0, lan к хосту),
# ha за na, hb за nb, wa, wb : белые хосты в core0, s : посторонний в core0. Адреса хостов выдаёт строка (host6, host4_*).
topo_body() {
  set -e
  local n p ifs
  for n in "${NSL[@]}"; do
    ip netns add "$PFX$n"
    ipn "$n" link set lo up
    # без RA и SLAAC: адреса только те, что выдала строка
    nsx "$n" sysctl -qw net.ipv6.conf.default.accept_ra=0 net.ipv6.conf.default.autoconf=0 net.ipv6.conf.default.use_tempaddr=0
  done
  ipn i link add core0 type bridge mcast_snooping 0
  for n in na nb wa wb s; do
    vl "$n" wan i "p-$n"
    ipn i link set "p-$n" master core0
  done
  vl na lan ha eth0
  vl nb lan hb eth0
  ipn i addr add "$CORE.254/24" dev core0
  ipn i addr add "$I6/64" dev core0 nodad
  ipn na addr add "$CORE.10/24" dev wan
  ipn na addr add "$NA6W/64" dev wan nodad
  ipn nb addr add "$CORE.30/24" dev wan
  ipn nb addr add "$NB6W/64" dev wan nodad
  ipn na addr add "$NA4L/24" dev lan
  ipn na addr add "$NA6L/64" dev lan nodad
  ipn nb addr add "$NB4L/24" dev lan
  ipn nb addr add "$NB6L/64" dev lan nodad
  for n in "${NSL[@]}"; do
    ifs="$(ipn "$n" -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$' || true)"
    for p in $ifs; do ipn "$n" link set "$p" up; done
  done
  ipn na route add default via "$CORE.254"
  ipn nb route add default via "$CORE.254"
  ipn na -6 route add default via "$I6" dev wan
  ipn nb -6 route add default via "$I6" dev wan
  ipn i -6 route add "$G6P:a::/64" via "$NA6W" dev core0
  ipn i -6 route add "$G6P:b::/64" via "$NB6W" dev core0
  for n in i na nb; do nsx "$n" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1; done
  # DNS-заглушка: любой запрос к резолверу виден счётчиком dns; только свои каталоги, сам /etc/netns не трогаем
  mkdir -p /etc/netns
  for n in ha hb wa wb s; do
    [[ ! -L "/etc/netns/$PFX$n" ]] || { echo "/etc/netns/$PFX$n: символьная ссылка" >&2; exit 2; }
    mkdir -p "/etc/netns/$PFX$n"
    echo "nameserver 192.0.2.53" > "/etc/netns/$PFX$n/resolv.conf"
  done
}

# Хост получает глобальный IPv6 и маршрут по умолчанию. ns dev адрес шлюз
host6() {
  ipn "$1" addr add "$3/64" dev "$2" nodad && ipn "$1" -6 route add default via "$4" dev "$2"
}
# Белый хост IPv4 в core0: номер хоста
host4_white() {
  ipn "$1" addr add "$CORE.$2/24" dev wan && ipn "$1" route add default via "$CORE.254"
}
# Хост за NAT: ns адрес шлюз
host4_nat() {
  ipn "$1" addr add "$2/24" dev eth0 && ipn "$1" route add default via "$3"
}
# NAT IPv4 роутера: ns сеть [опции masquerade]
nat4() {
  nsx "$1" nft -f - <<NFT
table ip nat13g {
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "wan" ip saddr $2 masquerade ${3:-}
  }
}
NFT
}
# Экран роутера IPv6 (спецификация, «Стенд L4»): входящие новые соединения из wan отбрасываются
fw6_on() {
  nsx "$1" nft -f - <<NFT
table ip6 fw13g {
  chain forward6 {
    type filter hook forward priority 0; policy accept;
    ct state established,related accept
    meta l4proto ipv6-icmp accept
    iifname "wan" ct state new drop
  }
}
NFT
}
l3_ok() { nsx "$1" ping "${3:--6}" -c 2 -W 2 "$2" >/dev/null 2>&1; }

meet_up() { # X Y: временная связь D4 (ULA)
  ip link add meet0 netns "$PFX$1" type veth peer name meet0 netns "$PFX$2" || return 1
  ipn "$1" addr add "$MEET_X6/126" dev meet0 nodad
  ipn "$2" addr add "$MEET_Y6/126" dev meet0 nodad
  ipn "$1" link set meet0 up
  ipn "$2" link set meet0 up
}
meet_down() { ipn "$1" link del meet0 2>/dev/null || true; }

# ---------------------------------------------------------------- строка: начало и конец
row_begin() { # id кап_секунд
  local rc
  [[ "$1" =~ ^[A-Za-z0-9-]+$ ]] || die "плохой id строки: $1"
  ROW_ID="$1"
  RD="$LOGS/$1"; rm -rf -- "$RD"; mkdir -p -- "$RD"
  W="$STATE/$1"; rm -rf -- "$W"; mkdir -p -- "$W"
  ROW_END=$(( $(now_s) + $2 ))
  DL=$(( $2 + 60 ))
  NODE_REAL=(); NODE_WRAP=(); CAP_REAL=(); CAP_WRAP=()
  NODE_NICE="$NICE_N"
  mkdir -p -- "$LOGS"
  do_teardown
  ( topo_body ) >> "$RD/setup.log" 2>&1; rc=$?
  if [[ $rc != 0 ]]; then log "$1: топология не поднялась (см. setup.log)"; return 1; fi
  return 0
}
begin_row() { # id кап
  row_begin "$1" "$2" && return 0
  vd "$1" v6 INCONCLUSIVE "-" "топология не поднялась (setup.log)"
  row_end
  return 1
}
setup_fail() { # id причина
  vd "$1" v6 INCONCLUSIVE "-" "стенд: $2"
  row_end
}

row_end() {
  nodes_stop_all
  local c
  for c in "${!CAP_REAL[@]}"; do cap_stop "$c"; done
  do_teardown
  ROW_END=0
  hostsafe_check "$ROW_ID"
}

# ---------------------------------------------------------------- узлы, захват
NA=()
node_args() { # метка ns [дополнительно...]
  local l="$1" ns="$2"; shift 2
  mkdir -p -- "$W/$ns/dest" "$W/$ns/partial"
  NA=(--port "$PORT" --book-dir "$W/$ns" --dest "$W/$ns/dest" --partial "$W/$ns/partial" --sas-auto-confirm
      --diag-every 5 --stop-file "$W/$l.stop" --deadline "$DL" "$@")
}
nstart() { # метка ns [дополнительно...]
  local l="$1" ns="$2"
  node_args "$@"
  node_start "$l" "$ns" "${NA[@]}"
}

cap_start() { # метка ns интерфейс фильтр
  bg_start "$RD/$1.cap.pid" "$2" tcpdump -i "$3" -nn -U -s 0 -w "$RD/$1.pcap" "$4"
  CAP_REAL[$1]="$BG_REAL"; CAP_WRAP[$1]="$BG_WRAP"
  sleep 1
}
cap_stop() { bg_stop "${CAP_REAL[$1]:-}" "${CAP_WRAP[$1]:-}"; unset "CAP_REAL[$1]" "CAP_WRAP[$1]"; }
cap_n() { # метка: число пакетов записи
  tcpdump -nn -r "$RD/$1.pcap" 2>/dev/null | wc -l
}

hold() { # секунды (прерывается капом строки)
  local i
  for i in $(seq 1 "$(( $1 * 5 ))"); do over_cap && return 1; sleep 0.2; done
  return 0
}

# ---------------------------------------------------------------- охрана хоста A (счётчики nft)
# dns (53/853, оба семейства), probe (192.0.2.1 и 2001:db8::1), mcast_udp (UDP к ff00::/8), other (всё прочее, кроме
# ICMP/ICMPv6/IGMP ядра) должны быть 0; peer (адреса друзей строки) > 0. Адреса other пишутся в наборы other4, other6.
guard13g() { # ns друзья_IPv4 друзья_IPv6 (через запятую, можно пусто)
  local ns="$1" e4="" e6=""
  [[ -z "$2" ]] || e4="elements = { $2 }"
  [[ -z "$3" ]] || e6="elements = { $3 }"
  nsx "$ns" nft flush ruleset 2>/dev/null || true
  nsx "$ns" nft -f - <<NFT
table inet chv13gg {
  set peers4 { type ipv4_addr; $e4 }
  set peers6 { type ipv6_addr; $e6 }
  counter dns { }
  counter probe { }
  counter mcast_udp { }
  counter kernel { }
  counter peer { }
  counter other { }
  set other4 { type ipv4_addr . inet_service; flags dynamic; size 64; }
  set other6 { type ipv6_addr . inet_service; flags dynamic; size 64; }
  chain output {
    type filter hook output priority 0; policy accept;
    th dport { 53, 853 } counter name "dns"
    oifname "lo" accept
    ip daddr 192.0.2.1 counter name "probe"
    ip6 daddr 2001:db8::1 counter name "probe"
    ip6 daddr ff00::/8 meta l4proto udp counter name "mcast_udp"
    meta l4proto { icmp, ipv6-icmp, igmp } counter name "kernel" accept
    ip daddr @peers4 counter name "peer" accept
    ip6 daddr @peers6 counter name "peer" accept
    meta nfproto ipv4 meta l4proto { tcp, udp } update @other4 { ip daddr . th dport }
    meta nfproto ipv6 meta l4proto { tcp, udp } update @other6 { ip6 daddr . th dport }
    counter name "other" accept
  }
}
NFT
}
gset13() { # ns набор
  local e
  e="$(nsx "$1" nft list set inet chv13gg "$2" 2>/dev/null | tr '\n' ' ' | sed -n 's/.*elements = {\([^}]*\)}.*/\1/p' \
    | sed -E 's/ \. /:/g; s/,/ /g; s/[[:space:]]+/ /g; s/^ //; s/ $//')"
  printf '%s' "${e:--}"
}
# Читает счётчики, пишет строку guard13g.tsv (id ns dns probe mcast_udp other peer other4 other6); GF — нарушения.
GF=""
guard_collect() { # id ns
  local id="$1" ns="$2" f="$RD/nft-$2.txt" v c line out=""
  GF=""
  nsx "$ns" nft list counters > "$f" 2>/dev/null || { GF="guard_unreadable@$ns "; return 0; }
  line="$id"$'\t'"$ns"
  for v in dns probe mcast_udp other; do
    c="$(cnt "$f" "$v")"; line+=$'\t'"${c:-?}"
    [[ "${c:-x}" == 0 ]] || out+="$v@$ns=${c:-?} "
  done
  c="$(cnt "$f" peer)"; line+=$'\t'"${c:-?}"
  [[ "${c:-0}" -gt 0 ]] || out+="peer@$ns=0 "
  line+=$'\t'"$(gset13 "$ns" other4)"$'\t'"$(gset13 "$ns" other6)"
  mkdir -p -- "$LOGS"; touch "$GUARDTSV"
  awk -F'\t' -v id="$id" '$1 != id' "$GUARDTSV" > "$GUARDTSV.tmp" || true
  mv -- "$GUARDTSV.tmp" "$GUARDTSV"
  printf '%s\n' "$line" >> "$GUARDTSV"
  GF="$out"
}

# ---------------------------------------------------------------- разбор логов
path_of() { # узел метка
  grep "^EVENT connected pair=$2 " "$(lgf "$1")" 2>/dev/null | tail -n1 | sed -n 's/.* path=\([^ ]*\).*/\1/p'
}
v6_after() { # узел метка N: соединений с путём Ipv6 после первых N строк лога
  cnt_after "$1" "^EVENT connected pair=$2 path=Ipv6 " "$3"
}
conn_after() { cnt_after "$1" "^EVENT connected pair=$2 " "$3"; }
# Последняя причина по паре: EVENT unreachable, иначе DIAG
reason_of() { # узел метка
  local line
  line="$(grep "^EVENT unreachable pair=$2 " "$(lgf "$1")" 2>/dev/null | tail -n1 || true)"
  [[ -n "$line" ]] || line="$(grep "^DIAG pair=$2 " "$(lgf "$1")" 2>/dev/null | tail -n1 || true)"
  [[ -n "$line" ]] || { echo none; return 0; }
  kv reason <<<"$line"
}
last_state() { # узел метка: connected|disconnected|none
  grep -E "^EVENT (connected|disconnected) pair=$2( |\$)" "$(lgf "$1")" 2>/dev/null | tail -n1 | awk '{print $2}'
}

# ---------------------------------------------------------------- дружба и передача
AX=(); BX=()
WHY=""; T_CONNECT="-"
# X приглашает, Y принимает; обе стороны подключены. T_CONNECT: секунды от выдачи приглашения.
pair_basic() { # X Y
  local X="$1" Y="$2" t0 i
  WHY=""; T_CONNECT="-"
  nstart "$X" "$X" --invite-out "$W/$X/inv" "${AX[@]}"
  nstart "$Y" "$Y" --invite-in "$W/$Y/inv" "${BX[@]}"
  for i in $(seq 1 300); do [[ -s "$W/$X/inv" ]] && break; sleep 0.2; done
  t0="$(now_s)"
  deliver "$W/$X/inv" "$W/$Y/inv" 60 || { WHY="приглашение не выпущено"; return 1; }
  wait_grep "$Y" '^EVENT (invite_finished pair=i1 outcome=Added|connected pair=i1 )' 60 \
    || { WHY="приглашение не принято"; return 1; }
  wait_grep "$X" '^EVENT connected pair=o1 ' 60 || { WHY="приглашающий не подключился"; return 1; }
  T_CONNECT=$(( $(now_s) - t0 ))
  return 0
}

# Дружба по временной связи D4 (ULA): после возврата X и Y подключены по связи, глобальные адреса друг друга пришли
# в ADDR_INFO (видны в строках STATE), связь ещё поднята; MX, MY — метки логов.
MX=0; MY=0
meet_pair() { # X Y глобальный_адрес_X глобальный_адрес_Y
  local X="$1" Y="$2"
  WHY=""
  nstart "$X" "$X" --invite-out "$W/$X/inv" --invite-addr "[$MEET_X6]:$PORT"
  nstart "$Y" "$Y" --invite-in "$W/$Y/inv"
  meet_up "$X" "$Y" || { WHY="связь meet0 не поднялась"; return 1; }
  deliver "$W/$X/inv" "$W/$Y/inv" 60 || { WHY="приглашение не выпущено"; return 1; }
  wait_grep "$Y" '^EVENT (invite_finished pair=i1 outcome=Added|connected pair=i1 )' 60 \
    || { WHY="приглашение по связи не принято"; return 1; }
  wait_grep "$X" '^EVENT connected pair=o1 ' 60 || { WHY="приглашающий не подключился по связи"; return 1; }
  wait_grep "$Y" "^STATE .*friend:i1=.*$3" 90 || { WHY="ADDR_INFO не принёс глобальный адрес X"; return 1; }
  wait_grep "$X" "^STATE .*friend:o1=.*$4" 90 || { WHY="ADDR_INFO не принёс глобальный адрес Y"; return 1; }
  sleep 2
  MX="$(lines_of "$X")"; MY="$(lines_of "$Y")"
  return 0
}

SRC_SHA=""
src_make() { # МиБ
  nice -n "$NODE_NICE" head -c "$(( $1 * 1048576 ))" /dev/urandom > "$W/src.bin"
  SRC_SHA="$(nice -n "$NODE_NICE" sha256sum "$W/src.bin" | awk '{print $1}')"
}
xfer_start() { # rcvns sndns sndlabel deadline
  local r="$1" s="$2"
  rm -rf -- "$W/$r/dest" "$W/$r/partial"; mkdir -p "$W/$r/dest" "$W/$r/partial" "$W/$s/dest" "$W/$s/partial"
  node_start rb "$r" --port "$PORT" --book-dir "$W/$r" --dest "$W/$r/dest" --partial "$W/$r/partial" \
    --accept --expect-complete 1 --deadline "$4" --hold 2
  sleep 1
  node_start sa "$s" --port "$PORT" --book-dir "$W/$s" --dest "$W/$s/dest" --partial "$W/$s/partial" \
    --send "$W/src.bin" --send-to "$3" --expect-complete 1 --deadline "$4" --hold 2
}
xfer_wait() { # секунды
  local i
  for i in $(seq 1 "$(( $1 * 2 ))"); do
    has rb '^RESULT xfer ' && return 0
    node_alive rb || { has rb '^RESULT xfer ' && return 0; return 1; }
    over_cap && return 1
    sleep 0.5
  done
  return 1
}
xfer_end() {
  node_wait_exit rb 30 || node_kill rb
  node_wait_exit sa 30 || node_kill sa
}
X_CMP=""
xfer_check() { # rcvns: cmp и sha256 получателя
  local f h
  X_CMP=ok
  f="$(find "$W/$1/dest" -maxdepth 1 -type f -name 'chervo-*-0' | head -n 1)"
  if [[ -z "$f" ]]; then X_CMP=nofile; return 0; fi
  cmp -s -- "$W/src.bin" "$f" || X_CMP=DIFF
  h="$(sed -n 's/.*RESULT received index=0 .*sha256=\([0-9a-f]*\).*/\1/p' "$(lgf rb)" | tail -n1)"
  if [[ -n "$h" && "$h" != "$SRC_SHA" ]]; then X_CMP=DIFF; fi
  return 0
}

# ---------------------------------------------------------------- строки
row_g61() {
  local id=G6-1 v6n pth xf="не запускалась"
  begin_row $id 420 || return 0
  host6 wa wan "$WA6" "$I6" && host6 wb wan "$WB6" "$I6" || { setup_fail $id "адреса IPv6 не выданы"; return 0; }
  l3_ok wa "$WB6" || { setup_fail $id "нет связности IPv6 wa-wb"; return 0; }
  guard13g wa "" "$WB6"
  AX=(); BX=()
  if ! pair_basic wa wb; then
    guard_collect $id wa
    vd $id v6 FAIL "нет соединения по IPv6: $WHY" "A и B только глобальный IPv6, без экрана"
    row_end; return 0
  fi
  v6n=$(( $(v6_after wa o1 0) + $(v6_after wb i1 0) )); pth="$(path_of wb i1)"
  if (( v6n > 0 && T_CONNECT <= 15 )); then
    node_stop wa; node_stop wb
    src_make 64
    xfer_start wa wb i1 300
    if xfer_wait 240; then xfer_check wa; xf="$X_CMP"; else xf="не завершилась"; fi
    xfer_end
  fi
  guard_collect $id wa
  if (( v6n == 0 )); then
    vd $id v6 FAIL "соединение есть, но путь не Ipv6 (путь B: ${pth:--})" "Connected{Ipv6} ожидался"
  elif (( T_CONNECT > 15 )); then
    vd $id v6 FAIL "Connected{Ipv6} за ${T_CONNECT} с (> 15)" "от выдачи приглашения"
  elif [[ "$xf" == ok ]]; then
    vd $id v6 PASS "Connected{Ipv6} за ${T_CONNECT} с (≤ 15); 64 МиБ, cmp и sha256 совпали" "охрана хоста: строка G6-13"
  else
    vd $id v6 FAIL "Connected{Ipv6} за ${T_CONNECT} с; передача 64 МиБ: $xf" "cmp или sha256 или завершение"
  fi
  row_end
}

# G6-2 и G6-4: оба за экраном, дружба через временную связь, затем связь удалена
row_fw_both() { # id
  local id="$1" t0 el cx cy bx by limit=60 note="" Y2 mr
  begin_row "$id" "$([[ $id == G6-4 ]] && echo 1800 || echo 420)" || return 0
  host6 ha eth0 "$HA6" "$NA6L" && host6 hb eth0 "$HB6" "$NB6L" || { setup_fail "$id" "адреса IPv6 не выданы"; return 0; }
  fw6_on na && fw6_on nb || { setup_fail "$id" "экран ip6 не загрузился"; return 0; }
  guard13g ha "" "$HB6, $MEET_Y6"
  if ! meet_pair ha hb "$HA6" "$HB6"; then
    guard_collect "$id" ha
    vd "$id" v6 INCONCLUSIVE "-" "подготовка: $WHY"
    row_end; return 0
  fi
  meet_down ha
  if [[ $id == G6-4 ]]; then
    # B уходит; A остаётся без ответа и уходит в отступ; затем B перезапускается (новая метка лога hb2)
    limit="$G64_LIMIT"
    node_stop hb
    hold "$G64_RETREAT"
    note="A ждал B ${G64_RETREAT} с; последняя причина A: $(reason_of ha o1); "
    MX="$(lines_of ha)"; MY=0; Y2=hb2
    nstart "$Y2" hb
  else
    Y2=hb
  fi
  t0="$(now_s)"
  while :; do
    cx="$(conn_after ha o1 "$MX")"; cy="$(conn_after "$Y2" i1 "$MY")"
    bx=$(( $(v6_after ha o1 "$MX") + $(v6_after "$Y2" i1 "$MY") ))
    (( cx > 0 && cy > 0 )) && break
    el=$(( $(now_s) - t0 ))
    (( el >= limit + 30 )) && break
    over_cap && break
    sleep 1
  done
  el=$(( $(now_s) - t0 ))
  guard_collect "$id" ha
  mr="$(reason_of ha o1)"
  if (( cx > 0 && cy > 0 && bx > 0 )); then
    if [[ $id == G6-4 ]]; then
      vd $id v6 PASS "Connected{Ipv6} через ${el} с после перезапуска B (≤ ${limit}); время информативно" "${note}"
    elif (( el <= limit )); then
      vd $id v6 PASS "Connected{Ipv6} через ${el} с после удаления связи (≤ ${limit})" "адреса глобальные из ADDR_INFO; оба за экраном ip6"
    else
      vd $id v6 FAIL "Connected{Ipv6} через ${el} с (> ${limit})" "после удаления связи"
    fi
  elif (( cx > 0 && cy > 0 )); then
    vd $id v6 FAIL "соединились через ${el} с, но путь не Ipv6" "${note}"
  else
    vd $id v6 FAIL "нет соединения за ${el} с (A: ${cx}, B: ${cy}); причина A: ${mr}" "${note}лимит ${limit} с"
  fi
  row_end
}

row_g63() {
  local id=G6-3 v6n
  begin_row $id 240 || return 0
  host6 wb wan "$WB6" "$I6" && host6 ha eth0 "$HA6" "$NA6L" || { setup_fail $id "адреса IPv6 не выданы"; return 0; }
  fw6_on na || { setup_fail $id "экран ip6 не загрузился"; return 0; }
  l3_ok ha "$WB6" || { setup_fail $id "нет исходящей связности ha-wb"; return 0; }
  AX=(); BX=()
  if pair_basic wb ha; then
    v6n=$(( $(v6_after wb o1 0) + $(v6_after ha i1 0) ))
    if (( T_CONNECT <= 30 )); then
      vd $id v6 PASS "соединение за ${T_CONNECT} с (≤ 30); путь Ipv6: $(( v6n > 0 ? 1 : 0 ))" "A за экраном ip6 звонит открытому B"
    else
      vd $id v6 FAIL "соединение за ${T_CONNECT} с (> 30)" "A за экраном, B открыт"
    fi
  else
    vd $id v6 FAIL "нет соединения: $WHY" "A за экраном, B открыт"
  fi
  row_end
}

row_g65() {
  local id=G6-5 pth n6
  begin_row $id 240 || return 0
  host4_white wb 51 || { setup_fail $id "IPv4 wb не выдан"; return 0; }
  host4_nat ha "$HA4" "$NA4L" && nat4 na 192.168.10.0/24 && host6 ha eth0 "$HA6" "$NA6L" || { setup_fail $id "адреса A не выданы"; return 0; }
  l3_ok ha "$CORE.51" -4 || { setup_fail $id "нет связности IPv4 ha-wb"; return 0; }
  cap_start c6 ha any 'ip6 and udp'
  AX=(); BX=()
  if pair_basic wb ha; then
    sleep 5
    pth="$(path_of ha i1)"; cap_stop c6; n6="$(cap_n c6)"
    if [[ -n "$pth" && "$pth" != Ipv6 && "$n6" == 0 ]]; then
      vd $id v6 PASS "Connected по IPv4 (путь ${pth}); IPv6 UDP-пакетов с A: 0" "B только IPv4, A двойной за NAT"
    else
      vd $id v6 FAIL "путь: ${pth:--}; IPv6 UDP-пакетов с A: ${n6}" "ожидался IPv4 и ни одного IPv6-пакета к B"
    fi
  else
    vd $id v6 FAIL "нет соединения: $WHY" "A двойной, B только IPv4"
  fi
  row_end
}

row_g66() {
  local id=G6-6 v6n
  begin_row $id 240 || return 0
  host6 wb wan "$WB6" "$I6" || { setup_fail $id "IPv6 wb не выдан"; return 0; }
  host4_nat ha "$HA4" "$NA4L" && nat4 na 192.168.10.0/24 && host6 ha eth0 "$HA6" "$NA6L" || { setup_fail $id "адреса A не выданы"; return 0; }
  l3_ok ha "$WB6" || { setup_fail $id "нет связности IPv6 ha-wb"; return 0; }
  AX=(); BX=()
  if pair_basic wb ha; then
    v6n=$(( $(v6_after wb o1 0) + $(v6_after ha i1 0) ))
    if (( v6n > 0 )); then vd $id v6 PASS "Connected{Ipv6} за ${T_CONNECT} с" "A двойной (IPv4 за NAT + IPv6), B только IPv6"
    else vd $id v6 FAIL "соединились, но путь не Ipv6 (A: $(path_of ha i1))" "ожидался Connected{Ipv6}"; fi
  else
    vd $id v6 FAIL "нет соединения: $WHY" "A двойной, B только IPv6"
  fi
  row_end
}

row_g67() {
  local id=G6-7 v6n
  begin_row $id 420 || return 0
  host4_nat ha "$HA4" "$NA4L" && nat4 na 192.168.10.0/24 "fully-random" && host6 ha eth0 "$HA6" "$NA6L" \
    && host4_nat hb "$HB4" "$NB4L" && nat4 nb 192.168.30.0/24 "fully-random" && host6 hb eth0 "$HB6" "$NB6L" \
    || { setup_fail $id "адреса не выданы"; return 0; }
  l3_ok ha "$HB6" || { setup_fail $id "нет связности IPv6 ha-hb"; return 0; }
  guard13g ha "" "$HB6"
  AX=(); BX=()
  if pair_basic ha hb; then
    v6n=$(( $(v6_after ha o1 0) + $(v6_after hb i1 0) ))
    guard_collect $id ha
    if (( v6n > 0 )); then vd $id v6 PASS "Connected{Ipv6} за ${T_CONNECT} с при IPv4 за симметричным NAT (fully-random) у обоих" "IPv6 открыт и обходит NAT"
    else vd $id v6 FAIL "соединились, но путь не Ipv6 (A: $(path_of ha o1))" "ожидался Connected{Ipv6}"; fi
  else
    guard_collect $id ha
    vd $id v6 FAIL "нет соединения: $WHY" "оба двойные, IPv4 за симметричным NAT"
  fi
  row_end
}

# G6-8 и G6-9: посторонний s шлёт на порт A (wa); ответов быть не должно. Запись на s: всё, что пришло от MAC wa
# (UDP и ICMPv6 type 1); ответы самого сокета отправителя считает pcap13g.py.
sil_setup() { # id
  local id="$1"
  host6 wa wan "$WA6" "$I6" && host6 wb wan "$WB6" "$I6" && host6 s wan "$S6" "$I6" || return 1
  l3_ok wa "$WB6" || return 1
  AX=(); BX=()
  pair_basic wa wb || { WHY="пара: $WHY"; return 1; }
  MAC_WA="$(ipn wa -o link show wan | awk '{for (i = 1; i <= NF; i++) if ($i == "link/ether") print $(i + 1)}' | head -n1)"
  [[ -n "$MAC_WA" ]] || { WHY="MAC wa не определён"; return 1; }
  return 0
}
MAC_WA=""
row_g68() {
  local id=G6-8 out rep ic n
  begin_row $id 240 || return 0
  sil_setup $id || { setup_fail $id "${WHY:-подготовка}"; return 0; }
  cap_start cs s wan "ip6 and ether src $MAC_WA and not dst host $WB6 and (udp or ip6[40] == 1)"
  out="$(nsx s python3 -I "$PYT" flood6 "$WA6" "$PORT" "$S6" 1000 2>&1)"
  sleep 1; cap_stop cs; n="$(cap_n cs)"
  rep="$(kv replies <<<" $out")"; ic="$(kv icmp_err <<<" $out")"
  if [[ "$out" != sent=* ]]; then
    vd $id v6 INCONCLUSIVE "отправитель не отработал" "${out//$'\n'/ }"
  elif [[ "$(kv sent <<<" $out")" -lt 1000 ]]; then
    vd $id v6 INCONCLUSIVE "отправлено меньше 1000: $out" "отправитель"
  elif [[ "$n" == 0 && "${rep:-x}" == 0 && "${ic:-x}" == 0 ]]; then
    vd $id v6 PASS "1000 случайных датаграмм и 3 Initial: ответов 0, ICMPv6 недоступен 0 (запись на s: 0 пакетов от A)" "порт A молчит для постороннего"
  else
    vd $id v6 FAIL "ответов сокета ${rep:-?}, ошибок ICMP ${ic:-?}, пакетов от A на s ${n}" "порт A должен молчать"
  fi
  row_end
}

row_g69() {
  local id=G6-9 out rep ic n np ll
  begin_row $id 300 || return 0
  sil_setup $id || { setup_fail $id "${WHY:-подготовка}"; return 0; }
  ipn s addr add "$SRC_6TO4/128" dev wan nodad && ipn s addr add "$SRC_TEREDO/128" dev wan nodad \
    && ipn i -6 route add "$SRC_6TO4/128" via "$S6" dev core0 && ipn i -6 route add "$SRC_TEREDO/128" via "$S6" dev core0 \
    || { setup_fail $id "адреса источников не выданы"; return 0; }
  l3_ok wa "$SRC_6TO4" && l3_ok wa "$SRC_TEREDO" || { setup_fail $id "ответ до адресов 2002:: и 2001:0:: не дойдёт (контроль)"; return 0; }
  ll="$(ipn s -6 -o addr show dev wan scope link | awk '{print $4}' | cut -d/ -f1 | head -n1)"
  [[ -n "$ll" ]] || { setup_fail $id "нет link-local на s"; return 0; }
  # верный стук B -> A: запись исходящих B при его перезапуске
  cap_start ck wb any "ip6 and udp and dst port $PORT and src host $WB6"
  node_stop wb
  nstart wb2 wb
  hold 15
  cap_stop ck
  np="$(nsx s python3 -I "$PYT" payloads "$RD/ck.pcap" "$PORT" 2>/dev/null || echo 0)"
  if [[ "${np:-0}" -lt 1 ]]; then vd $id v6 INCONCLUSIVE "в записи нет датаграмм B -> A (стук не получен)" "повтор невозможен"; row_end; return 0; fi
  cap_start cs s wan "ip6 and ether src $MAC_WA and not dst host $WB6 and (udp or ip6[40] == 1)"
  out="$(nsx s python3 -I "$PYT" replay6 "$RD/ck.pcap" "$WA6" "$PORT" wan "$ll" "$SRC_6TO4" "$SRC_TEREDO" 2>&1)"
  out+=" $(nsx s python3 -I "$PYT" flood6 "$WA6" "$PORT" "$SRC_6TO4" 200 2>&1)"
  out+=" $(nsx s python3 -I "$PYT" flood6 "$WA6" "$PORT" "$SRC_TEREDO" 200 2>&1)"
  out+=" $(nsx s python3 -I "$PYT" flood6 "$WA6" "$PORT" "$ll" 200 wan 2>&1)"
  sleep 1; cap_stop cs; n="$(cap_n cs)"
  rep="$(tr ' ' '\n' <<<"$out" | awk -F= '$1 == "replies" { s += $2 } END { print s + 0 }')"
  ic="$(tr ' ' '\n' <<<"$out" | awk -F= '$1 == "icmp_err" { s += $2 } END { print s + 0 }')"
  if [[ "$out" != sent=* || "$(grep -o "sent=" <<<"$out" | wc -l)" != 4 ]]; then
    vd $id v6 INCONCLUSIVE "отправитель не отработал" "${out//$'\n'/ }"
  elif [[ "$n" == 0 && "$rep" == 0 && "$ic" == 0 ]]; then
    vd $id v6 PASS "датаграммы и ${np} записанных стуков с link-local, 6to4 и Teredo: ответов 0, ICMPv6 недоступен 0 (запись на s: 0)" "источники третьих сторон и link-local выбрасываются до стука"
  else
    vd $id v6 FAIL "ответов сокета ${rep}, ошибок ICMP ${ic}, пакетов от A на s ${n}" "порт A не должен отвечать этим источникам"
  fi
  row_end
}

row_g610() {
  local id=G6-10 t0 el ok_b=0 w alive=1 dis_a dis_b ca cb
  begin_row $id 300 || return 0
  host6 wa wan "$WA6" "$I6" && host6 wb wan "$WB6" "$I6" || { setup_fail $id "адреса IPv6 не выданы"; return 0; }
  l3_ok wa "$WB6" || { setup_fail $id "нет связности IPv6 wa-wb"; return 0; }
  AX=(); BX=()
  pair_basic wa wb || { vd $id v6 INCONCLUSIVE "-" "подготовка: $WHY"; row_end; return 0; }
  sleep 5
  MX="$(lines_of wa)"; MY="$(lines_of wb)"
  ipn wa addr add "$NEW6/64" dev wan nodad || { setup_fail $id "новый адрес не выдан"; return 0; }
  ipn wa addr change "$WA6/64" dev wan preferred_lft 0 valid_lft 300
  sleep 5
  ipn wa addr del "$WA6/64" dev wan
  t0="$(now_s)"
  for w in $(seq 1 15); do sleep 1; done
  dis_a="$(cnt_after wa '^EVENT disconnected pair=o1' "$MX")"; dis_b="$(cnt_after wb '^EVENT disconnected pair=i1' "$MY")"
  ca="$(last_state wa o1)"; cb="$(last_state wb i1)"
  [[ "$ca" == connected && "$cb" == connected ]] || alive=0
  # B получает новый IPv6 в ADDR_INFO
  for w in $(seq 1 45); do
    if wait_grep wb "^STATE .*friend:i1=.*$NEW6" 1; then ok_b=1; break; fi
    over_cap && break
  done
  if (( alive == 1 && ok_b == 1 )); then
    vd $id v6 PASS "через 15 с после удаления старого адреса соединение живо (разрывов: A ${dis_a}, B ${dis_b}); B получил новый IPv6" "старому адресу preferred_lft 0, затем удалён"
  elif (( alive == 0 )); then
    vd $id v6 FAIL "через 15 с соединения нет (A: ${ca:-none}, B: ${cb:-none})" "соединение должно жить или переподключиться ≤ 15 с"
  else
    vd $id v6 FAIL "соединение живо, но B не получил новый IPv6 за 45 с после окна" "ADDR_INFO с новым адресом"
  fi
  row_end
}

row_g611() {
  local id=G6-11 st
  begin_row $id 240 || return 0
  host4_white wa 50 && ipn wa addr add "$EUI6/64" dev wan nodad && ipn wa -6 route add default via "$I6" dev wan \
    || { setup_fail $id "адреса A не выданы"; return 0; }
  host4_nat hb "$HB4" "$NB4L" && nat4 nb 192.168.30.0/24 && host6 hb eth0 "$HB6" "$NB6L" && fw6_on nb \
    || { setup_fail $id "адреса B не выданы"; return 0; }
  l3_ok hb "$CORE.50" -4 || { setup_fail $id "нет связности IPv4 hb-wa"; return 0; }
  AX=(); BX=()
  if pair_basic wa hb; then
    sleep 20
    st="$(grep -c "$EUI_TAIL" "$(lgf hb)" 2>/dev/null || true)"
    if [[ "${st:-0}" == 0 ]] && has hb "^STATE .*friend:i1=.*$CORE\\.50"; then
      vd $id v6 PASS "соединение по IPv4 за ${T_CONNECT} с; адреса EUI-64 в приглашении и книге B (STATE, ADDR_INFO) нет" "единственный глобальный IPv6 A это EUI-64; B за экраном ip6, звонок A по IPv6 до B не доходит"
    elif [[ "${st:-0}" != 0 ]]; then
      vd $id v6 FAIL "адрес EUI-64 A найден в логе B (строк: ${st})" "T8: EUI-64 не публикуется"
    else
      vd $id v6 INCONCLUSIVE "IPv4-адрес A в книге B не найден (STATE)" "проверка книги B не состоялась"
    fi
  else
    vd $id v6 FAIL "нет соединения: $WHY" "IPv4 должен работать при единственном EUI-64 IPv6"
  fi
  row_end
}

row_g612() {
  local id=G6-12 i r="" ls
  begin_row $id 420 || return 0
  host6 wb wan "$WB6" "$I6" || { setup_fail $id "IPv6 wb не выдан"; return 0; }
  host4_nat ha "$HA4" "$NA4L" && nat4 na 192.168.10.0/24 && host6 ha eth0 "$HA6" "$NA6L" || { setup_fail $id "адреса A не выданы"; return 0; }
  l3_ok ha "$WB6" || { setup_fail $id "нет связности IPv6 ha-wb"; return 0; }
  AX=(); BX=()
  pair_basic wb ha || { vd $id v6 INCONCLUSIVE "-" "подготовка: $WHY"; row_end; return 0; }
  node_stop wb; node_stop ha
  # для A (метка B: i1) известны только адреса IPv6; у A IPv6 выключен
  nsx ha sysctl -qw net.ipv6.conf.all.disable_ipv6=1 || { setup_fail $id "disable_ipv6 не сработал"; return 0; }
  nstart wb2 wb
  nstart ha2 ha
  wait_grep ha2 '^EVENT started ' 30 || { vd $id v6 FAIL "A не стартовал" "A должен стартовать без IPv6"; row_end; return 0; }
  ls="$(grep '^EVENT started ' "$(lgf ha2)" | head -n1 | kv listen)"
  for i in $(seq 1 90); do
    r="$(reason_of ha2 i1)"
    [[ "$r" == NoIpv6 ]] && break
    over_cap && break
    sleep 1
  done
  if [[ "$r" == NoIpv6 ]]; then
    vd $id v6 PASS "A стартовал (listen=${ls:-?}); причина для B: NoIpv6" "текст причины (новая редакция) проверяет L3 texts_no_ipv6_new_wording; узел печатает только имя причины"
  else
    vd $id v6 FAIL "A стартовал (listen=${ls:-?}); причина для B: ${r:-none}" "ожидалась NoIpv6"
  fi
  row_end
}

# G6-13: охрана хоста A в строках G6-1, G6-2, G6-7 (запускает недостающие)
row_g613() {
  local id=G6-13 r bad="" miss="" line peers=0
  for r in G6-1 G6-2 G6-7; do
    awk -F'\t' -v id="$r" '$1 == id { f = 1 } END { exit f ? 0 : 1 }' "$GUARDTSV" 2>/dev/null || run_row "$r"
  done
  for r in G6-1 G6-2 G6-7; do
    line="$(awk -F'\t' -v id="$r" '$1 == id' "$GUARDTSV" 2>/dev/null | head -n1)"
    if [[ -z "$line" ]]; then miss+="$r "; continue; fi
    awk -F'\t' '($3 + 0 > 0 || $4 + 0 > 0 || $5 + 0 > 0 || $6 + 0 > 0 || $7 + 0 == 0)' <<<"$line" | grep -q . && bad+="$r($(awk -F'\t' '{printf "dns=%s probe=%s mcast=%s other=%s peer=%s", $3, $4, $5, $6, $7}' <<<"$line")) "
    peers=$(( peers + $(awk -F'\t' '{print $7 + 0}' <<<"$line") ))
  done
  if [[ -n "$miss" ]]; then
    vd $id v6 INCONCLUSIVE "нет данных охраны: $miss" "строка не отработала до охраны"
  elif [[ -n "$bad" ]]; then
    vd $id v6 FAIL "нарушения охраны: $bad" "UDP наружу ⊆ адреса друзей; DNS, зонды, multicast IPv6 = 0"
  else
    vd $id v6 PASS "G6-1, G6-2, G6-7: нарушений 0 (dns, зонды маршрута обоих семейств, UDP к multicast IPv6, прочие назначения: 0); пакетов к друзьям ${peers}" "UDP наружу ⊆ адреса друзей строки"
  fi
}

row_g614() {
  local id=G6-14
  begin_row $id 240 || return 0
  host6 wa wan "$WA6" "$I6" && host6 wb wan "$WB6" "$I6" || { setup_fail $id "адреса IPv6 не выданы"; return 0; }
  l3_ok wb "$WA6" || { setup_fail $id "нет связности IPv6 wb-wa"; return 0; }
  guard13g wb "" "$WA6"
  AX=(--invite-addr "[$WA6]:$PORT"); BX=()
  if pair_basic wa wb; then
    sleep 5
    guard_collect $id wb
    if [[ "$(cnt "$RD/nft-wb.txt" dns)" == 0 ]]; then
      vd $id v6 PASS "соединение только по IPv6-литералу приглашения за ${T_CONNECT} с; DNS (53/853) у звонящего 0" "прочее по охране: ${GF:-чисто}"
    else
      vd $id v6 FAIL "DNS у звонящего: $(cnt "$RD/nft-wb.txt" dns)" "нарушения охраны: $GF"
    fi
  else
    guard_collect $id wb
    vd $id v6 FAIL "нет соединения: $WHY" "по IPv6-литералу приглашения"
  fi
  row_end
}

# ---------------------------------------------------------------- повтор стендов 16 и 13в
do_repeat() {
  local rc16 rc13 rd="$LOGS/repeat"
  mkdir -p -- "$rd"
  log "повтор stage16.sh all (узел по умолчанию: --listen dual)"
  CHV_LOGS="$rd/stage16" bash "$ROOT/stage16.sh" all > "$rd/stage16.out" 2>&1; rc16=$?
  log "повтор stage13v.sh all"
  CHV_LOGS="$rd/stage13v" bash "$ROOT/stage13v.sh" all > "$rd/stage13v.out" 2>&1; rc13=$?
  vd REPEAT16 repeat "$([[ $rc16 == 0 ]] && echo DONE || echo FAIL)" "stage16.sh all: код ${rc16}" "сравнить вердикты с NETTEST-2026-10-18 и 16а: $rd/stage16/summary16.tsv"
  vd REPEAT13V repeat "$([[ $rc13 == 0 ]] && echo DONE || echo FAIL)" "stage13v.sh all: код ${rc13}" "сравнить с прогоном 838894c: $rd/stage13v/summary13v.tsv"
}

run_row() {
  case "$1" in
    G6-1) row_g61 ;;
    G6-2|G6-4) row_fw_both "$1" ;;
    G6-3) row_g63 ;;
    G6-5) row_g65 ;;
    G6-6) row_g66 ;;
    G6-7) row_g67 ;;
    G6-8) row_g68 ;;
    G6-9) row_g69 ;;
    G6-10) row_g610 ;;
    G6-11) row_g611 ;;
    G6-12) row_g612 ;;
    G6-13) row_g613 ;;
    G6-14) row_g614 ;;
    *) return 2 ;;
  esac
}
ALL_ROWS=(G6-1 G6-2 G6-3 G6-4 G6-5 G6-6 G6-7 G6-8 G6-9 G6-10 G6-11 G6-12 G6-13 G6-14)

usage() {
  echo "использование: stage13g.sh <G6-1..G6-14|all|repeat|full|report|teardown>" >&2
}

# ---------------------------------------------------------------- отчёт: роли вместо адресов
# Карта ролей: адрес роль. Длинные адреса не пересекаются границами (после адреса IPv6 не бывает цифры, буквы, двоеточия).
sanitize() {
  local e=() pair a r c="${CORE//./\\.}"
  local v6map=("$I6 INET6" "$NA6W NAT-A6" "$NB6W NAT-B6" "$WA6 WA6" "$WB6 WB6" "$S6 STRANGER6" "$NEW6 WA6-NEW" "$EUI6 WA6-EUI64"
               "$HA6 HA6" "$NA6L NAT-A6" "$HB6 HB6" "$NB6L NAT-B6" "$SRC_6TO4 SRC-6TO4" "$SRC_TEREDO SRC-TEREDO"
               "$MEET_X6 MEET-X6" "$MEET_Y6 MEET-Y6" "2001:db8::1 DOC6-PROBE")
  local v4map=("$CORE.254 INET" "$CORE.50 WA" "$CORE.51 WB" "$CORE.10 NAT-A" "$CORE.30 NAT-B" "$HA4 HA" "$NA4L NAT-A"
               "$HB4 HB" "$NB4L NAT-B" "192.0.2.1 PROBE4")
  for pair in "${v6map[@]}"; do
    a="${pair% *}"; r="${pair#* }"
    e+=(-e "s/(^|[^0-9A-Za-z:.])${a}([^0-9A-Za-z:]|\$)/\\1${r}\\2/g" -e "s/(^|[^0-9A-Za-z:.])${a}([^0-9A-Za-z:]|\$)/\\1${r}\\2/g")
  done
  for pair in "${v4map[@]}"; do
    a="${pair% *}"; r="${pair#* }"; a="${a//./\\.}"
    e+=(-e "s/(^|[^0-9.])${a}([^0-9.]|\$)/\\1${r}\\2/g" -e "s/(^|[^0-9.])${a}([^0-9.]|\$)/\\1${r}\\2/g")
  done
  : "$c"
  sed -E "${e[@]}"
}
# 0 — чисто; иначе причина на stdout и код 1
check_clean() { # файл
  local f="$1" h u
  if grep -Eq '([0-9]{1,3}\.){3}[0-9]{1,3}' "$f"; then echo "IPv4-адрес"; return 1; fi
  if grep -Eq '(^|[^0-9A-Za-z:])(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,6}:([0-9A-Fa-f]{1,4})?|::[0-9A-Fa-f]{1,4})([^0-9A-Za-z:]|$)' "$f"; then
    echo "IPv6-адрес"; return 1
  fi
  if grep -Fq -e '/home/' -e '/tmp/chervo' -e '/root/' "$f"; then echo "путь домашнего каталога"; return 1; fi
  h="$(hostname 2>/dev/null || true)"
  if [[ ${#h} -ge 3 ]] && tr "[:upper:]" "[:lower:]" < "$f" | grep -Fwq -- "${h,,}"; then echo "имя хоста"; return 1; fi
  u="${SUDO_USER:-}"
  if [[ -n "$u" && "$u" != root && ${#u} -ge 3 ]] && tr "[:upper:]" "[:lower:]" < "$f" | grep -Fwq -- "${u,,}"; then echo "имя пользователя"; return 1; fi
  return 0
}
render() {
  echo "# Стенд 13г: IPv6 в netns"
  echo
  echo "Эмуляция netns на одной машине, не реальные роутеры и не реальные провайдеры. Адреса заменены ролями."
  echo
  echo "| Строка | Вердикт | Факт | Примечание |"
  echo "|---|---|---|---|"
  awk -F'\t' '$1 != "HOSTSAFE" { gsub(/\|/, "/"); printf "| %s | %s | %s | %s |\n", $1, $3, $5, $12 }' "$SUMMARY"
  echo
  awk -F'\t' '$1 == "HOSTSAFE" { printf "HOSTSAFE: %s. %s\n", $3, $5 }' "$SUMMARY"
  echo
  echo "Не проверено: реальные домашние роутеры (экран IPv6, сроки записей), реальные IPv6 провайдеров, временные адреса и выбор источника на Windows и macOS, брандмауэр Windows для двойного сокета, Teredo на Windows, macOS ECN на двойном сокете, доставка ОС пакетов с v4-mapped источником."
}
do_report() {
  local tmp why out="$LOGS/report13g.md"
  [[ -s "$SUMMARY" ]] || { echo "report: нет $SUMMARY" >&2; return 2; }
  tmp="$(mktemp "${TMPDIR:-/tmp}/report13g.XXXXXX")" || return 2
  render | sanitize > "$tmp"
  if ! why="$(check_clean "$tmp")"; then
    rm -f -- "$tmp"
    echo "report13g: отказ записи отчёта: в тексте осталось: $why" >&2
    return 4
  fi
  mv -- "$tmp" "$out"
  echo "report13g: записан $out"
}

# ---------------------------------------------------------------- вход и уборка
cleanup() {
  local l
  if [[ "$STARTED" == 1 ]]; then
    for l in "${!NODE_REAL[@]}"; do node_kill "$l"; done
    for l in "${!CAP_REAL[@]}"; do cap_stop "$l"; done
    do_teardown || true
    if [[ -n "${SUDO_UID:-}" && -d "$LOGS" ]]; then chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" -- "$LOGS" 2>/dev/null || true; fi
  fi
  if [[ "$STATE_OWNED" == 1 && "${CHV_KEEP:-0}" != 1 && -n "$STATE" && "$STATE" != / ]]; then rm -rf -- "$STATE"; fi
  if [[ "$STATE_HOME" == 1 && "${CHV_KEEP:-0}" != 1 && -n "$STATE" && "$STATE" != / && "$STATE" == "$(home_dir)"/.chervo-stage13g.* ]]; then
    rm -rf -- "$STATE"
  fi
}

main() {
  local id
  case "$CMD" in
    ""|-h|--help) usage; exit 2 ;;
    report) do_report; exit $? ;;
  esac
  need_root
  STARTED=1
  trap cleanup EXIT
  mkdir -p -- "$LOGS"
  if [[ "$CMD" == teardown ]]; then do_teardown; exit 0; fi
  if [[ -z "${CHV_STATE:-}" ]]; then CHV_STATE="$(home_dir)/.chervo-stage13g.$$"; STATE_HOME=1; fi
  state_init
  bins_import
  hostsafe_begin
  case "$CMD" in
    all)
      for id in "${ALL_ROWS[@]}"; do run_row "$id"; done
      echo "--- $SUMMARY"; cat -- "$SUMMARY" ;;
    repeat) do_repeat ;;
    full)
      for id in "${ALL_ROWS[@]}"; do run_row "$id"; done
      do_repeat
      echo "--- $SUMMARY"; cat -- "$SUMMARY" ;;
    *)
      run_row "$CMD"
      if [[ $? == 2 ]]; then usage; exit 2; fi ;;
  esac
  hostsafe_end "$CMD"
}
main
