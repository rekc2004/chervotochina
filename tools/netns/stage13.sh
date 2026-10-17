#!/usr/bin/env bash
# Стенд netns этапа 13 (часть C5): слой соединения chervo-connect против настоящих NAT ядра Linux.
# Использование:
#   sudo bash tools/netns/stage13.sh <white|forward|prpr|sym|cgnat|udp|addrchange|all|teardown>
# Требуется Linux, root, ip, nft, cargo (сборка идёт вне ns). Каталог логов: CHV_LOGS=/путь
# (по умолчанию tools/netns/logs13). Адресное пространство «интернета» стенда: CORE=11.0.0 (в ns, наружу не
# маршрутизируется; 198.51.100.0/24 и подобные документационные сети слой адресов считает не глобальными,
# поэтому для публикации адресов нужен «глобальный» префикс).
#
# Прогнан 2026-10-17 на Linux (Ubuntu 24.04, nftables 1.0.9): white, forward, sym, cgnat, udp, addrchange PASS; prpr NOTRUN.
#
# Функции стенда (log, nsx, spk_in, bg_start, bg_stop, cnt, evl, kv, verdict) скопированы из stage9.sh без
# изменения смысла; префикс ns другой (chv13-), чтобы стенды этапов 9 и 13 не мешали друг другу.
# Узел: `cargo build --release --locked -p chervo-connect --example node13` (ключи в памяти узла, он живёт всё
# время строки стенда). Бинарники запускаются только внутри ns (env -i).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
# Рабочий каталог (бинарники из него запускаются от root): непредсказуемое имя, владелец root, режим 700.
# Своё значение CHV_STATE допускается, только если каталог принадлежит запускающему; режим ставится 700.
STATE_OWNED=0
if [[ -n "${CHV_STATE:-}" ]]; then
  STATE="$CHV_STATE"
  # до любых mkdir/chmod: не символьная ссылка и, если уже есть, принадлежит запускающему
  [[ ! -L "$STATE" ]] || { echo "CHV_STATE не должен быть символьной ссылкой" >&2; exit 2; }
  if [[ -e "$STATE" ]]; then
    [[ -d "$STATE" && "$(stat -c %u -- "$STATE")" == "$(id -u)" ]] || { echo "CHV_STATE не каталог или не принадлежит текущему пользователю" >&2; exit 2; }
  fi
  mkdir -p -- "$STATE"
  [[ ! -L "$STATE" && "$(stat -c %u -- "$STATE")" == "$(id -u)" ]] || { echo "CHV_STATE не принадлежит текущему пользователю" >&2; exit 2; }
  chmod 700 -- "$STATE"
else
  STATE="$(mktemp -d /tmp/chervo-stage13.XXXXXX)"
  chmod 700 -- "$STATE"
  STATE_OWNED=1
fi
LOGS="${CHV_LOGS:-$ROOT/logs13}"
BIN="$STATE/bin"
NODE="$BIN/node13"
CORE="${CORE:-11.0.0}"
PORT=4433
SUMMARY="$LOGS/summary13.txt"
CMD="${1:-}"
# белые узлы wa, wb; NAT: na (PR), nb (PR), nf (FC: проброс порта на hf), nsy (SYM), ncg (CGNAT);
# за ними хосты ha, hb, hf, hs, hc
NSL=(i wa wb na nb nf nsy ncg ha hb hf hs hc)
RD=""
declare -A NODE_REAL=() NODE_WRAP=()
BG_REAL=""; BG_WRAP=""

log() { echo "[stage13.sh] $*" >&2; }
nsx() { local ns="$1"; shift; ip netns exec "chv13-$ns" "$@"; }
spk_in() { local ns="$1"; shift; nsx "$ns" env -i PATH="$PATH" "$@"; }
mkdirs() { mkdir -p "$LOGS"; }

# ---------------------------------------------------------------- сборка
do_build() {
  log "cargo build (вне ns)"
  ( cd "$REPO"
    cargo build --release --locked -p chervo-connect --example node13
  ) >&2
  mkdir -p "$BIN"
  cp "$REPO/target/release/examples/node13" "$NODE"
}

# ---------------------------------------------------------------- стенд
do_teardown() {
  set +e
  local n
  for n in "${NSL[@]}"; do
    if ip netns list 2>/dev/null | grep -q "^chv13-$n\b"; then
      ip netns pids "chv13-$n" 2>/dev/null | xargs -r kill 2>/dev/null
    fi
  done
  sleep 0.5
  for n in "${NSL[@]}"; do
    ip netns del "chv13-$n" 2>/dev/null
    rm -rf "/etc/netns/chv13-$n"
  done
  set -e
}

vl() { # ns1 if1 ns2 if2
  ip link add "$2" netns "chv13-$1" type veth peer name "$4" netns "chv13-$3"
}

ipn() { local ns="$1"; shift; ip -n "chv13-$ns" "$@"; }

# NAT-правила: ns, тип (PR | FC | SYM), LAN-подсеть, внутренний host:port для FC.
# PR: порт сохраняется, входящее пускается только в ответ (EIM/APDF). FC: плюс проброс udp/4433 на хост.
# SYM: masquerade fully-random (порт зависит от назначения, EDM).
nat_load() {
  local ns="$1" type="$2" lan="$3" host="${4:-}"
  local masq="masquerade" pre=""
  case "$type" in
    PR) ;;
    FC) pre="iifname \"wan\" udp dport $PORT dnat ip to $host" ;;
    SYM) masq="masquerade fully-random" ;;
    *) echo "тип NAT: $type" >&2; return 1 ;;
  esac
  nsx "$ns" nft flush ruleset
  nsx "$ns" nft -f - <<NFT
table inet nat13 {
  chain pre {
    type nat hook prerouting priority dstnat;
    $pre
  }
  chain post {
    type nat hook postrouting priority srcnat;
    oifname "wan" ip saddr $lan $masq
  }
  chain fwd13 {
    type filter hook forward priority filter; policy drop;
    iifname "lan" oifname "wan" accept
    iifname "wan" ct state established,related accept
    iifname "wan" ct status dnat accept
  }
  chain inp13 {
    type filter hook input priority filter;
    iifname "wan" drop
  }
}
NFT
}

do_setup() {
  do_teardown
  log "setup netns"
  local n p
  for n in "${NSL[@]}"; do
    ip netns add "chv13-$n"
    ipn "$n" link set lo up
  done
  ipn i link add core0 type bridge
  for n in wa wb na nb nf nsy ncg; do
    vl "$n" wan i "p-$n"
    ipn i link set "p-$n" master core0
  done
  ipn i addr add "$CORE.254/24" dev core0
  ipn wa addr add "$CORE.50/24" dev wan
  ipn wb addr add "$CORE.51/24" dev wan
  ipn na addr add "$CORE.10/24" dev wan
  ipn nf addr add "$CORE.20/24" dev wan
  ipn nb addr add "$CORE.30/24" dev wan
  ipn ncg addr add "$CORE.40/24" dev wan
  ipn nsy addr add "$CORE.60/24" dev wan
  # LAN: ha-na, hb-nb, hf-nf, hs-nsy, hc-ncg (за ncg адреса 100.64.0.0/10: CGNAT)
  vl na lan ha eth0;  ipn na addr add 192.168.10.1/24 dev lan;  ipn ha addr add 192.168.10.2/24 dev eth0
  vl nb lan hb eth0;  ipn nb addr add 192.168.30.1/24 dev lan;  ipn hb addr add 192.168.30.2/24 dev eth0
  vl nf lan hf eth0;  ipn nf addr add 192.168.20.1/24 dev lan;  ipn hf addr add 192.168.20.2/24 dev eth0
  vl nsy lan hs eth0; ipn nsy addr add 192.168.60.1/24 dev lan; ipn hs addr add 192.168.60.2/24 dev eth0
  vl ncg lan hc eth0; ipn ncg addr add 100.64.0.1/10 dev lan;   ipn hc addr add 100.64.0.2/10 dev eth0
  for n in "${NSL[@]}"; do
    local ifs
    ifs="$(ipn "$n" -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$')"
    for p in $ifs; do ipn "$n" link set "$p" up; done
  done
  ipn i link set core0 up
  # маршрут по умолчанию нужен зонду маршрута (connect без отправки); пакетов на 192.0.2.1 быть не должно
  for n in wa wb na nb nf nsy ncg; do ipn "$n" route add default via "$CORE.254"; done
  ipn ha route add default via 192.168.10.1
  ipn hb route add default via 192.168.30.1
  ipn hf route add default via 192.168.20.1
  ipn hs route add default via 192.168.60.1
  ipn hc route add default via 100.64.0.1
  for n in na nb nf nsy ncg; do nsx "$n" sysctl -qw net.ipv4.ip_forward=1; done
  # смена адреса в строке addrchange: без этого удаление основного адреса снесёт и вторичный
  nsx wa sysctl -qw net.ipv4.conf.all.promote_secondaries=1 net.ipv4.conf.wan.promote_secondaries=1
  # DNS-заглушка: любой запрос к резолверу виден счётчиком dns
  for n in wa wb ha hb hf hs hc; do
    mkdir -p "/etc/netns/chv13-$n"
    echo "nameserver 192.0.2.53" > "/etc/netns/chv13-$n/resolv.conf"
  done
  nat_load na PR 192.168.10.0/24
  nat_load nb PR 192.168.30.0/24
  nat_load nf FC 192.168.20.0/24 "192.168.20.2:$PORT"
  nat_load nsy SYM 192.168.60.0/24
  nat_load ncg PR 100.64.0.0/10
  log "стенд готов"
}

# Счётчики исходящего трафика узла: допустимые получатели (peers) отдельно от всего прочего.
# dns: порты 53 и 853; probe: адреса зонда маршрута (192.0.2.1, 2001:db8::1); other: всё остальное.
nft_guard() { # ns peers4(через запятую)
  local ns="$1" p4="$2" P6="" ND6="" M6=""
  # IPv6 в ядре может быть выключен (как в stage9.sh): тогда правила IPv6 не загружаются
  if [[ -e /proc/net/if_inet6 ]]; then
    P6='ip6 daddr 2001:db8::1 counter name "probe"'
    ND6='icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } counter name "nd" accept'
    M6='icmpv6 type mld2-listener-report counter name "mcast_kernel" accept'
  fi
  nsx "$ns" nft flush ruleset 2>/dev/null || true
  nsx "$ns" nft -f - <<NFT
table inet chv13g {
  set peers4 { type ipv4_addr; elements = { $p4 } }
  counter dns { }
  counter probe { }
  counter peer { }
  counter nd { }
  counter mcast_kernel { }
  counter other { }
  chain output {
    type filter hook output priority 0; policy accept;
    th dport { 53, 853 } counter name "dns"
    oifname "lo" accept
    ip daddr 192.0.2.1 counter name "probe"
    $P6
    ip daddr @peers4 counter name "peer" accept
    $ND6
    $M6
    ip protocol igmp counter name "mcast_kernel" accept
    counter name "other" accept
  }
}
NFT
}

cnt() { # файл-счётчиков имя
  awk -v n="$2" '$1 == "counter" && $2 == n { f = 1 } f && $1 == "packets" { print $2; exit }' "$1"
}

# Итог счётчиков узла: пустая строка, если dns = probe = other = 0 и peer > 0; иначе список нарушений.
guard_fail() { # ns метка
  local ns="$1" f="$RD/nft-$2.txt" v out=""
  nsx "$ns" nft list counters > "$f"
  for v in dns probe other; do
    [[ "$(cnt "$f" "$v")" == 0 ]] || out+="$v@$2=$(cnt "$f" "$v") "
  done
  [[ "$(cnt "$f" peer)" -gt 0 ]] || out+="peer@$2=0 "
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

node_start() { # метка ns args...
  local label="$1" ns="$2"; shift 2
  bg_start "$RD/$label.pid" "$ns" sh -c 'exec env -i PATH="$PATH" "$@" >"$0" 2>"$0.err"' "$RD/$label.log" "$NODE" "$@"
  NODE_REAL[$label]="$BG_REAL"
  NODE_WRAP[$label]="$BG_WRAP"
}

node_wait() { { wait "${NODE_WRAP[$1]}"; } 2>/dev/null || true; }
node_kill() { bg_stop "${NODE_REAL[$1]:-}" "${NODE_WRAP[$1]:-}"; }

# Ждёт строку в логе узла; 0 — нашлась, 1 — нет за secs.
wait_grep() { # метка regex secs
  local f="$RD/$1.log" i
  for i in $(seq 1 "$(( $3 * 5 ))"); do
    grep -Eq "$2" "$f" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

res_ok() { grep -q '^RESULT ok' "$RD/$1.log" 2>/dev/null; }
last_state() { grep '^STATE ' "$RD/$1.log" 2>/dev/null | tail -n 1 || true; }

row_begin() {
  mkdirs
  RD="$LOGS/$1"; rm -rf "$RD"; mkdir -p "$RD"
  [[ -x "$NODE" ]] || do_build
  ip netns list | grep -q '^chv13-i\b' || do_setup
}

row_end() {
  local l
  for l in "${!NODE_REAL[@]}"; do node_kill "$l"; done
  NODE_REAL=(); NODE_WRAP=()
}

verdict() { # СТРОКА PASS|FAIL|INCONCLUSIVE|NOTRUN причина
  mkdirs; touch "$SUMMARY"
  grep -v "^$1 " "$SUMMARY" > "$SUMMARY.tmp" || true
  mv "$SUMMARY.tmp" "$SUMMARY"
  echo "$1 $2 ${RD#"$ROOT"/} $3" >> "$SUMMARY"
  log "$1 $2: $3"
}

# ---------------------------------------------------------------- строки
# white-white: оба узла с белым IP, приглашение, соединение, счётчики узла A
row_white() {
  row_begin white
  local f=""
  nft_guard wa "$CORE.51"
  node_start wa wa --port $PORT --book-dir "$RD/wa" --invite-out "$RD/inv" --sas-auto-confirm \
    --expect-connected 1 --deadline 90 --hold 5
  node_start wb wb --port $PORT --book-dir "$RD/wb" --invite-in "$RD/inv" --sas-auto-confirm \
    --expect-connected 1 --deadline 90 --hold 5
  node_wait wa; node_wait wb
  res_ok wa || f+="wa_not_connected "
  res_ok wb || f+="wb_not_connected "
  f+="$(guard_fail wa wa)"
  row_end
  if [[ -n "${f// /}" ]]; then verdict WHITE FAIL "$f"
  else verdict WHITE PASS "белый-белый: соединение есть у обоих; у wa получатели только друг (счётчики dns, probe, other равны 0)"
  fi
}

# forward(FC)-PR: hf за NAT с пробросом (настройка --forward) учится внешнему IP у белого друга wa, выдаёт
# приглашение с адресом IP:проброс; hb за PR-NAT принимает и звонит
row_forward() {
  row_begin forward
  local f="" path=""
  nft_guard hb "$CORE.20"
  node_start wa wa --port $PORT --book-dir "$RD/wa" --invite-out "$RD/inv1" --sas-auto-confirm \
    --expect-connected 1 --deadline 120 --hold 20
  node_start hf hf --port $PORT --forward $PORT --book-dir "$RD/hf" --invite-in "$RD/inv1" \
    --invite-out "$RD/inv2" --sas-auto-confirm --expect-connected 2 --deadline 120 --hold 20
  node_start hb hb --port $PORT --book-dir "$RD/hb" --invite-in "$RD/inv2" --sas-auto-confirm \
    --expect-connected 1 --deadline 120 --hold 20
  node_wait wa; node_wait hf; node_wait hb
  res_ok wa || f+="wa_not_connected "
  res_ok hf || f+="hf_not_connected "
  res_ok hb || f+="hb_not_connected "
  path="$(grep '^EVENT connected' "$RD/hb.log" | head -n 1 | kv x path || true)"
  f+="$(guard_fail hb hb)"
  row_end
  # вид пути приблизительный (спецификация 13, «Path kind»): ожидается PortMapped, расхождение только в тексте
  if [[ -n "${f// /}" ]]; then verdict FORWARD FAIL "$f"
  else verdict FORWARD PASS "forward-PR: соединение есть, вид пути у hb: ${path:-нет}; ожидался PortMapped (расхождение не провал)"
  fi
}

# PR-PR через общего белого друга: НЕ ВЫПОЛНЯЕТСЯ. Чтобы два узла за PR-NAT открыли путь одновременным
# открытием, каждому нужен адрес другого. Адрес друга другому не передаётся (запрет спецификации), токен
# обновления адреса выпускается только по набору публикации `PublishSet`, который вне chervo-addr построить
# нельзя, а у узла стенда нет аргументов для токенов. Приглашение между двумя узлами за PR-NAT не получится:
# звонить может только приглашённый, а пригласивший не знает адреса приглашённого.
# Нужно решение архитектора/владельца (например, публичный выпуск токена обновления для стенда).
row_prpr() {
  RD="$LOGS/prpr"; mkdirs; rm -rf "$RD"; mkdir -p "$RD"
  verdict PRPR NOTRUN "не выполняется: у узла стенда нет способа передать узлу адрес другого узла (см. комментарий в stage13.sh)"
}

# SYM: hs за symmetric NAT принимает приглашения двух белых друзей, видит разные порты и называет
# SymmetricNat; затем друг wa пропадает, и после трёх неудач программа сообщает причину.
# Часть «SYM-PR: нет соединения» здесь не проверяется (дружбу SYM-PR создать нечем, как и PR-PR).
row_sym() {
  row_begin sym
  local f=""
  node_start wa wa --port $PORT --book-dir "$RD/wa" --invite-out "$RD/inva" --sas-auto-confirm \
    --expect-connected 1 --deadline 120 --hold 600
  node_start wb wb --port $PORT --book-dir "$RD/wb" --invite-out "$RD/invb" --sas-auto-confirm \
    --expect-connected 1 --deadline 120 --hold 600
  node_start hs hs --port $PORT --book-dir "$RD/hs" --invite-in "$RD/inva" --invite-in "$RD/invb" \
    --sas-auto-confirm --expect-connected 2 --deadline 120 --hold 600
  wait_grep hs '^RESULT ok' 120 || f+="hs_not_connected "
  if [[ -z "$f" ]]; then
    wait_grep hs '^STATE .*nat_view=Symmetric' 60 || f+="hs_nat_view_not_symmetric($(last_state hs)) "
    node_kill wa
    wait_grep hs '^EVENT unreachable .*reason=SymmetricNat' 360 || f+="no_symmetric_diagnosis "
  fi
  row_end
  if [[ -n "${f// /}" ]]; then verdict SYM FAIL "$f"
  else verdict SYM PASS "hs: nat_view=Symmetric (разные порты у двух друзей), после потери друга unreachable reason=SymmetricNat; SYM-PR не проверялось"
  fi
}

# CGNAT: hc с адресом 100.64.0.2 за ncg; BehindCgnat, подсказка про посредника, ни одного пакета не к другу
row_cgnat() {
  row_begin cgnat
  local f=""
  nft_guard hc "$CORE.50"
  node_start wa wa --port $PORT --book-dir "$RD/wa" --invite-out "$RD/inv" --sas-auto-confirm \
    --expect-connected 1 --deadline 120 --hold 600
  node_start hc hc --port $PORT --book-dir "$RD/hc" --invite-in "$RD/inv" --sas-auto-confirm \
    --expect-connected 1 --deadline 120 --hold 600
  wait_grep hc '^RESULT ok' 120 || f+="hc_not_connected "
  if [[ -z "$f" ]]; then
    wait_grep hc '^STATE .*nat_view=BehindCgnat' 60 || f+="hc_nat_view_not_cgnat($(last_state hc)) "
    node_kill wa
    wait_grep hc '^EVENT unreachable .*reason=BehindCgnat rendezvous_could_help=true' 360 || f+="no_cgnat_diagnosis "
  fi
  f+="$(guard_fail hc hc)"
  row_end
  if [[ -n "${f// /}" ]]; then verdict CGNAT FAIL "$f"
  else verdict CGNAT PASS "hc: nat_view=BehindCgnat, unreachable reason=BehindCgnat rendezvous_could_help=true; получатели только друг (dns, probe, other равны 0)"
  fi
}

# UDP закрыт на ha (nft, оба направления) после того, как ha подружился с wa и wb: UdpBlockedSuspected
row_udp() {
  row_begin udp
  local f=""
  node_start wa wa --port $PORT --book-dir "$RD/wa" --invite-out "$RD/inva" --sas-auto-confirm \
    --expect-connected 1 --deadline 120 --hold 900
  node_start wb wb --port $PORT --book-dir "$RD/wb" --invite-out "$RD/invb" --sas-auto-confirm \
    --expect-connected 1 --deadline 120 --hold 900
  node_start ha ha --port $PORT --book-dir "$RD/ha" --invite-in "$RD/inva" --invite-in "$RD/invb" \
    --sas-auto-confirm --expect-connected 2 --deadline 120 --hold 900 --udp-window 60
  wait_grep ha '^RESULT ok' 120 || f+="ha_not_connected "
  if [[ -z "$f" ]]; then
    nsx ha nft -f - <<NFT
table inet chv13blk {
  chain out { type filter hook output priority -10; policy accept; meta l4proto udp drop; }
  chain inp13 { type filter hook input priority -10; policy accept; meta l4proto udp drop; }
}
NFT
    wait_grep ha '^EVENT unreachable .*reason=UdpBlockedSuspected' 600 || f+="no_udp_blocked_diagnosis($(grep '^EVENT unreachable' "$RD/ha.log" | tail -n 1 || true)) "
  fi
  row_end
  if [[ -n "${f// /}" ]]; then verdict UDP FAIL "$f"
  else verdict UDP PASS "ha: после закрытия UDP у обоих друзей нет ответа, unreachable reason=UdpBlockedSuspected"
  fi
}

# Смена адреса wa посреди соединения (ip addr add/del): соединение живёт или набирается заново за 15 с,
# друг получает новый адрес (ADDR_INFO)
row_addrchange() {
  row_begin addrchange
  local f="" st=""
  node_start wa wa --port $PORT --book-dir "$RD/wa" --invite-out "$RD/inv" --sas-auto-confirm \
    --expect-connected 1 --deadline 90 --hold 60
  node_start wb wb --port $PORT --book-dir "$RD/wb" --invite-in "$RD/inv" --sas-auto-confirm \
    --expect-connected 1 --deadline 90 --hold 60
  wait_grep wa '^RESULT ok' 90 || f+="wa_not_connected "
  wait_grep wb '^RESULT ok' 90 || f+="wb_not_connected "
  if [[ -z "$f" ]]; then
    sleep 12   # окно между обновлениями адреса по соединению (10 с)
    ipn wa addr add "$CORE.52/24" dev wan
    ipn wa addr del "$CORE.50/24" dev wan
    wait_grep wa '^EVENT own_addrs_changed' 10 || f+="wa_no_own_addrs_changed "
    sleep 15
    st="$(last_state wa)"; [[ "$st" == *"connected=1"* ]] || f+="wa_not_connected_after_15s($st) "
    st="$(last_state wb)"; [[ "$st" == *"connected=1"* ]] || f+="wb_not_connected_after_15s($st) "
    wait_grep wb "^STATE .*friend#1=\\[[^]]*$CORE\\.52:$PORT" 20 || f+="wb_no_new_address "
  fi
  node_wait wa; node_wait wb
  row_end
  if [[ -n "${f// /}" ]]; then verdict ADDRCHANGE FAIL "$f"
  else verdict ADDRCHANGE PASS "после смены адреса соединение у обоих живо через 15 с, wb знает новый адрес wa"
  fi
}

kv() { sed -n "s/.* $2=\([^ ]*\).*/\1/p" | head -n1; }

# ---------------------------------------------------------------- вход
need_privs() {
  [[ "$(id -u)" == 0 ]] || { echo "INCONCLUSIVE: нужен root (netns, nftables)" >&2; exit 3; }
  command -v ip >/dev/null && command -v nft >/dev/null \
    || { echo "INCONCLUSIVE: нужны ip и nft" >&2; exit 3; }
}

TEARDOWN_ON_EXIT=0
cleanup() {
  local l
  for l in "${!NODE_REAL[@]}"; do node_kill "$l"; done
  if [[ "$TEARDOWN_ON_EXIT" == 1 ]]; then do_teardown || true; fi
  if [[ "$STATE_OWNED" == 1 && "${CHV_KEEP:-0}" != 1 && -n "$STATE" && "$STATE" != / ]]; then rm -rf -- "$STATE"; fi
}
trap cleanup EXIT
case "$CMD" in
  teardown) need_privs; do_teardown ;;
  white) need_privs; row_white ;;
  forward) need_privs; row_forward ;;
  prpr) need_privs; row_prpr ;;
  sym) need_privs; row_sym ;;
  cgnat) need_privs; row_cgnat ;;
  udp) need_privs; row_udp ;;
  addrchange) need_privs; row_addrchange ;;
  all)
    need_privs
    TEARDOWN_ON_EXIT=1
    mkdirs
    row_white; row_forward; row_prpr; row_sym; row_cgnat; row_udp; row_addrchange
    echo "--- $SUMMARY"; cat "$SUMMARY"
    do_teardown
    TEARDOWN_ON_EXIT=0
    ;;
  *) echo "использование: stage13.sh <white|forward|prpr|sym|cgnat|udp|addrchange|all|teardown>" >&2; exit 2 ;;
esac
