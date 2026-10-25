#!/usr/bin/env bash
# Стенд netns этапа 13в (поиск друзей в локальной сети, спецификация docs/specs/stage-13v-lan.md, раздел 11).
# Использование:
#   sudo bash tools/netns/stage13v.sh <lan1|lanoff|stranger|spoof|iface|portscan|hostsafe|all|teardown>
# Требуется Linux, root, ip, nft, cargo (сборка идёт вне ns). Для строк с захватом (iface, spoof, replay в stranger)
# нужен tcpdump; нет tcpdump: эти части NOTRUN, не PASS. Каталог логов: CHV_LOGS=/путь (по умолчанию logs13v).
#
# НЕ ПРОГОНЯЛСЯ: написан на Windows-машине (там нет ни netns, ни nft); проверено только `bash -n`. Первый прогон
# на Linux-машине владельца почти наверняка потребует правок самого стенда, как и у стендов 13, 13а, 14, 16.
#
# Отличие от текста спецификации (раздел 11, LAN1): узел стенда `node13` держит ключи пар в оперативной памяти и не
# переживает перезапуск, поэтому «остановить оба, сменить адреса, запустить оба» заменено на «сменить адреса у
# работающих узлов» (`ip addr flush`; старое соединение оборвётся по таймауту QUIC, поиск в LAN должен найти новые
# адреса). Узлы запускаются с --lan с самого начала (флаг читается только при старте). Проверка та же: после смены
# адресов соединение возвращается по пути Lan, и без записей о новых адресах в книге.
#
# Сеть: мост br0 (внутри ns br) без роутера, хосты a и b (узлы, 192.168.77.2 и .3, после смены .12 и .13),
# c (чужой, .4), d (молчащий, .5); второй мост br1 (10.9.0.0/24) с хостом e и вторым интерфейсом хоста a.
# Функции log, nsx, bg_start, bg_stop, node_*, wait_grep, verdict взяты из stage13.sh (префикс ns chv13v-).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
STATE_OWNED=0
if [[ -n "${CHV_STATE:-}" ]]; then
  STATE="$CHV_STATE"
  [[ ! -L "$STATE" ]] || { echo "CHV_STATE не должен быть символьной ссылкой" >&2; exit 2; }
  if [[ -e "$STATE" ]]; then
    [[ -d "$STATE" && "$(stat -c %u -- "$STATE")" == "$(id -u)" ]] || { echo "CHV_STATE не каталог или не принадлежит текущему пользователю" >&2; exit 2; }
  fi
  mkdir -p -- "$STATE"
  chmod 700 -- "$STATE"
else
  STATE="$(mktemp -d /tmp/chervo-stage13v.XXXXXX)"
  chmod 700 -- "$STATE"
  STATE_OWNED=1
fi
LOGS="${CHV_LOGS:-$ROOT/logs13v}"
BIN="$STATE/bin"
NODE="$BIN/node13"
PORT=4433
GROUP=239.255.112.47
GPORT=47131
SUMMARY="$LOGS/summary13v.txt"
CMD="${1:-}"
NSL=(br a b c d e)
RD=""
CAP_PID=""
declare -A NODE_REAL=() NODE_WRAP=()
BG_REAL=""; BG_WRAP=""

log() { echo "[stage13v.sh] $*" >&2; }
nsx() { local ns="$1"; shift; ip netns exec "chv13v-$ns" "$@"; }
ipn() { local ns="$1"; shift; ip -n "chv13v-$ns" "$@"; }
mkdirs() { mkdir -p "$LOGS"; }
have() { command -v "$1" >/dev/null 2>&1; }

do_build() {
  log "cargo build (вне ns)"
  ( cd "$REPO"
    cargo build --release --locked -p chervo-connect --example node13
  ) >&2
  mkdir -p "$BIN"
  cp "$REPO/target/release/examples/node13" "$NODE"
}

do_teardown() {
  set +e
  local n
  for n in "${NSL[@]}"; do
    if ip netns list 2>/dev/null | grep -q "^chv13v-$n\b"; then
      ip netns pids "chv13v-$n" 2>/dev/null | xargs -r kill 2>/dev/null
    fi
  done
  sleep 0.5
  for n in "${NSL[@]}"; do
    ip netns del "chv13v-$n" 2>/dev/null
    rm -rf "/etc/netns/chv13v-$n"
  done
  set -e
}

# host ns, мост, интерфейс в хосте, адрес/маска
attach() {
  local ns="$1" br="$2" ifn="$3" cidr="$4" pn="v-$1-$3"
  ip link add "$ifn" netns "chv13v-$ns" type veth peer name "$pn" netns "chv13v-br"
  ipn br link set "$pn" master "$br"
  ipn br link set "$pn" up
  ipn "$ns" addr add "$cidr" dev "$ifn"
  ipn "$ns" link set "$ifn" up
}

do_setup() {
  do_teardown
  log "setup netns"
  local n
  for n in "${NSL[@]}"; do
    ip netns add "chv13v-$n"
    ipn "$n" link set lo up
  done
  ipn br link add br0 type bridge
  ipn br link add br1 type bridge
  # без IGMP-прослушивания моста: маяки идут всем портам, как в простой домашней сети
  ipn br link set br0 type bridge mcast_snooping 0
  ipn br link set br1 type bridge mcast_snooping 0
  ipn br link set br0 up
  ipn br link set br1 up
  attach a br0 eth0 192.168.77.2/24
  attach b br0 eth0 192.168.77.3/24
  attach c br0 eth0 192.168.77.4/24
  attach d br0 eth0 192.168.77.5/24
  attach a br1 eth1 10.9.0.1/24
  attach e br1 eth0 10.9.0.2/24
  # маршрут по умолчанию нужен зонду маршрута (connect без отправки); такого шлюза нет, пакетов на него не будет
  for n in a b c d; do ipn "$n" route add default via 192.168.77.1; done
  ipn c route add 224.0.0.0/4 dev eth0
  for n in a b c d e; do
    mkdir -p "/etc/netns/chv13v-$n"
    echo "nameserver 192.0.2.53" > "/etc/netns/chv13v-$n/resolv.conf"
  done
  log "стенд готов"
}

# Счётчики исходящего трафика узла a или b. peers4: все адреса друга (до и после смены).
# grp: датаграммы на группу; badttl: на группу с TTL не 1; badlen: на группу с длиной UDP не 565 (557 + 8);
# igmp: IGMP; igmp_bad: IGMP не на 224.0.0.22; unreach: ICMP «порт недоступен» (ядро, PORTSCAN);
# dns, probe, other: всё прочее (должно быть 0). Входящие счётчики (положительные контроли): rx_grp: датаграммы
# на группу; rx_c, rx_d: те же с адресов c и d.
nft_guard() { # ns peers4(через запятую)
  local ns="$1" p4="$2"
  nsx "$ns" nft flush ruleset 2>/dev/null || true
  nsx "$ns" nft -f - <<NFT
table inet chv13vg {
  set peers4 { type ipv4_addr; elements = { $p4 } }
  counter grp { }
  counter badttl { }
  counter badlen { }
  counter igmp { }
  counter igmp_bad { }
  counter unreach { }
  counter peer { }
  counter dns { }
  counter probe { }
  counter v6 { }
  counter other { }
  counter rx_grp { }
  counter rx_c { }
  counter rx_d { }
  chain input {
    type filter hook input priority 0; policy accept;
    ip daddr $GROUP udp dport $GPORT counter name "rx_grp"
    ip saddr 192.168.77.4 ip daddr $GROUP counter name "rx_c"
    ip saddr 192.168.77.5 ip daddr $GROUP counter name "rx_d"
  }
  chain output {
    type filter hook output priority 0; policy accept;
    oifname "lo" accept
    th dport { 53, 853 } counter name "dns"
    ip daddr 192.0.2.1 counter name "probe"
    ip daddr $GROUP ip ttl != 1 counter name "badttl"
    ip daddr $GROUP udp length != 565 counter name "badlen"
    ip daddr $GROUP udp dport $GPORT counter name "grp" accept
    ip protocol igmp ip daddr != 224.0.0.22 counter name "igmp_bad"
    ip protocol igmp counter name "igmp" accept
    ip daddr @peers4 counter name "peer" accept
    icmp type destination-unreachable counter name "unreach" accept
    meta nfproto ipv6 counter name "v6" accept
    counter name "other" accept
  }
}
NFT
}

cnt() { # файл-счётчиков имя
  awk -v n="$2" '$1 == "counter" && $2 == n { f = 1 } f && $1 == "packets" { print $2; exit }' "$1"
}

snap() { # ns метка: сохранить счётчики, вернуть путь
  local f="$RD/nft-$2.txt"
  nsx "$1" nft list counters > "$f"
  echo "$f"
}

# Нарушения счётчиков узла: пустая строка, если badttl = badlen = igmp_bad = dns = probe = other = 0.
guard_fail() { # ns метка
  local f v out=""
  f="$(snap "$1" "$2")"
  for v in badttl badlen igmp_bad dns probe other; do
    [[ "$(cnt "$f" "$v")" == 0 ]] || out+="$v@$2=$(cnt "$f" "$v") "
  done
  echo "$out"
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

node_start() { # метка ns args...
  local label="$1" ns="$2"; shift 2
  bg_start "$RD/$label.pid" "$ns" sh -c 'exec env -i PATH="$PATH" "$@" >"$0" 2>"$0.err"' "$RD/$label.log" "$NODE" "$@"
  NODE_REAL[$label]="$BG_REAL"
  NODE_WRAP[$label]="$BG_WRAP"
}

node_kill() { bg_stop "${NODE_REAL[$1]:-}" "${NODE_WRAP[$1]:-}"; }

wait_grep() { # метка regex secs
  local f="$RD/$1.log" i
  for i in $(seq 1 "$(( $3 * 5 ))"); do
    grep -Eq "$2" "$f" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

# Число событий connected в логе узла и вид пути последнего.
n_conn() { grep -c '^EVENT connected' "$RD/$1.log" 2>/dev/null || true; }
last_path() { grep '^EVENT connected' "$RD/$1.log" 2>/dev/null | tail -n 1 | sed -n 's/.* path=\([^ ]*\).*/\1/p'; }

row_begin() {
  mkdirs
  RD="$LOGS/$1"; rm -rf "$RD"; mkdir -p "$RD"
  [[ -x "$NODE" ]] || do_build
  ip netns list | grep -q '^chv13v-br\b' || do_setup
}

row_end() {
  local l
  for l in "${!NODE_REAL[@]}"; do node_kill "$l"; done
  NODE_REAL=(); NODE_WRAP=()
  # захват tcpdump (если ещё ждёт маяк) и правила хоста c (snat) не переходят в следующую строку
  if [[ -n "$CAP_PID" ]]; then kill "$CAP_PID" 2>/dev/null || true; { wait "$CAP_PID"; } 2>/dev/null || true; CAP_PID=""; fi
  nsx c nft flush ruleset 2>/dev/null || true
  # адреса хостов возвращаются в исходные для следующей строки
  ipn a addr flush dev eth0 2>/dev/null || true; ipn a addr add 192.168.77.2/24 dev eth0 2>/dev/null || true
  ipn b addr flush dev eth0 2>/dev/null || true; ipn b addr add 192.168.77.3/24 dev eth0 2>/dev/null || true
  ipn a link set eth0 up 2>/dev/null || true
  for l in a b; do ipn "$l" route add default via 192.168.77.1 2>/dev/null || true; done
}

verdict() { # СТРОКА PASS|FAIL|INCONCLUSIVE|NOTRUN причина
  mkdirs; touch "$SUMMARY"
  grep -v "^$1 " "$SUMMARY" > "$SUMMARY.tmp" || true
  mv "$SUMMARY.tmp" "$SUMMARY"
  echo "$1 $2 ${RD#"$ROOT"/} $3" >> "$SUMMARY"
  log "$1 $2: $3"
}

# Дружба a-b (приглашение по адресу LAN) и первое соединение; флаги узлов: $1 (например --lan).
# Возвращает 0, если оба узла дали RESULT ok.
befriend_ab() { # флаги...
  nft_guard a "192.168.77.3,192.168.77.13"
  nft_guard b "192.168.77.2,192.168.77.12"
  node_start a a --port $PORT --book-dir "$RD/a" --invite-out "$RD/inv" --invite-addr "192.168.77.2:$PORT" \
    --sas-auto-confirm --expect-connected 1 --deadline 90 --hold 600 "$@"
  node_start b b --port $PORT --book-dir "$RD/b" --invite-in "$RD/inv" \
    --sas-auto-confirm --expect-connected 1 --deadline 90 --hold 600 "$@"
  wait_grep a '^RESULT ok' 90 && wait_grep b '^RESULT ok' 90
}

# Оба хоста получают новые адреса (.2 -> .12, .3 -> .13).
change_ips() {
  ipn a addr flush dev eth0; ipn a addr add 192.168.77.12/24 dev eth0; ipn a route add default via 192.168.77.1
  ipn b addr flush dev eth0; ipn b addr add 192.168.77.13/24 dev eth0; ipn b route add default via 192.168.77.1
}

# Ждёт нового соединения (число событий выросло) у обоих узлов; печатает секунды или пусто.
wait_reconnect() { # n_a n_b secs
  local i
  for i in $(seq 1 "$3"); do
    if [[ "$(n_conn a)" -gt "$1" && "$(n_conn b)" -gt "$2" ]]; then echo "$i"; return 0; fi
    sleep 1
  done
  return 1
}

# ---------------------------------------------------------------- строки
row_lan1() {
  row_begin lan1
  local f="" na nb t=""
  if ! befriend_ab --lan --expect-path lan; then f+="not_connected_first "; fi
  if [[ -z "$f" ]]; then
    na="$(n_conn a)"; nb="$(n_conn b)"
    change_ips
    t="$(wait_reconnect "$na" "$nb" 240)" || f+="no_reconnect_after_ip_change "
    [[ -z "$t" ]] || { [[ "$(last_path a)" == Lan && "$(last_path b)" == Lan ]] || f+="path_not_lan(a=$(last_path a) b=$(last_path b)) "; }
    local fa; fa="$(snap a lan1a)"
    [[ "$(cnt "$fa" grp)" -gt 0 ]] || f+="a_sent_no_beacons "
    [[ "$(cnt "$fa" badttl)" == 0 && "$(cnt "$fa" badlen)" == 0 ]] || f+="bad_ttl_or_len "
  fi
  f+="$(guard_fail a lan1a)$(guard_fail b lan1b)"
  row_end
  if [[ -n "${f// /}" ]]; then verdict LAN1 FAIL "$f"
  else verdict LAN1 PASS "после смены адресов обоих хостов соединение вернулось по пути Lan за ${t}s; на группу только 565-байтные (557 UDP) пакеты с TTL 1; кроме друга, группы и IGMP 224.0.0.22 ничего не уходило"
  fi
}

row_lanoff() {
  row_begin lanoff
  local f="" na nb fa
  if ! befriend_ab; then f+="not_connected_first "; fi
  if [[ -z "$f" ]]; then
    na="$(n_conn a)"; nb="$(n_conn b)"
    change_ips
    sleep 60
    [[ "$(n_conn a)" == "$na" && "$(n_conn b)" == "$nb" ]] || f+="reconnected_without_lan "
    fa="$(snap a lanoffa)"
    [[ "$(cnt "$fa" grp)" == 0 ]] || f+="beacons_sent_with_lan_off(grp=$(cnt "$fa" grp)) "
    [[ "$(cnt "$fa" igmp)" == 0 ]] || f+="igmp_with_lan_off(igmp=$(cnt "$fa" igmp)) "
    fa="$(snap b lanoffb)"
    [[ "$(cnt "$fa" grp)" == 0 && "$(cnt "$fa" igmp)" == 0 ]] || f+="b_group_traffic_with_lan_off "
  fi
  f+="$(guard_fail a lanoffa)$(guard_fail b lanoffb)"
  row_end
  if [[ -n "${f// /}" ]]; then verdict LANOFF FAIL "$f"
  else verdict LANOFF PASS "без --lan за 60 с после смены адресов соединения нет; ни одного пакета на группу, ни одного IGMP"
  fi
}

# Счётчики хоста c (положительные контроли: без них строка не может быть PASS):
# c_grp: его исходящие на группу; c_uni: его одноадресные на a:GPORT; unreach: входящие ICMP «порт недоступен».
# Вызывать до загрузки правил snat (flush ruleset их сотрёт).
c_nft_setup() {
  nsx c nft flush ruleset 2>/dev/null || true
  nsx c nft -f - <<NFT
table inet chv13vc {
  counter c_grp { }
  counter c_uni { }
  counter unreach { }
  chain input { type filter hook input priority 0; policy accept; icmp type destination-unreachable counter name "unreach"; }
  chain output {
    type filter hook output priority 0; policy accept;
    ip daddr $GROUP udp dport $GPORT counter name "c_grp"
    ip daddr 192.168.77.2 udp dport $GPORT counter name "c_uni"
  }
}
NFT
}

# Шлёт датаграммы на группу с хоста c: файл-образец, число секунд; печатает число отправленных.
# ВСЁ внутри ns c (nsx): ни один пакет не выходит в корневое пространство имён хоста.
flood_from_c() { # payload secs
  nsx c bash -c 'exec 7>"/dev/udp/$0/$1"; end=$((SECONDS+$3)); n=0
    while ((SECONDS<end)); do cat -- "$2" >&7; n=$((n+1)); done; echo "$n"' "$GROUP" "$GPORT" "$1" "$2"
}

# Число из файла счётчиков nft (пусто или нет такого: 0).
cnt0() { local v; v="$(cnt "$1" "$2")"; echo "${v:-0}"; }

row_stranger() {
  row_begin stranger
  local f="" na nb t="" sent="" cap="$RD/replay.bin" replay=0 cf="" cg=0 rxc=0
  head -c 557 /dev/urandom > "$RD/rand.bin"
  c_nft_setup
  if have tcpdump && have xxd; then
    # маяк a, снятый чужим хостом: байты после заголовков IP (20) и UDP (8)
    nsx c tcpdump -i eth0 -nn -c 1 -x "udp and dst host $GROUP and dst port $GPORT and src host 192.168.77.2" \
      > "$RD/cap.txt" 2>/dev/null &
    CAP_PID=$!
  fi
  if ! befriend_ab --lan; then f+="not_connected_first "; fi
  if [[ -z "$f" ]]; then
    if [[ -s "$RD/cap.txt" ]]; then
      grep -E '^\s+0x' "$RD/cap.txt" | sed -E 's/^\s+0x[0-9a-f]+:\s+//; s/ //g' | tr -d '\n' \
        | cut -c 57- | xxd -r -p > "$cap" || true
      [[ "$(stat -c %s -- "$cap" 2>/dev/null || echo 0)" == 557 ]] && replay=1
    fi
    na="$(n_conn a)"; nb="$(n_conn b)"
    change_ips
    # 20 с потока случайных 557-байтных датаграмм; потом (если есть) повтор маяка a со своего адреса c
    sent="$(flood_from_c "$RD/rand.bin" 20)"
    if [[ "$replay" == 1 ]]; then flood_from_c "$cap" 5 >/dev/null; fi
    log "stranger: отправлено случайных датаграмм: $sent (за 20 с)"
    t="$(wait_reconnect "$na" "$nb" 30)" || f+="no_reconnect_within_30s_after_flood "
    [[ "$(n_conn a)" -gt "$na" ]] || true
  fi
  f+="$(guard_fail a stra)$(guard_fail b strb)"
  # положительные контроли: c действительно слал на группу (его счётчик), и b это принял (его счётчик)
  cf="$(snap c strc)"; cg="$(cnt0 "$cf" c_grp)"; rxc="$(cnt0 "$RD/nft-strb.txt" rx_c)"
  row_end
  if [[ -n "${f// /}" ]]; then verdict STRANGER FAIL "$f"
  elif [[ "$cg" -lt 1 || "$rxc" -lt 1 ]]; then verdict STRANGER INCONCLUSIVE "нет доказательства потока: c_grp=$cg, rx_c на b=$rxc (поток не дошёл до b или не отправлялся)"
  elif [[ "$replay" != 1 ]]; then verdict STRANGER INCONCLUSIVE "поток дошёл до b (c_grp=$cg, rx_c=$rxc), a и b чужому ничего не слали, но повтор маяка не выполнялся (нужны tcpdump и xxd)"
  else verdict STRANGER PASS "поток ${sent} датаграмм и повтор маяка a с адреса c (c_grp=$cg, у b rx_c=$rxc): a и b чужому ничего не слали (other = 0), соединение вернулось за ${t}s после потока"
  fi
}

# C повторяет маяк a с исходным адресом d (nft snat в ns c): b не должен слать d ни одного пакета.
# Маяк живёт только эпоху ±1 (около двух минут); если до повтора он устарел, строка INCONCLUSIVE.
row_spoof() {
  row_begin spoof
  local f="" cap="$RD/replay.bin" age0 age cf="" cg=0 rxd=0
  if ! have tcpdump || ! have xxd; then
    verdict SPOOF NOTRUN "нужны tcpdump и xxd"
    return 0
  fi
  c_nft_setup
  nsx c tcpdump -i eth0 -nn -c 1 -x "udp and dst host $GROUP and dst port $GPORT and src host 192.168.77.2" \
    > "$RD/cap.txt" 2>/dev/null &
  CAP_PID=$!
  if ! befriend_ab --lan; then f+="not_connected_first "; fi
  if [[ -z "$f" ]]; then
    age0=$SECONDS
    wait_grep a '^EVENT lan_attached ok=true' 5 || f+="a_lan_not_attached "
    sleep 3
    grep -E '^\s+0x' "$RD/cap.txt" | sed -E 's/^\s+0x[0-9a-f]+:\s+//; s/ //g' | tr -d '\n' \
      | cut -c 57- | xxd -r -p > "$cap" || true
    [[ "$(stat -c %s -- "$cap" 2>/dev/null || echo 0)" == 557 ]] || f+="no_beacon_captured "
  fi
  if [[ -z "$f" ]]; then
    # a пропадает с сети: b теряет соединение, и пара становится «ожидаемой»
    ipn a link set eth0 down
    wait_grep b '^EVENT disconnected' 100 || f+="b_still_connected "
    age=$(( SECONDS - age0 ))
    if [[ -z "$f" && "$age" -gt 100 ]]; then f+="beacon_too_old(${age}s) "; fi
  fi
  if [[ -z "$f" ]]; then
    nsx c nft -f - <<NFT
table ip chv13vsnat {
  chain post { type nat hook postrouting priority srcnat; ip daddr $GROUP udp dport $GPORT snat to 192.168.77.5; }
}
NFT
    flood_from_c "$cap" 5 >/dev/null
    sleep 5
  fi
  f+="$(guard_fail b spoofb)"
  # положительные контроли: c слал на группу, snat сработал (b принял датаграммы с адресом d)
  cf="$(snap c spoofc)"; cg="$(cnt0 "$cf" c_grp)"; rxd="$(cnt0 "$RD/nft-spoofb.txt" rx_d)"
  row_end
  if [[ "$f" == *beacon_too_old* || "$f" == *b_still_connected* || "$f" == *no_beacon_captured* ]]; then verdict SPOOF INCONCLUSIVE "$f (повторить)"
  elif [[ -n "${f// /}" ]]; then verdict SPOOF FAIL "$f"
  elif [[ "$cg" -lt 1 || "$rxd" -lt 1 ]]; then verdict SPOOF INCONCLUSIVE "подмена не доказана: c_grp=$cg, rx_d на b=$rxd (snat не сработал или маяк не дошёл)"
  else verdict SPOOF PASS "маяк a с подменённым источником d дошёл до b (rx_d=$rxd, c_grp=$cg): b не отправил d ни одного пакета (other = 0)"
  fi
}

# У a второй интерфейс br1 (не маршрут по умолчанию); слушатель e в той же сети br1: маяков 0.
row_iface() {
  row_begin iface
  local f="" n=0
  if ! have tcpdump; then
    verdict IFACE NOTRUN "нужен tcpdump"
    return 0
  fi
  nsx e tcpdump -i eth0 -nn -l "udp and dst port $GPORT" > "$RD/e.txt" 2>/dev/null &
  local tp=$!
  sleep 1
  if ! befriend_ab --lan; then f+="not_connected_first "; fi
  sleep 70   # не меньше одного периода маяков (60 ± 10 с) после дружбы
  kill "$tp" 2>/dev/null || true; { wait "$tp"; } 2>/dev/null || true
  n="$(grep -c "$GPORT" "$RD/e.txt" 2>/dev/null || true)"
  [[ "$n" == 0 ]] || f+="e_received_${n}_datagrams "
  f+="$(guard_fail a ifa)"
  row_end
  if [[ -n "${f// /}" ]]; then verdict IFACE FAIL "$f"
  else verdict IFACE PASS "хост e в br1 (не маршрут по умолчанию a) получил 0 маяков за 70 с после дружбы"
  fi
}

# Одноадресная датаграмма на порт поиска: ядро отвечает ICMP «порт недоступен» (сокет привязан к группе), a ничего больше не шлёт c.
row_portscan() {
  row_begin portscan
  local f="" u=0 cu=0
  if ! befriend_ab --lan; then f+="not_connected_first "; fi
  c_nft_setup
  # одна одноадресная датаграмма из ns c (не из корневого пространства имён хоста)
  nsx c bash -c 'exec 8>"/dev/udp/$0/$1"; printf x >&8' 192.168.77.2 "$GPORT"
  sleep 2
  nsx c nft list counters > "$RD/nft-c.txt"
  u="$(cnt0 "$RD/nft-c.txt" unreach)"
  cu="$(cnt0 "$RD/nft-c.txt" c_uni)"
  [[ "$u" -ge 1 ]] || f+="c_got_no_icmp_unreachable "
  f+="$(guard_fail a psa)"
  row_end
  if [[ -n "${f// /}" ]]; then
    if [[ "$cu" -lt 1 ]]; then verdict PORTSCAN INCONCLUSIVE "c ничего не отправил (c_uni=0): $f"
    else verdict PORTSCAN FAIL "$f"
    fi
  else verdict PORTSCAN PASS "одноадресный пакет c -> a:$GPORT (c_uni=$cu): c получил ICMP port unreachable ($u), других пакетов a к c нет"
  fi
}

# Сеть хоста не тронута (как в стендах 16 и 17): снимок до и после.
host_snapshot() { { ip -o addr; ip route; ip -o link; nft list ruleset 2>/dev/null || true; } | sort; }

row_hostsafe() {
  mkdirs; RD="$LOGS/hostsafe"; rm -rf "$RD"; mkdir -p "$RD"
  [[ -n "${HOST_BEFORE:-}" ]] || { verdict HOSTSAFE NOTRUN "снимок до стенда не сделан (запускать через all)"; return 0; }
  host_snapshot > "$RD/after.txt"
  if diff -q "$HOST_BEFORE" "$RD/after.txt" >/dev/null; then verdict HOSTSAFE PASS "адреса, маршруты, интерфейсы и nft хоста не изменились"
  else cp "$HOST_BEFORE" "$RD/before.txt"; verdict HOSTSAFE FAIL "сеть хоста изменилась (diff before/after в каталоге строки)"
  fi
}

need_privs() {
  [[ "$(id -u)" == 0 ]] || { echo "INCONCLUSIVE: нужен root (netns, nftables)" >&2; exit 3; }
  have ip && have nft || { echo "INCONCLUSIVE: нужны ip и nft" >&2; exit 3; }
}

TEARDOWN_ON_EXIT=0
cleanup() {
  local l
  for l in "${!NODE_REAL[@]}"; do node_kill "$l"; done
  if [[ "$TEARDOWN_ON_EXIT" == 1 ]]; then do_teardown || true; fi
  if [[ "$STATE_OWNED" == 1 && "${CHV_KEEP:-0}" != 1 && -n "$STATE" && "$STATE" != / ]]; then rm -rf -- "$STATE"; fi
}
trap cleanup EXIT
HOST_BEFORE=""
case "$CMD" in
  teardown) need_privs; do_teardown ;;
  lan1) need_privs; row_lan1 ;;
  lanoff) need_privs; row_lanoff ;;
  stranger) need_privs; row_stranger ;;
  spoof) need_privs; row_spoof ;;
  iface) need_privs; row_iface ;;
  portscan) need_privs; row_portscan ;;
  hostsafe) need_privs; row_hostsafe ;;
  all)
    need_privs
    TEARDOWN_ON_EXIT=1
    mkdirs
    HOST_BEFORE="$STATE/host-before.txt"
    host_snapshot > "$HOST_BEFORE"
    row_lan1; row_lanoff; row_stranger; row_spoof; row_iface; row_portscan
    do_teardown
    TEARDOWN_ON_EXIT=0
    row_hostsafe
    echo "--- $SUMMARY"; cat "$SUMMARY"
    ;;
  *) echo "использование: stage13v.sh <lan1|lanoff|stranger|spoof|iface|portscan|hostsafe|all|teardown>" >&2; exit 2 ;;
esac
