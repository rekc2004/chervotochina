#!/usr/bin/env bash
# Стенд netns этапа 13в: поиск друзей в локальной сети (свой маяк), строки LAN1-LAN11, CAPTURE и HOSTSAFE
# по docs/specs/stage-13v-lan.md (раздел L6 и дополнение 1).
# Использование (root, Linux):
#   sudo CHV_NODE16=/путь/к/node16 bash tools/netns/stage13v.sh <LAN1..LAN11|LAN3-17|CAPTURE|all|teardown>
# Сборка узла (обычный пользователь, вне стенда): cargo build --release -p chervo-transfer --example node16
#   и CHV_NODE16=target/release/examples/node16. CAPTURE считается по записи LAN1 и запускается вместе с ней.
# Нужны: Linux, root, ip, nft, tcpdump, python3 (pcap13v.py лежит рядом), cargo не нужен (узел собран заранее).
# Переменные: CHV_NODE16 (обязательна), CHV_LOGS (по умолчанию tools/netns/logs13v), CHV_STATE, CHV_KEEP=1,
#   LAN3_SECS (600, окно записи маяков), LAN8_BURST_S (4, предел до первого маяка с нового адреса, с; решение дирижёра:
#   опрос смены адреса движком раз в 2 с и серия через 1 с в 2 с не укладываются).
#
# НЕ ЗАПУСКАЛСЯ НА LINUX СБОРЩИКОМ (not run on Linux by the builder): на машине сборки (Windows) проверен только
# `bash -n`, pcap13v.py проверен на синтетическом pcap. Прогон на Linux делает дирижёр или владелец. Ожидания строк взяты
# из спецификации и не подгоняются; строка, которую нельзя оценить, получает INCONCLUSIVE, а не PASS.
#
# Безопасность (умный дом на той же машине): только ns chv13v-*, все nft/sysctl/tcpdump и python3 с отправкой пакетов
# запускаются через `ip netns exec`; на хосте не меняется ничего, кроме создания и удаления своих ns и каталогов
# /etc/netns/chv13v-*; снимок хоста до и после каждой команды (HOSTSAFE). В реальную сеть ничего не уходит.
#
# Топология (192.168.50.0/24 и 192.168.60.0/24, адреса «интернета» не нужны):
#   sw : мост br0 (коммутатор домашней сети; без IGMP-snooping: иначе мост без адреса сам объявляет себя в группе
#        224.0.0.106 отчётом IGMPv3 с адреса 0.0.0.0, и этот чужой пакет попадает в записи узлов, см. LAN2)
#   a : 192.168.50.11 (узел A), b : .12 (узел B), o : .99 (наблюдатель O, он же отправитель потока и подделок),
#   r : маршрутизатор .1 (eth0 в br0) и 192.168.60.1 (eth1), c : 192.168.60.11 за маршрутизатором (узел C).
# Книги: A и B дружат (приглашение A -> B), метки: у A друг o1 (B), у B друг i1 (A). Для LAN3-17 у A ещё 16 друзей
# (вспомогательные узлы в ns o, метки o2..o17). Книги делаются один раз на команду и копируются в каждую строку.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
# shellcheck source=lib16.sh
source "$ROOT/lib16.sh"
# lib16.sh хозяйничает с префиксом chv16-: у этого стенда свои пространства имён и свои сообщения
PFX="chv13v-"
NSL=(sw a b o r c)
log() { echo "[stage13v.sh] $*" >&2; }

LOGS="${CHV_LOGS:-$ROOT/logs13v}"
SUMMARY="$LOGS/summary13v.tsv"
HSTSV="$LOGS/hostsafe13v.tsv"
CMD="${1:-}"
LAN_PORT=45817
A_IP=192.168.50.11
B_IP=192.168.50.12
O_IP=192.168.50.99
PORT_OLD=4433
PORT_NEW=4444
LAN3_SECS="${LAN3_SECS:-600}"
LAN8_BURST_S="${LAN8_BURST_S:-4}"
STARTED=0
ROW_ID=""
DL=900
PYT=""
declare -A CAP_REAL=() CAP_WRAP=()

# ---------------------------------------------------------------- вход, проверки
need_root() {
  [[ "$(id -u)" == 0 ]] || { echo "INCONCLUSIVE: нужен root (netns, nftables)" >&2; exit 3; }
  local t
  for t in ip nft tcpdump python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "INCONCLUSIVE: нужен $t" >&2; exit 3; }
  done
}

bins_import() {
  bin_import CHV_NODE16 node16 1 || { echo "INCONCLUSIVE: CHV_NODE16 не принят" >&2; exit 3; }
  NODE="$BIN/node16"
  cp -- "$ROOT/pcap13v.py" "$BIN/pcap13v.py" || { echo "INCONCLUSIVE: нет pcap13v.py" >&2; exit 3; }
  chmod 644 -- "$BIN/pcap13v.py"
  PYT="$BIN/pcap13v.py"
}

# ---------------------------------------------------------------- HOSTSAFE
HS_DIR=""
hostsafe_begin() { HS_DIR="$STATE/hs"; rm -rf -- "$HS_DIR"; snap_take "$HS_DIR/a"; }
hostsafe_check() { # метка
  local d
  [[ -n "$HS_DIR" ]] || return 0
  snap_take "$HS_DIR/b"
  d="$(snap_diff "$HS_DIR/a" "$HS_DIR/b")"
  if [[ -n "${d// /}" ]]; then
    mkdir -p -- "$LOGS"
    rm -rf -- "$LOGS/hostsafe-fail"; cp -r -- "$HS_DIR" "$LOGS/hostsafe-fail" 2>/dev/null || true
    printf '%s\t%s\t%s\t%s\n' "$(date +%F)" "$1" FAIL "$d" >> "$HSTSV"
    vd HOSTSAFE ctl FAIL "хост изменился" "после $1: $d"
    echo "HOSTSAFE FAIL после $1: изменилось на хосте: $d. Остановка, хост не чинится; сообщите дирижёру (logs13v/hostsafe-fail)." >&2
    exit 5
  fi
  return 0
}
hostsafe_end() { # метка команды
  hostsafe_check "$1"
  printf '%s\t%s\t%s\t%s\n' "$(date +%F)" "$1" PASS "-" >> "$HSTSV"
  local n
  n="$(awk -F'\t' '$3 == "PASS"' "$HSTSV" 2>/dev/null | wc -l)"
  vd HOSTSAFE ctl PASS "до и после ${n} команд: nft хоста, ссылки, ns, ip_forward без изменений" "nft сравнивается без счётчиков и наборов"
}

# ---------------------------------------------------------------- топология
topo_body() {
  set -e
  local n
  for n in "${NSL[@]}"; do
    ip netns add "$PFX$n"
    ipn "$n" link set lo up
  done
  ipn sw link add br0 type bridge mcast_snooping 0
  ipn sw link set br0 up
  for n in a b o r; do
    vl "$n" eth0 sw "p-$n"
    ipn sw link set "p-$n" master br0
    ipn sw link set "p-$n" up
    ipn "$n" link set eth0 up
  done
  ipn a addr add "$A_IP/24" dev eth0
  ipn b addr add "$B_IP/24" dev eth0
  ipn o addr add "$O_IP/24" dev eth0
  ipn r addr add 192.168.50.1/24 dev eth0
  vl r eth1 c eth0
  ipn r addr add 192.168.60.1/24 dev eth1
  ipn c addr add 192.168.60.11/24 dev eth0
  ipn r link set eth1 up
  ipn c link set eth0 up
  nsx r sysctl -qw net.ipv4.ip_forward=1
  ipn a route add default via 192.168.50.1 dev eth0 metric 100
  ipn b route add default via 192.168.50.1 dev eth0 metric 100
  ipn c route add default via 192.168.60.1 dev eth0
}

# Туннель VPN на A: обманка tun0 с адресом и маршрутом по умолчанию метрики 0 (дешевле домашнего).
vpn_on() { # cidr
  ipn a link add tun0 type dummy
  ipn a link set tun0 up multicast on
  ipn a addr add "$1" dev tun0
  ipn a route add default dev tun0 metric 0
}

row_begin() { # id кап_секунд
  local rc
  [[ "$1" =~ ^[A-Za-z0-9-]+$ ]] || die "плохой id строки: $1"
  ROW_ID="$1"
  RD="$LOGS/$1"; rm -rf -- "$RD"; mkdir -p -- "$RD"
  W="$STATE/$1"; rm -rf -- "$W"; mkdir -p -- "$W"
  ROW_END=$(( $(now_s) + $2 ))
  DL=$(( $2 + 60 ))
  NODE_REAL=(); NODE_WRAP=(); CAP_REAL=(); CAP_WRAP=()
  NODE_NICE=0
  mkdir -p -- "$LOGS"
  do_teardown
  ( topo_body ) >> "$RD/setup.log" 2>&1; rc=$?
  if [[ $rc != 0 ]]; then log "$1: топология не поднялась (см. setup.log)"; return 1; fi
  return 0
}

row_end() {
  nodes_stop_all
  local c
  for c in "${!CAP_REAL[@]}"; do cap_stop "$c"; done
  do_teardown
  hostsafe_check "$ROW_ID"
}

# ---------------------------------------------------------------- узлы и записи
node_args() { # метка порт [дополнительно...]
  local l="$1" p="$2"; shift 2
  mkdir -p -- "$W/$l/dest" "$W/$l/partial"
  NA=(--port "$p" --book-dir "$W/$l" --dest "$W/$l/dest" --partial "$W/$l/partial" --sas-auto-confirm
      --diag-every 5 --stop-file "$W/$l.stop" --deadline "$DL" "$@")
}
a_start() { # режим порт [дополнительно...]
  local mode="$1" port="$2"; shift 2
  node_args a "$port" --lan "$mode" --dump-pubkeys "$W/pubkeys-a" "$@"
  node_start a a "${NA[@]}"
}
b_start() { # режим порт [дополнительно...]
  local mode="$1" port="$2"; shift 2
  node_args b "$port" --lan "$mode" "$@"
  node_start b b "${NA[@]}"
}

cap_start() { # метка ns интерфейс фильтр
  bg_start "$RD/$1.cap.pid" "$2" tcpdump -i "$3" -nn -U -s 0 -w "$RD/$1.pcap" "$4"
  CAP_REAL[$1]="$BG_REAL"; CAP_WRAP[$1]="$BG_WRAP"
  sleep 1
}
cap_stop() { bg_stop "${CAP_REAL[$1]:-}" "${CAP_WRAP[$1]:-}"; }
# число UDP-пакетов записи по полям (src= dst= sport= dport= len=)
cap_count() { # метка поле=значение...
  local l="$1"; shift
  python3 -I "$PYT" count "$RD/$l.pcap" "$@" 2>/dev/null || echo "?"
}
cap_total() { # метка
  python3 -I "$PYT" tsv "$RD/$1.pcap" 2>/dev/null | wc -l
}

# Дождаться, пока строка не кончится или не пройдёт n секунд (нужные узлы работают).
hold() { # секунды
  local i
  for i in $(seq 1 "$(( $1 * 5 ))"); do over_cap && return 1; sleep 0.2; done
  return 0
}

# ---------------------------------------------------------------- книги
# Книга A с n друзьями и книга B (друг A). Живут в $STATE/books-<n>; в строку копируются.
books_make() { # n
  local n="$1" dest="$STATE/books-$1" k ok=1 args=()
  [[ -d "$dest/a" ]] && return 0
  row_begin "books-$n" 600 || return 1
  for k in $(seq 1 "$n"); do args+=(--invite-out "$W/a/inv-$k"); done
  node_args a "$PORT_OLD" "${args[@]}" --invite-lan
  node_start a a "${NA[@]}"
  node_args b "$PORT_OLD" --invite-in "$W/b/inv"
  node_start b b "${NA[@]}"
  deliver "$W/a/inv-1" "$W/b/inv" 60 || ok=0
  if [[ $ok == 1 ]]; then
    wait_grep b '^EVENT (invite_finished pair=i1 outcome=Added|connected pair=i1 )' 60 || ok=0
    wait_grep a '^EVENT connected pair=o1 ' 60 || ok=0
  fi
  for k in $(seq 2 "$n"); do
    [[ $ok == 1 ]] || break
    node_args "h$k" "$((5000 + k))" --invite-in "$W/h$k/inv"
    node_start "h$k" o "${NA[@]}"
    deliver "$W/a/inv-$k" "$W/h$k/inv" 60 || { ok=0; break; }
    wait_grep a "^EVENT connected pair=o$k " 60 || ok=0
  done
  nodes_stop_all
  if [[ $ok == 1 ]]; then
    mkdir -p -- "$dest"
    cp -a -- "$W/a" "$dest/a" && cp -a -- "$W/b" "$dest/b"
    # узлы вышли: ключи и книги записаны
  fi
  do_teardown
  [[ $ok == 1 ]] || { log "книги для n=$n не собраны (см. $RD)"; return 1; }
  return 0
}
books_copy() { # n
  rm -rf -- "$W/a" "$W/b"
  cp -a -- "$STATE/books-$1/a" "$W/a" && cp -a -- "$STATE/books-$1/b" "$W/b"
}

# Подготовка строки: топология и копия книг.
lan_row() { # id кап_секунд n
  books_make "$3" || return 1
  row_begin "$1" "$2" || return 1
  books_copy "$3" || { log "$1: книги не скопированы"; return 1; }
  return 0
}

# ---------------------------------------------------------------- строки
connected_lan() { # метка секунды: B видит A по сети, путь Lan
  wait_grep "$1" '^EVENT connected pair=i1 path=Lan ' "$2"
}

row_lan1() {
  lan_row LAN1 150 1 || { vd LAN1 lan INCONCLUSIVE "-" "топология или книги"; return 0; }
  cap_start capa a any 'udp or igmp'
  b_start listen "$PORT_OLD"
  local t0 dt
  t0="$(now_s)"
  a_start announce "$PORT_NEW"
  if connected_lan b 40; then
    dt=$(( $(now_s) - t0 ))
    vd LAN1 lan PASS "B Connected{Lan} за ${dt} с (≤ 40)" "A на новом порту $PORT_NEW, адрес A в книге B устарел"
  else
    vd LAN1 lan FAIL "нет Connected{Lan} за 40 с" "один набор на пару за раз: идущий набор по устаревшему адресу задерживает набор по находке (решение дирижёра)"
  fi
  # CAPTURE по записи A: получатели, DNS, 5353, 1900
  sleep 2
  cap_stop capa
  capture_verdict capa
  row_end
}

capture_verdict() { # метка записи A
  local l="$1" dsts bad="" d dns mdns ssdp
  python3 -I "$PYT" tsv "$RD/$l.pcap" 2>/dev/null > "$RD/$l.tsv"
  dsts="$(awk -v a="$A_IP" '$2 == a && $4 == 17 { print $3 ":" $6 }' "$RD/$l.tsv" | sort -u)"
  for d in $dsts; do
    case "$d" in
      "224.0.0.1:$LAN_PORT") ;;
      "$B_IP":*) ;;
      *) bad+="$d " ;;
    esac
  done
  dns="$(awk -v a="$A_IP" '$2 == a && $4 == 17 && ($6 == 53 || $6 == 853)' "$RD/$l.tsv" | wc -l)"
  mdns="$(awk -v a="$A_IP" '$2 == a && $4 == 17 && $6 == 5353' "$RD/$l.tsv" | wc -l)"
  ssdp="$(awk -v a="$A_IP" '$2 == a && $4 == 17 && $6 == 1900' "$RD/$l.tsv" | wc -l)"
  if [[ -n "$bad" || "$dns" != 0 || "$mdns" != 0 || "$ssdp" != 0 ]]; then
    vd CAPTURE lan FAIL "лишние назначения: ${bad:-нет}; DNS $dns, 5353 $mdns, 1900 $ssdp" "запись A во время LAN1"
  elif [[ -z "$dsts" ]]; then
    vd CAPTURE lan INCONCLUSIVE "в записи нет UDP от A" "запись пуста"
  else
    vd CAPTURE lan PASS "назначения A: $(echo "$dsts" | tr '\n' ' ')" "DNS 0, 5353 0, 1900 0"
  fi
}

row_lan2() {
  lan_row LAN2 150 1 || { vd LAN2 lan INCONCLUSIVE "-" "топология или книги"; return 0; }
  cap_start capa a any "udp dst port $LAN_PORT or igmp"
  cap_start capb b any "udp dst port $LAN_PORT or igmp"
  a_start listen 4455
  b_start listen 4466
  hold 70
  local conn udp igmp
  conn=$(( $(cntl a '^EVENT connected ') + $(cntl b '^EVENT connected ') ))
  udp=$(( $(cap_count capa dport=$LAN_PORT) + $(cap_count capb dport=$LAN_PORT) ))
  igmp="$(( $(cap_total capa) - $(cap_count capa dport=$LAN_PORT) + $(cap_total capb) - $(cap_count capb dport=$LAN_PORT) ))"
  cap_stop capa; cap_stop capb
  if [[ "$igmp" != 0 ]]; then
    # для разбора: кто послал, видно по источнику, группе и признаку исходящего (фильтр и порог не меняются)
    { echo "--- capa"; tcpdump -nn -e -v -r "$RD/capa.pcap" 2>&1; echo "--- capb"; tcpdump -nn -e -v -r "$RD/capb.pcap" 2>&1; } > "$RD/lan2-pkts.txt"
  fi
  if [[ "$conn" == 0 && "$udp" == 0 && "$igmp" == 0 ]]; then
    vd LAN2 lan PASS "70 с: соединений 0, датаграмм на порт маяка 0, IGMP 0" "оба узла «только слушать», адреса друг друга в книгах устарели"
  else
    vd LAN2 lan FAIL "соединений $conn, датаграмм на порт маяка $udp, IGMP/прочее $igmp" "режим «только слушать» ничего не шлёт"
  fi
  row_end
}

# n: число друзей у A (1 или 17)
row_lan3() { # n
  local n="$1" id="LAN3" rc
  [[ "$n" == 1 ]] || id="LAN3-$n"
  lan_row "$id" $(( LAN3_SECS + 120 )) "$n" || { vd "$id" lan INCONCLUSIVE "-" "топология или книги"; return 0; }
  cap_start capo o eth0 "udp dst port $LAN_PORT and src host $A_IP"
  a_start announce "$PORT_OLD"
  hold "$LAN3_SECS"
  cap_stop capo
  local out
  out="$(python3 -I "$PYT" lan3 "$RD/capo.pcap" "$W/pubkeys-a" "$A_IP" "$PORT_OLD" "$(hostname)" "$n" 2>&1)"; rc=$?
  printf '%s\n' "$out" > "$RD/lan3.txt"
  if [[ $rc == 0 && "$out" == OK* ]]; then
    vd "$id" lan PASS "$out" "запись ${LAN3_SECS} с, n=$n"
  elif [[ "$out" == *"ни одного маяка"* ]]; then
    vd "$id" lan INCONCLUSIVE "$out" "A не рассылал: запись пуста"
  else
    vd "$id" lan FAIL "$(echo "$out" | tr '\n' ';')" "см. lan3.txt"
  fi
  row_end
}

cpu_ticks() { # pid
  awk '{ print $14 + $15 }' "/proc/$1/stat" 2>/dev/null || echo 0
}

row_lan4() {
  lan_row LAN4 240 1 || { vd LAN4 lan INCONCLUSIVE "-" "топология или книги"; return 0; }
  cap_start capb o eth0 "udp and src host $B_IP and dst host $O_IP"
  cap_start capa o eth0 "udp dst port $LAN_PORT and src host $A_IP"
  b_start listen "$PORT_OLD"
  a_start announce "$PORT_NEW"
  # маяки A записаны за 20 с (серия 1, 3, 7 с и далее раз в 30 с); связь до потока допускается
  hold 20
  local c0 c1 t_flood
  c0="$(cpu_ticks "${NODE_REAL[b]:-0}")"
  t_flood="$(now_s)"
  nsx o python3 -I "$PYT" flood "$O_IP" 100000 > "$RD/flood.txt" 2>&1
  nsx o python3 -I "$PYT" replay "$RD/capa.pcap" "$O_IP" >> "$RD/flood.txt" 2>&1
  c1="$(cpu_ticks "${NODE_REAL[b]:-0}")"
  local cpu_ms=$(( (c1 - c0) * 1000 / ${CLK_TCK:-100} ))
  local flood_s=$(( $(now_s) - t_flood ))
  # после потока B должен найти A сам (если связь уже была до потока, она остаётся)
  local found=0
  if has b '^EVENT connected pair=i1 path=Lan '; then found=1
  elif connected_lan b 60; then found=1; fi
  cap_stop capb; cap_stop capa
  local to_o
  to_o="$(cap_count capb src=$B_IP dst=$O_IP)"
  if [[ "$found" == 1 && "$to_o" == 0 ]]; then
    vd LAN4 lan PASS "поток 100000 и повтор за ${flood_s} с: B->O пакетов 0, B нашёл A; CPU B ${cpu_ms} мс" "предел приёма 32 в секунду до разбора; запись CPU: ${cpu_ms} мс"
  else
    vd LAN4 lan FAIL "B->O пакетов ${to_o}, B нашёл A: ${found}; CPU B ${cpu_ms} мс" "поток не должен вызывать ответов и не должен лишать пути LAN"
  fi
  row_end
}

# Значение счётчика набора B на адрес A (пакеты, до разрешения ARP: A уже не отвечает).
dial_count() {
  local c
  c="$(nsx b nft list counter inet chv13v dial 2>/dev/null | awk '$1 == "packets" { print $2; exit }')"
  echo "${c:-0}"
}

# Длина IPv4-пакета со стуком: 20 (IP) + 8 (UDP) + 48 (KNOCK_LEN). Стук уходит три раза за один набор (0, 1 и 3 с);
# повторы рукопожатия QUIC (Initial с растущим шагом) и хвост прежнего соединения имеют другую длину.
KNOCK_IP_LEN=76

row_lan5() {
  lan_row LAN5 260 1 || { vd LAN5 lan INCONCLUSIVE "-" "топология или книги"; return 0; }
  # A и B соединиться не могут: A не набирает B (выход на B_IP закрыт) и не принимает набор на PORT_NEW. Иначе (прогон
  # cfc103f) живое соединение гасит находки, его хвост (PTO, keep-alive) шумит в счётчике, а запись маяков живёт
  # лишь около минуты после ухода A и успевает дать один набор. Маяки A идут весь срок.
  nsx a nft -f - <<NFT
table inet chv13v_blk {
  chain out { type filter hook output priority 0; policy accept; ip daddr $B_IP drop; }
  chain in { type filter hook input priority 0; policy accept; udp dport $PORT_NEW drop; }
}
NFT
  # Счётчик набора B считает только стуки (длина $KNOCK_IP_LEN) на адрес A; udp_all для разбора (все пакеты на этот порт).
  nsx b nft -f - <<NFT
table inet chv13v {
  counter dial { }
  counter udp_all { }
  chain out {
    type filter hook output priority 0; policy accept;
    ip daddr $A_IP udp dport $PORT_NEW counter name "udp_all"
    ip daddr $A_IP udp dport $PORT_NEW meta length $KNOCK_IP_LEN counter name "dial"
  }
}
NFT
  cap_start capa o eth0 "udp dst port $LAN_PORT and src host $A_IP"
  b_start listen "$PORT_OLD"
  # Счётчик читается каждые полсекунды с запуска A: начало набора = рост после 3 с без роста (стуки идут с шагом 1 и 2 с).
  # Первые 15 с идёт запись маяков, потом раз в 5 с их повтор с подставленным источником $A_IP поверх настоящих маяков A.
  local i c last=0 t0 now_t prev_change=-100 starts=() gap min_gap=999 k span
  t0="$(now_s)"
  a_start announce "$PORT_NEW"
  for i in $(seq 0 219); do
    if (( i == 30 )); then cap_stop capa; fi
    if (( i >= 30 && (i - 30) % 10 == 0 )); then
      nsx o python3 -I "$PYT" spoof "$RD/capa.pcap" "$A_IP" "$O_IP" >> "$RD/spoof.txt" 2>&1
    fi
    c="$(dial_count)"
    if (( c > last )); then
      now_t=$(( $(now_s) - t0 ))
      if (( now_t - prev_change > 3 )); then starts+=("$now_t"); fi
      prev_change=$now_t
      last="$c"
    fi
    sleep 0.5
  done
  span=$(( $(now_s) - t0 ))
  for (( k = 1; k < ${#starts[@]}; k++ )); do
    gap=$(( starts[k] - starts[k - 1] ))
    (( gap < min_gap )) && min_gap=$gap
  done
  nsx b nft list table inet chv13v > "$RD/dial.txt" 2>&1
  if (( $(cntl a '^EVENT connected ') + $(cntl b '^EVENT connected ') > 0 )); then
    vd LAN5 lan INCONCLUSIVE "узлы соединились, блокировка не сработала" "наборов нет при живом соединении; смотрите a.log, b.log"
  elif (( ${#starts[@]} < 2 )); then
    vd LAN5 lan INCONCLUSIVE "наборов (стуков) на $A_IP:$PORT_NEW за ${span} с: ${#starts[@]}, нужно не меньше двух" "один набор не проверяет промежуток; повторите"
  elif (( min_gap >= 31 )); then
    vd LAN5 lan PASS "наборов на $A_IP:$PORT_NEW за ${span} с: ${#starts[@]}, наименьший промежуток ${min_gap} с (≥ 31)" "ограничитель: строгий адрес не чаще раза в 32 с, находки идут каждые 5 с"
  else
    vd LAN5 lan FAIL "наборов ${#starts[@]}, промежуток ${min_gap} с (< 31)" "строгий предел 32 с на IP нарушен"
  fi
  row_end
}

row_lan6() {
  lan_row LAN6 150 1 || { vd LAN6 lan INCONCLUSIVE "-" "топология или книги"; return 0; }
  cap_start capc c eth0 "udp dst port $LAN_PORT"
  cap_start capo o eth0 "udp dst port $LAN_PORT and src host $A_IP"
  mkdir -p -- "$W/c"
  node_args c "$PORT_OLD" --lan listen
  node_start c c "${NA[@]}"
  a_start announce "$PORT_OLD"
  hold 70
  local at_c at_o
  at_c="$(cap_total capc)"; at_o="$(cap_count capo dport=$LAN_PORT)"
  cap_stop capc; cap_stop capo
  if [[ "$at_o" == 0 ]]; then
    vd LAN6 lan INCONCLUSIVE "A не рассылал: на наблюдателе маяков 0" "контрольная запись пуста"
  elif [[ "$at_c" == 0 ]]; then
    vd LAN6 lan PASS "C за маршрутизатором принял датаграмм 0 (в домашней сети маяков $at_o)" "маяк не пересекает маршрутизатор"
  else
    vd LAN6 lan FAIL "C принял датаграмм ${at_c}" "224.0.0.1 не должен выходить из домашней сети"
  fi
  row_end
}

row_lan7() {
  lan_row LAN7 150 1 || { vd LAN7 lan INCONCLUSIVE "-" "топология или книги"; return 0; }
  # адрес A не частный: документационный диапазон RFC 5737 (класс Documentation, не Private)
  ipn a addr flush dev eth0
  ipn a addr add 203.0.113.11/24 dev eth0
  ipn a route add default via 203.0.113.1 dev eth0 metric 100
  cap_start capa a any "udp dst port $LAN_PORT"
  cap_start capo o eth0 "udp dst port $LAN_PORT"
  a_start announce "$PORT_OLD"
  hold 70
  local n_a n_o
  n_a="$(cap_count capa dport=$LAN_PORT)"; n_o="$(cap_count capo dport=$LAN_PORT)"
  cap_stop capa; cap_stop capo
  if [[ "$n_a" == 0 && "$n_o" == 0 ]] && [[ "$(cntl a ' lan=NoPrivateRoute ')" -gt 0 ]]; then
    vd LAN7 lan PASS "70 с: маяков 0 (A и наблюдатель), состояние NoPrivateRoute (строки STATE)" "адрес по умолчанию 203.0.113.11 не частный"
  elif [[ "$n_a" == 0 && "$n_o" == 0 ]]; then
    vd LAN7 lan INCONCLUSIVE "маяков 0, но в строках STATE нет lan=NoPrivateRoute" "состояние службы не подтверждено"
  else
    vd LAN7 lan FAIL "маяков: A $n_a, наблюдатель $n_o" "с нечастным адресом по умолчанию маяк слать нельзя"
  fi
  row_end
}

row_lan8() {
  lan_row LAN8 200 1 || { vd LAN8 lan INCONCLUSIVE "-" "топология или книги"; return 0; }
  cap_start capo o eth0 "udp dst port $LAN_PORT and src host 192.168.50.21"
  b_start listen "$PORT_OLD"
  a_start announce "$PORT_OLD"
  connected_lan b 40 || { vd LAN8 lan INCONCLUSIVE "-" "B не нашёл A до смены адреса"; row_end; return 0; }
  hold 5
  local n_before t_change
  n_before="$(cntl b '^EVENT connected pair=i1 ')"
  # Без promote_secondaries удаление основного адреса уносит и добавленный после него в той же сети: A оставался без
  # адреса, а `route replace` падал с «Nexthop has invalid gateway» (прогон cfc103f). Опция только в ns A.
  nsx a sysctl -qw net.ipv4.conf.eth0.promote_secondaries=1
  t_change="$(date +%s.%N)"
  ipn a addr add 192.168.50.21/24 dev eth0
  ipn a addr del "$A_IP/24" dev eth0
  ipn a route replace default via 192.168.50.1 dev eth0 metric 100
  hold 45
  cap_stop capo
  local first dt reconnected
  first="$(python3 -I "$PYT" first-time "$RD/capo.pcap" 192.168.50.21 2>/dev/null || echo -)"
  reconnected=$(( $(cntl b '^EVENT connected pair=i1 ') - n_before ))
  if [[ "$first" == - ]]; then
    vd LAN8 lan FAIL "с нового адреса маяков нет" "ожидалась серия после смены адреса"
    row_end; return 0
  fi
  dt="$(awk -v a="$first" -v b="$t_change" 'BEGIN { printf "%.1f", a - b }')"
  if awk -v d="$dt" -v m="$LAN8_BURST_S" 'BEGIN { exit !(d <= m) }' && (( reconnected >= 1 )); then
    vd LAN8 lan PASS "первый маяк с нового адреса через ${dt} с (≤ ${LAN8_BURST_S}); B переподключался ${reconnected} раз" "время включает опрос смены адреса движком (2 с) и серию (1 с)"
  else
    vd LAN8 lan FAIL "первый маяк с нового адреса через ${dt} с (≤ ${LAN8_BURST_S}), переподключений ${reconnected}" "предел ${LAN8_BURST_S} с (решение дирижёра): опрос смены адреса движком раз в 2 с, затем серия через 1 с"
  fi
  row_end
}

# VPN: tun0 с адресом по умолчанию метрики 0 и домашний br0 дороже
row_vpn() { # id cidr
  lan_row "$1" 330 1 || { vd "$1" lan INCONCLUSIVE "-" "топология или книги"; return 0; }
  vpn_on "$2"
  cap_start capa a any 'udp dst port 9'
  b_start listen "$PORT_OLD"
  a_start announce "$PORT_NEW"
  local ok=0 sweeps
  connected_lan b 40 && ok=1
  # три прохода опроса маршрутов (раз в 60 с)
  hold 190
  sweeps="$(cap_count capa dport=9)"
  cap_stop capa
  if [[ $ok == 1 && "$sweeps" == 0 ]]; then
    vd "$1" lan PASS "B Connected{Lan} при маршруте по умолчанию в туннель $2; пакетов на цели опроса 0 за 190 с" "опрос только спрашивает систему, пакетов не шлёт"
  elif [[ $ok == 1 ]]; then
    vd "$1" lan FAIL "пакетов на цели опроса (порт 9): ${sweeps}" "опрос маршрутов не должен ничего отправлять"
  else
    vd "$1" lan FAIL "нет Connected{Lan} за 40 с при маршруте по умолчанию в туннель $2" "опрос должен найти домашний интерфейс"
  fi
  row_end
}

row_lan11() {
  lan_row LAN11 150 1 || { vd LAN11 lan INCONCLUSIVE "-" "топология или книги"; return 0; }
  vpn_on 172.18.0.1/30
  cap_start capa a any "udp dst port $LAN_PORT"
  cap_start capt a tun0 "udp"
  a_start listen "$PORT_OLD"
  hold 70
  local n_a n_t
  n_a="$(cap_count capa dport=$LAN_PORT)"; n_t="$(cap_total capt)"
  cap_stop capa; cap_stop capt
  if node_alive a && [[ "$n_a" == 0 && "$n_t" == 0 ]]; then
    vd LAN11 lan PASS "70 с «только слушать» при туннеле по умолчанию: датаграмм на порт маяка 0, на tun0 UDP 0" "ничего от кода поиска ни в tun0, ни в br0"
  else
    vd LAN11 lan FAIL "на порт маяка ${n_a}, UDP в tun0 ${n_t}" "режим «только слушать» ничего не шлёт"
  fi
  row_end
}

run_row() {
  case "$1" in
    LAN1) row_lan1 ;;
    LAN2) row_lan2 ;;
    LAN3) row_lan3 1 ;;
    LAN3-17) row_lan3 17 ;;
    LAN4) row_lan4 ;;
    LAN5) row_lan5 ;;
    LAN6) row_lan6 ;;
    LAN7) row_lan7 ;;
    LAN8) row_lan8 ;;
    LAN9) row_vpn LAN9 172.18.0.1/30 ;;
    LAN10) row_vpn LAN10 198.18.0.1/16 ;;
    LAN11) row_lan11 ;;
    CAPTURE) row_lan1 ;;
    *) return 2 ;;
  esac
}

usage() {
  echo "использование: stage13v.sh <LAN1..LAN11|LAN3-17|CAPTURE|all|teardown>" >&2
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
}

main() {
  case "$CMD" in
    ""|-h|--help) usage; exit 2 ;;
  esac
  need_root
  STARTED=1
  trap cleanup EXIT
  mkdir -p -- "$LOGS"
  if [[ "$CMD" == teardown ]]; then do_teardown; exit 0; fi
  state_init
  CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"
  bins_import
  hostsafe_begin
  case "$CMD" in
    all)
      local id
      for id in LAN1 LAN2 LAN3 LAN3-17 LAN4 LAN5 LAN6 LAN7 LAN8 LAN9 LAN10 LAN11; do run_row "$id"; done
      echo "--- $SUMMARY"; cat -- "$SUMMARY" ;;
    *)
      run_row "$CMD"
      if [[ $? == 2 ]]; then usage; exit 2; fi ;;
  esac
  hostsafe_end "$CMD"
}
main
