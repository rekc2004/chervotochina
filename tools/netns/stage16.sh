#!/usr/bin/env bash
# Стенд netns этапа 16: сетевые тесты (netns, nftables, tc netem) по docs/specs/stage-16-nettest.md.
# Использование (root, Linux):
#   sudo CHV_NODE16=... [CHV_SPIKE8=...] [CHV_MINIUPNPD=...] [CHV_NODE16_LIAR=...] bash tools/netns/stage16.sh <команда>
# Команды: preflight | natcheck | conn | speed | g7 | extra | quick | all | <id строки> | teardown | build-liar
#   id строки: C01..C20, V01..V05, G7-BASE, G7-CALLEE, G7-LAPTOP, G7-DROP15, S-<ПУТЬ>-<ПРОФИЛЬ> (S-WHITE-N0, S-LAN-N0,
#   S-UPNP-R1, S-PUNCH-N0 ...), X01 (идёт вместе с C06), X02, NATCHECK.
#   build-liar запускается от обычного пользователя (нужен cargo), остальное от root.
# Переменные: CHV_NODE16 (обязательна), CHV_SPIKE8 (NATCHECK), CHV_MINIUPNPD (C18, S-UPNP), CHV_NODE16_LIAR (X02);
#   CHV_LOGS (по умолчанию tools/netns/logs/stage16), CHV_STATE, CHV_KEEP=1, CHV_NICE (10; узлы строк скорости идут под
#   nice), CHV_REPEATS (3), CHV_WIN (240, окно наблюдения связности, с), CORE (11.0.0).
#
# НЕ ЗАПУСКАЛСЯ НА LINUX СБОРЩИКОМ (not run on Linux by the builder): на машине сборки (Windows) проверен только `bash -n`
# и самопроверка report16.sh. Прогон на Linux делает дирижёр. Ожидания строк взяты из спецификации и не подгоняются.
#
# Безопасность (умный дом на той же машине): только ns chv16-*, все nft/sysctl/tc/ethtool/tcpdump/miniupnpd через
# `ip netns exec`; STATE через mktemp -d (режим 700); бинарники из переменных окружения копируются в STATE/bin;
# снимок хоста до и после каждой команды и после каждой строки (HOSTSAFE); при выходе ns сносятся.
# Скрипт запускается без `set -e` намеренно: строка не должна ронять стенд; ошибки топологии ловятся отдельно.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
# shellcheck source=lib16.sh
source "$ROOT/lib16.sh"

LOGS="${CHV_LOGS:-$ROOT/logs/stage16}"
SUMMARY="$LOGS/summary16.tsv"
SPEEDTSV="$LOGS/speed16.tsv"
NATTSV="$LOGS/natcheck16.tsv"
HSTSV="$LOGS/hostsafe16.tsv"
CMD="${1:-}"
WIN="${CHV_WIN:-240}"
REPEATS="${CHV_REPEATS:-3}"
UUID="81c5ab36-606c-44f1-a3b0-5814b1dd7a01"
UDN="uuid:$UUID"
HAVE_SPIKE8=0; HAVE_MPD=0; HAVE_LIAR=0
STARTED=0
MPD_REAL=""; MPD_WRAP=""
TCPD_REAL=""; TCPD_WRAP=""
ROW_ID=""
DL=900
CLK_TCK=100

# ---------------------------------------------------------------- вход, проверки
need_root() {
  [[ "$(id -u)" == 0 ]] || { echo "INCONCLUSIVE: нужен root (netns, nftables)" >&2; exit 3; }
  command -v ip >/dev/null && command -v nft >/dev/null || { echo "INCONCLUSIVE: нужны ip и nft" >&2; exit 3; }
}

bins_import() {
  local rc
  bin_import CHV_NODE16 node16 1 || { echo "INCONCLUSIVE: CHV_NODE16 не принят" >&2; exit 3; }
  NODE="$BIN/node16"
  bin_import CHV_SPIKE8 spike8 0; rc=$?
  if [[ $rc == 0 ]]; then HAVE_SPIKE8=1; elif [[ $rc == 2 ]]; then exit 3; fi
  bin_import CHV_MINIUPNPD miniupnpd 0; rc=$?
  if [[ $rc == 0 ]]; then HAVE_MPD=1; elif [[ $rc == 2 ]]; then exit 3; fi
  bin_import CHV_NODE16_LIAR node16-liar 0; rc=$?
  if [[ $rc == 0 ]]; then HAVE_LIAR=1; elif [[ $rc == 2 ]]; then exit 3; fi
  return 0
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
    hostsafe_summary
    echo "HOSTSAFE FAIL после $1: изменилось на хосте: $d. Остановка, хост не чинится; сообщите дирижёру (логи в logs/stage16/hostsafe-fail)." >&2
    exit 5
  fi
  return 0
}
hostsafe_end() { # метка команды
  hostsafe_check "$1"
  printf '%s\t%s\t%s\t%s\n' "$(date +%F)" "$1" PASS "-" >> "$HSTSV"
  hostsafe_summary
}
hostsafe_summary() {
  local n f
  n="$(awk -F'\t' '$3 == "PASS"' "$HSTSV" 2>/dev/null | wc -l)"
  f="$(awk -F'\t' '$3 == "FAIL"' "$HSTSV" 2>/dev/null | wc -l)"
  if (( f > 0 )); then vd HOSTSAFE ctl FAIL "хост изменился" "см. hostsafe16.tsv"
  else vd HOSTSAFE ctl PASS "до и после ${n} команд: nft хоста, ссылки, ns, ip_forward без изменений" "nft сравнивается без счётчиков и наборов"
  fi
}

# ---------------------------------------------------------------- топология
topo_body() {
  set -e
  local n p ifs
  for n in "${NSL[@]}"; do
    ip netns add "$PFX$n"
    ipn "$n" link set lo up
  done
  ipn i link add core0 type bridge
  for n in wa wb m na na2 nb nr cg cg2; do
    vl "$n" wan i "p-$n"
    ipn i link set "p-$n" master core0
  done
  ipn i addr add "$CORE.254/24" dev core0
  ipn wa addr add "$CORE.50/24" dev wan
  ipn wb addr add "$CORE.51/24" dev wan
  ipn m addr add "$CORE.100/24" dev wan
  ipn m addr add "$CORE.101/24" dev wan
  ipn na addr add "$CORE.10/24" dev wan
  ipn na2 addr add "$CORE.12/24" dev wan
  ipn nb addr add "$CORE.30/24" dev wan
  ipn nr addr add "$CORE.20/24" dev wan
  ipn cg addr add "$CORE.40/24" dev wan
  ipn cg2 addr add "$CORE.41/24" dev wan
  # NAT-A: мост lan (ha, ha2); NAT-A2: сеть второго интерфейса ноутбука ha
  ipn na link add lan type bridge
  vl na lh1 ha eth0; ipn na link set lh1 master lan
  vl na lh2 ha2 eth0; ipn na link set lh2 master lan
  ipn na addr add 192.168.10.1/24 dev lan
  ipn ha addr add 192.168.10.2/24 dev eth0
  ipn ha2 addr add 192.168.10.3/24 dev eth0
  vl na2 lan ha eth1
  ipn na2 addr add 192.168.12.1/24 dev lan
  ipn ha addr add 192.168.12.2/24 dev eth1
  vl nb lan hb eth0; ipn nb addr add 192.168.30.1/24 dev lan; ipn hb addr add 192.168.30.2/24 dev eth0
  vl nr lan hr eth0; ipn nr addr add 192.168.20.1/24 dev lan; ipn hr addr add 192.168.20.2/24 dev eth0
  # CGNAT: внутри 100.64.0.0/10 (hc и wan домашнего роутера nd); nd за ним, hd за nd
  ipn cg link add lan type bridge
  vl cg lc hc eth0; ipn cg link set lc master lan
  vl cg ld nd wan; ipn cg link set ld master lan
  ipn cg addr add 100.64.0.1/10 dev lan
  ipn hc addr add 100.64.0.2/10 dev eth0
  ipn nd addr add 100.64.0.3/10 dev wan
  vl nd lan hd eth0; ipn nd addr add 192.168.40.1/24 dev lan; ipn hd addr add 192.168.40.2/24 dev eth0
  ipn cg2 link add lan type bridge
  vl cg2 lc hc2 eth0; ipn cg2 link set lc master lan
  ipn cg2 addr add 100.64.0.1/10 dev lan
  ipn hc2 addr add 100.64.0.2/10 dev eth0
  for n in "${NSL[@]}"; do
    ifs="$(ipn "$n" -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$' || true)"
    for p in $ifs; do ipn "$n" link set "$p" up; done
  done
  # второй интерфейс ноутбука по умолчанию выключен (строки G7-LAPTOP)
  ipn ha link set eth1 down
  # маршруты по умолчанию нужны зонду маршрута (connect без отправки); пакетов на 192.0.2.1 быть не должно
  for n in wa wb m na na2 nb nr cg cg2; do ipn "$n" route add default via "$CORE.254"; done
  ipn ha route add default via 192.168.10.1
  ipn ha2 route add default via 192.168.10.1
  ipn hb route add default via 192.168.30.1
  ipn hr route add default via 192.168.20.1
  ipn hc route add default via 100.64.0.1
  ipn nd route add default via 100.64.0.1
  ipn hd route add default via 192.168.40.1
  ipn hc2 route add default via 100.64.0.1
  for n in i na na2 nb nr cg nd cg2; do nsx "$n" sysctl -qw net.ipv4.ip_forward=1; done
  # смена адреса: без этого удаление основного адреса снесёт и вторичный
  for n in wa wb na nb; do
    nsx "$n" sysctl -qw net.ipv4.conf.all.promote_secondaries=1 net.ipv4.conf.wan.promote_secondaries=1
  done
  # DNS-заглушка: любой запрос к резолверу виден счётчиком dns; только свои каталоги, сам /etc/netns не трогаем
  mkdir -p /etc/netns
  for n in wa wb ha ha2 hb hr hc hd hc2; do
    [[ ! -L "/etc/netns/$PFX$n" ]] || { echo "/etc/netns/$PFX$n: символьная ссылка" >&2; exit 2; }
    mkdir -p "/etc/netns/$PFX$n"
    echo "nameserver 192.0.2.53" > "/etc/netns/$PFX$n/resolv.conf"
  done
}

# Правила NAT ns по таблице типов (спецификация п. 6). Типы: FC AR PR SYM CGN DNAT UPNP.
nat_load() { # ns тип
  local ns="$1" type="$2" L="" H="" masq="masquerade" pre="" lanout="" xch="" pfirst=""
  case "$ns" in
    na)  L=192.168.10.0/24; H=192.168.10.2 ;;
    na2) L=192.168.12.0/24; H=192.168.12.2 ;;
    nb)  L=192.168.30.0/24; H=192.168.30.2 ;;
    nr)  L=192.168.20.0/24; H=192.168.20.2 ;;
    nd)  L=192.168.40.0/24; H=192.168.40.2 ;;
    cg|cg2) L=100.64.0.0/10; H=100.64.0.2 ;;
    *) echo "nat_load: неизвестный ns $ns" >&2; return 1 ;;
  esac
  case "$type" in
    FC)
      pre='iifname "wan" udp dport @fcmap dnat ip to '"$H"
      lanout='iifname "lan" oifname "wan" meta l4proto udp update @fcmap { udp sport }' ;;
    AR)
      pre='iifname "wan" udp dport 4433 ip saddr @seen dnat ip to '"$H"
      lanout='iifname "lan" oifname "wan" udp sport 4433 update @seen { ip daddr }' ;;
    PR|CGN|DNAT) ;;
    SYM) masq="masquerade fully-random" ;;
    UPNP)
      pre='jump prerouting_miniupnpd'
      lanout='jump miniupnpd'
      pfirst='jump postrouting_miniupnpd'
      xch=$'chain miniupnpd { }\n  chain prerouting_miniupnpd { }\n  chain postrouting_miniupnpd { }' ;;
    *) echo "nat_load: неизвестный тип $type" >&2; return 1 ;;
  esac
  nsx "$ns" nft flush ruleset
  nsx "$ns" nft -f - <<NFT
table inet nat16 {
  set seen  { type ipv4_addr; flags dynamic,timeout; timeout 120s; }
  set fcmap { type inet_service; flags dynamic,timeout; timeout 120s; }
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    $pre
  }
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    $pfirst
    oifname "wan" ip saddr $L $masq
  }
  chain fwd16 {
    type filter hook forward priority filter; policy drop;
    $lanout
    iifname "lan" oifname "wan" accept
    iifname "wan" ct state established,related accept
    iifname "wan" ct status dnat accept
  }
  chain inp16 {
    type filter hook input priority filter; policy accept;
    iifname "wan" icmp type echo-request accept
    iifname "wan" drop
  }
  $xch
}
NFT
}

load_default_nats() {
  nat_load na PR && nat_load na2 PR && nat_load nb PR && nat_load nr UPNP \
    && nat_load cg CGN && nat_load nd DNAT && nat_load cg2 CGN
}

# Внешний адрес NAT хоста (для списка допустимых получателей охраны).
wan_of() {
  case "$1" in
    ha|ha2) echo "$CORE.10" ;;
    hb) echo "$CORE.30" ;;
    hr) echo "$CORE.20" ;;
    hc|hd) echo "$CORE.40" ;;
    hc2) echo "$CORE.41" ;;
    wa) echo "$CORE.50" ;;
    wb) echo "$CORE.51" ;;
    *) echo "$CORE.254" ;;
  esac
}

# ---------------------------------------------------------------- строка: начало и конец
row_begin() { # id кап_секунд
  local rc
  [[ "$1" =~ ^[A-Za-z0-9-]+$ ]] || die "плохой id строки: $1"
  ROW_ID="$1"
  RD="$LOGS/$1"; rm -rf -- "$RD"; mkdir -p -- "$RD"
  W="$STATE/$1"; rm -rf -- "$W"; mkdir -p -- "$W"
  ROW_END=$(( $(now_s) + $2 ))
  DL=$(( $2 + 120 ))
  NODE_REAL=(); NODE_WRAP=(); MPD_REAL=""; MPD_WRAP=""; TCPD_REAL=""; TCPD_WRAP=""
  NODE_NICE=0
  mkdir -p -- "$LOGS"
  do_teardown
  ( topo_body ) >> "$RD/setup.log" 2>&1; rc=$?
  if [[ $rc != 0 ]]; then log "$1: топология не поднялась (см. setup.log)"; return 1; fi
  load_default_nats >> "$RD/setup.log" 2>&1 || { log "$1: правила NAT не загрузились"; return 1; }
  return 0
}

mpd_stop() {
  bg_stop "$MPD_REAL" "$MPD_WRAP"
  MPD_REAL=""; MPD_WRAP=""
}
tcpd_stop() {
  bg_stop "$TCPD_REAL" "$TCPD_WRAP"
  TCPD_REAL=""; TCPD_WRAP=""
}

row_end() {
  local l
  for l in "${!NODE_REAL[@]}"; do node_stop "$l"; done
  NODE_REAL=(); NODE_WRAP=()
  mpd_stop; tcpd_stop
  do_teardown
  if [[ -n "$W" ]]; then rm -rf -- "$W"; fi
  ROW_END=0
  hostsafe_check "$ROW_ID"
}

# Контроль типа NAT: 0 — можно использовать, 1 — зонд NATCHECK дважды не совпал (строка INCONCLUSIVE).
nat_type_bad() { # ТИП@ns
  [[ -f "$NATTSV" ]] || return 1
  awk -F'\t' -v k="$1" '$1 == k { v = $7 } END { exit (v == "MISMATCH") ? 0 : 1 }' "$NATTSV"
}

# ---------------------------------------------------------------- NATCHECK
natcheck_one() { # ключ тип ns хост
  local key="$1" type="$2" ns="$3" host="$4" try out em ef gm="" gf="" gp="" v="MISMATCH" ext
  case "$type" in
    FC) em=EIM; ef=EIF ;; AR) em=EIM; ef=ADF ;; SYM) em=EDM; ef=APDF ;; *) em=EIM; ef=APDF ;;
  esac
  for try in 1 2; do
    if ! row_begin "natcheck-${key//@/-}-$try" 120; then v=INCONCLUSIVE; break; fi
    case "$ns" in na|nb) nat_load "$ns" "$type" ;; *) ;; esac
    bg_start "$RD/refl.pid" m sh -c 'exec env -i PATH="$1" "$2" reflect --bind "$3" >"$4" 2>&1' sh \
      "$SAFE_PATH" "$BIN/spike8" "$CORE.100:7001,$CORE.100:7002,$CORE.101:7001" "$RD/refl.log"
    local rr="$BG_REAL" rw="$BG_WRAP"
    sleep 1
    out="$RD/probe.log"
    nsx "$host" env -i PATH="$SAFE_PATH" timeout 60 "$BIN/spike8" natprobe --local 0.0.0.0:4433 \
      --r1a "$CORE.100:7001" --r1b "$CORE.100:7002" --r2 "$CORE.101:7001" > "$out" 2> "$out.err" < /dev/null || true
    bg_stop "$rr" "$rw"
    row_end
    gm="$(kv mapping < "$out")"; gf="$(kv filtering < "$out")"; ext="$(kv ext < "$out")"; gp="${ext##*:}"
    if [[ -z "$gm" ]]; then v=INCONCLUSIVE; continue; fi
    if [[ "$gm" == "$em" && "$gf" == "$ef" ]] && { [[ "$em" != EIM ]] || [[ "$gp" == "$PORT" ]]; }; then v=PASS; break; fi
    v=MISMATCH
  done
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$key" "$em" "$ef" "${gm:--}" "${gf:--}" "${gp:--}" "$v" "$try" >> "$NATTSV"
  [[ "$v" == PASS ]]
}

do_natcheck() {
  local bad=0 k
  : > "$NATTSV"
  if [[ $HAVE_SPIKE8 != 1 ]]; then
    vd NATCHECK ctl INCONCLUSIVE "CHV_SPIKE8 не задан" "типы NAT независимо не проверены"
    return 0
  fi
  natcheck_one FC@na FC na ha || bad=1
  natcheck_one AR@na AR na ha || bad=1
  natcheck_one PR@na PR na ha || bad=1
  natcheck_one SYM@na SYM na ha || bad=1
  natcheck_one PR@nb PR nb hb || bad=1
  natcheck_one CGN@hc CGN cg hc || bad=1
  natcheck_one DNAT@hd DNAT nd hd || bad=1
  k="$(awk -F'\t' '$7 == "PASS"' "$NATTSV" | wc -l)"
  if (( bad == 0 )); then vd NATCHECK ctl PASS "все 7 контролей типов NAT прошли" "порядок и методика stage 8, зонд natprobe"
  else vd NATCHECK ctl INCONCLUSIVE "прошло $k из 7" "несовпавший тип INCONCLUSIVE в строках, где он используется; правила не подгонялись"
  fi
}

# ---------------------------------------------------------------- общие шаги строк связности
CA=()
ca() { # ns deadline
  mkdir -p "$W/$1/dest" "$W/$1/partial"
  CA=(--port "$PORT" --book-dir "$W/$1" --dest "$W/$1/dest" --partial "$W/$1/partial" --sas-auto-confirm
      --diag-every 5 --stop-file "$W/$1.stop" --deadline "$2")
}

obs_start() { # хосты, которых приглашают белые наблюдатели wa, wb
  local o h
  local args
  for o in wa wb; do
    args=()
    for h in "$@"; do args+=(--invite-out "$W/$o/inv-$h"); done
    ca "$o" "$DL"
    node_start "$o" "$o" "${CA[@]}" "${args[@]}"
  done
}

# nat_view не Unknown (и не пусто) за secs
wait_nat_view() { # метка секунды [нужное]
  local i v
  for i in $(seq 1 "$(( $2 * 2 ))"); do
    v="$(nat_view_of "$1")"
    if [[ -n "${3:-}" ]]; then [[ "$v" == "$3" ]] && return 0
    elif [[ -n "$v" && "$v" != Unknown ]]; then return 0
    fi
    over_cap && return 1
    sleep 0.5
  done
  return 1
}

meet_up() { # X Y
  ip link add meet0 netns "$PFX$1" type veth peer name meet0 netns "$PFX$2" || return 1
  ipn "$1" addr add 10.99.0.1/30 dev meet0
  ipn "$2" addr add 10.99.0.2/30 dev meet0
  ipn "$1" link set meet0 up
  ipn "$2" link set meet0 up
}
meet_down() { ipn "$1" link del meet0 2>/dev/null || true; }

# Выпуск токена src -> dst: стенд — «мессенджер». В лог пишется только размер.
TOKRES=""
token_pass2() { # метка_узла_источника каталог_источника метка_узла_приёмника каталог_приёмника [копия_токена]
  local sl="$1" sd="$2" dl="$3" dd="$4" n0 i res err k
  n0="$(lines_of "$sl")"
  k="$(cntl "$dl" '^EVENT token_(applied|rejected) ')"
  rm -f -- "$W/$sd/tok"; : > "$W/$sd/tok.go"
  res=""
  for i in $(seq 1 90); do
    res="$(tail -n +"$(( n0 + 1 ))" "$(lgf "$sl")" | grep -E '^EVENT token_(issued|failed) ' | head -n1 || true)"
    [[ -n "$res" ]] && break
    sleep 0.5
  done
  TOKOK=0
  if [[ "$res" == "EVENT token_issued"* ]]; then
    if deliver "$W/$sd/tok" "$W/$dd/tok-in" 10; then
      echo "token delivered bytes=$(wc -c < "$W/$sd/tok")" >> "$RD/stand.log"
      [[ -z "${5:-}" ]] || cp -- "$W/$sd/tok" "$5"
      TOKRES+="$sd>$dd:ok "
      TOKOK=1
      for i in $(seq 1 20); do [[ "$(cntl "$dl" '^EVENT token_(applied|rejected) ')" -gt "$k" ]] && break; sleep 0.5; done
    else
      TOKRES+="$sd>$dd:no_file "
    fi
  else
    err="$(sed -n 's/.* error=\([^ ]*\).*/\1/p' <<<"$res" | head -n1)"
    TOKRES+="$sd>$dd:failed(${err:-timeout}) "
  fi
}
TOKOK=0
token_pass() { token_pass2 "$1" "$1" "$2" "$2" "${3:-}"; }

# Дружба через метки: observers wa wb, встречная связка X-Y (X — приглашающий), токены по списку (xy yx).
# После возврата: X и Y подключены к wa, wb; X знает Y как o1, Y знает X как i3; MX, MY — метки логов в момент
# разрыва связки. Параметр pair_only=1 не ждёт связи по токенам.
flow_meet() { # X Y "токены" [доп. аргументы X через пробел не поддерживаются: XA_EXTRA]
  local X="$1" Y="$2" toks="$3" t
  obs_start "$X" "$Y"
  ca "$X" "$DL"
  node_start "$X" "$X" "${CA[@]}" --invite-in "$W/$X/inv-wa" --invite-in "$W/$X/inv-wb" \
    --invite-out "$W/$X/inv-meet" --invite-addr 10.99.0.1:4433 \
    --token-to o1 --token-out "$W/$X/tok" --token-in "$W/$X/tok-in" "${XA_EXTRA[@]}"
  ca "$Y" "$DL"
  node_start "$Y" "$Y" "${CA[@]}" --invite-in "$W/$Y/inv-wa" --invite-in "$W/$Y/inv-wb" --invite-in "$W/$Y/inv-meet" \
    --token-to i3 --token-out "$W/$Y/tok" --token-in "$W/$Y/tok-in"
  local o h
  for o in wa wb; do
    for h in "$X" "$Y"; do
      deliver "$W/$o/inv-$h" "$W/$h/inv-$o" 60 || { WHY="приглашение от $o для $h не выпущено"; return 1; }
    done
  done
  for h in "$X" "$Y"; do
    for o in 1 2; do
      wait_grep "$h" "^EVENT (invite_finished pair=i$o outcome=Added|connected pair=i$o )" 60 \
        || { WHY="$h: приглашение i$o не завершено"; return 1; }
    done
  done
  for h in "$X" "$Y"; do
    wait_nat_view "$h" 60 || { WHY="no observation: nat_view Unknown у $h"; return 1; }
  done
  meet_up "$X" "$Y" || { WHY="связка meet0 не поднялась"; return 1; }
  deliver "$W/$X/inv-meet" "$W/$Y/inv-meet" 60 || { WHY="приглашение по связке не выпущено"; return 1; }
  wait_grep "$Y" '^EVENT (invite_finished pair=i3 outcome=Added|connected pair=i3 )' 60 \
    || { WHY="приглашение по связке не принято"; return 1; }
  wait_grep "$X" '^EVENT (invite_finished pair=o1 outcome=Added|connected pair=o1 )' 60 \
    || { WHY="приглашающий не получил итог по связке"; return 1; }
  sleep 2
  MX="$(lines_of "$X")"; MY="$(lines_of "$Y")"
  meet_down "$X"
  # старое соединение по связке живёт до простоя 30 с: ждём его конца (не фатально), затем токены
  for t in $(seq 1 150); do
    has_after_meet "$X" "disconnected pair=o1 " "$MX" && has_after_meet "$Y" "disconnected pair=i3 " "$MY" && break
    over_cap && break
    sleep 0.5
  done
  XA_MARK_MX="$MX"; XA_MARK_MY="$MY"
  for t in $toks; do
    case "$t" in
      xy) token_pass "$X" "$Y" ;;
      yx) token_pass "$Y" "$X" ;;
    esac
  done
  return 0
}
# Rev. 2 (S3), C07: связка раньше наблюдателей. Связка поднята, приглашение по ней принято обеими сторонами, связка снята, и
# только потом наблюдатели (приглашения, nat_view не Unknown). Токенов нет. Метки: X: o1 (связка), i1, i2 (наблюдатели);
# Y: i1 (связка), i2, i3 (наблюдатели); k-й --invite-in получает метку i<k> (node16.rs).
flow_meet_first() { # X Y "токены"
  local X="$1" Y="$2" toks="$3" o h t
  ca "$X" "$DL"
  node_start "$X" "$X" "${CA[@]}" --invite-in "$W/$X/inv-wa" --invite-in "$W/$X/inv-wb" \
    --invite-out "$W/$X/inv-meet" --invite-addr 10.99.0.1:4433 \
    --token-to o1 --token-out "$W/$X/tok" --token-in "$W/$X/tok-in" "${XA_EXTRA[@]}"
  ca "$Y" "$DL"
  node_start "$Y" "$Y" "${CA[@]}" --invite-in "$W/$Y/inv-meet" --invite-in "$W/$Y/inv-wa" --invite-in "$W/$Y/inv-wb" \
    --token-to i1 --token-out "$W/$Y/tok" --token-in "$W/$Y/tok-in"
  meet_up "$X" "$Y" || { WHY="связка meet0 не поднялась"; return 1; }
  deliver "$W/$X/inv-meet" "$W/$Y/inv-meet" 60 || { WHY="приглашение по связке не выпущено"; return 1; }
  wait_grep "$Y" '^EVENT (invite_finished pair=i1 outcome=Added|connected pair=i1 )' 60 \
    || { WHY="приглашение по связке не принято"; return 1; }
  wait_grep "$X" '^EVENT (invite_finished pair=o1 outcome=Added|connected pair=o1 )' 60 \
    || { WHY="приглашающий не получил итог по связке"; return 1; }
  sleep 2
  MX="$(lines_of "$X")"; MY="$(lines_of "$Y")"
  meet_down "$X"
  # наблюдатели стартуют только теперь
  obs_start "$X" "$Y"
  for o in wa wb; do
    for h in "$X" "$Y"; do
      deliver "$W/$o/inv-$h" "$W/$h/inv-$o" 60 || { WHY="приглашение от $o для $h не выпущено"; return 1; }
    done
  done
  for o in 1 2; do
    wait_grep "$X" "^EVENT (invite_finished pair=i$o outcome=Added|connected pair=i$o )" 60 \
      || { WHY="$X: приглашение i$o не завершено"; return 1; }
    wait_grep "$Y" "^EVENT (invite_finished pair=i$((o + 1)) outcome=Added|connected pair=i$((o + 1)) )" 60 \
      || { WHY="$Y: приглашение i$((o + 1)) не завершено"; return 1; }
  done
  for h in "$X" "$Y"; do
    wait_nat_view "$h" 60 || { WHY="no observation: nat_view Unknown у $h"; return 1; }
  done
  XA_MARK_MX="$MX"; XA_MARK_MY="$MY"
  for t in $toks; do
    case "$t" in
      xy) token_pass "$X" "$Y" ;;
      yx) token_pass "$Y" "$X" ;;
    esac
  done
  return 0
}
has_after_meet() { [[ "$(cnt_after "$1" "EVENT $2" "$3")" -gt 0 ]]; }
XA_EXTRA=()
XA_MARK_MX=0; XA_MARK_MY=0

# Пара без наблюдателей: inviter приглашает invitee. AX, BX — дополнительные аргументы.
AX=(); BX=()
flow_pair() { # inviter invitee
  ca "$1" "$DL"; node_start "$1" "$1" "${CA[@]}" --invite-out "$W/$1/inv" "${AX[@]}"
  ca "$2" "$DL"; node_start "$2" "$2" "${CA[@]}" --invite-in "$W/$2/inv" "${BX[@]}"
  deliver "$W/$1/inv" "$W/$2/inv" 60 || { WHY="приглашение не выпущено"; return 1; }
  wait_grep "$2" '^EVENT (invite_finished pair=i1 outcome=Added|connected pair=i1 )' 60 \
    || { WHY="приглашение не принято"; return 1; }
  wait_grep "$1" '^EVENT connected pair=o1 ' 60 || { WHY="не подключились после приглашения"; return 1; }
  return 0
}

# Хост за NAT принимает приглашения белых наблюдателей; проверяемая пара — X (i1) и wa (o1).
flow_obs() { # X
  local X="$1" o h
  obs_start "$X"
  ca "$X" "$DL"
  node_start "$X" "$X" "${CA[@]}" --invite-in "$W/$X/inv-wa" --invite-in "$W/$X/inv-wb" "${XA_EXTRA[@]}"
  for o in wa wb; do
    deliver "$W/$o/inv-$X" "$W/$X/inv-$o" 60 || { WHY="приглашение от $o не выпущено"; return 1; }
  done
  for h in 1 2; do
    wait_grep "$X" "^EVENT (invite_finished pair=i$h outcome=Added|connected pair=i$h )" 60 \
      || { WHY="$X: приглашение i$h не завершено"; return 1; }
  done
  wait_nat_view "$X" 60 || { WHY="no observation: nat_view Unknown у $X"; return 1; }
  return 0
}

# miniupnpd на nr (конфиг как в stage13a.sh mpd_conf: таблица nat16, ext_ifname=wan, listening_ip=lan, uuid, NAT-PMP и PCP выключены).
mpd_start() {
  local conf="$RD/miniupnpd.conf" i
  cat > "$conf" <<CONF
ext_ifname=wan
listening_ip=192.168.20.1/24
http_port=5000
uuid=$UUID
enable_upnp=yes
enable_natpmp=no
enable_pcp_pmp=no
secure_mode=yes
system_uptime=yes
min_lifetime=60
upnp_table_name=nat16
upnp_nat_table_name=nat16
upnp_forward_chain=miniupnpd
upnp_nat_chain=prerouting_miniupnpd
upnp_nat_postrouting_chain=postrouting_miniupnpd
lease_file=$RD/leases
allow 1024-65535 192.168.20.0/24 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
CONF
  bg_start "$RD/mpd.pid" nr sh -c 'exec "$1" -d -f "$2" -P "$3" >"$4" 2>&1' sh "$BIN/miniupnpd" "$conf" "$RD/mpd.mpid" "$RD/miniupnpd.log"
  MPD_REAL="$BG_REAL"; MPD_WRAP="$BG_WRAP"
  for i in $(seq 1 50); do
    grep -qiE 'HTTP listening on port|listening' "$RD/miniupnpd.log" 2>/dev/null && break
    kill -0 "$MPD_REAL" 2>/dev/null || break
    sleep 0.1
  done
  sleep 0.5
  [[ -n "$MPD_REAL" ]] && kill -0 "$MPD_REAL" 2>/dev/null
}

# Причина: последняя EVENT unreachable по паре, иначе последняя DIAG. Суффикс +rv, если rendezvous_could_help=true.
reason_of() { # узел метка_пары
  local line r rv
  line="$(grep "^EVENT unreachable pair=$2 " "$(lgf "$1")" 2>/dev/null | tail -n1 || true)"
  [[ -n "$line" ]] || line="$(grep "^DIAG pair=$2 " "$(lgf "$1")" 2>/dev/null | tail -n1 || true)"
  [[ -n "$line" ]] || { echo none; return 0; }
  r="$(kv reason <<<"$line")"; rv="$(kv rendezvous_could_help <<<"$line")"
  [[ "$rv" == true ]] && r+="+rv"
  echo "${r:-none}"
}
# ожидание совпадает с полученным (ожидание "-" не проверяется; без +rv в ожидании суффикс игнорируется)
rcmp() { # ожидание получено
  local e="$1" g="$2"
  [[ "$e" == "-" ]] && return 0
  [[ "$e" == *+rv ]] || g="${g%+rv}"
  [[ "$e" == "$g" ]]
}
path_of() { # узел метка
  grep "^EVENT connected pair=$2 " "$(lgf "$1")" 2>/dev/null | tail -n1 | sed -n 's/.* path=\([^ ]*\).*/\1/p'
}

# ---------------------------------------------------------------- таблица строк связности
ROW_X=""; ROW_Y=""; ROW_TA=""; ROW_TB=""; ROW_FLOW=""; ROW_TOK=""; ROW_EXP=""; ROW_EXX="-"; ROW_EXY="-"
ROW_PATH="-"; ROW_GUARD=""; ROW_ACT=""; ROW_NV=""
CONN_IDS=(C01 C02 C03 C04 C05 C06 C07 C07H C08 C09 C10 C11 C12 C13 C14 C15 C16 C17 C18 C19)
conn_def() { # id
  ROW_X=""; ROW_Y=""; ROW_TA=""; ROW_TB=""; ROW_FLOW=""; ROW_TOK=""; ROW_EXP=""; ROW_EXX="-"; ROW_EXY="-"
  ROW_PATH="-"; ROW_GUARD=""; ROW_ACT=""; ROW_NV=""; XA_EXTRA=(); AX=(); BX=()
  case "$1" in
    C01) ROW_X=ha; ROW_Y=ha2; ROW_FLOW=lan; ROW_EXP=yes; ROW_PATH=Lan; AX=(--invite-lan) ;;
    C03) ROW_X=wa; ROW_Y=wb; ROW_FLOW=white; ROW_EXP=yes ;;
    C04) ROW_X=ha; ROW_Y=hb; ROW_TA=FC; ROW_TB=PR; ROW_FLOW=meet; ROW_TOK="xy"; ROW_EXP=yes ;;
    C05) ROW_X=ha; ROW_Y=hb; ROW_TA=AR; ROW_TB=AR; ROW_FLOW=meet; ROW_TOK="xy yx"; ROW_EXP=yes ;;
    C06) ROW_X=ha; ROW_Y=hb; ROW_TA=PR; ROW_TB=PR; ROW_FLOW=meet; ROW_TOK="xy yx"; ROW_EXP=yes; ROW_PATH=SimultaneousOpen; ROW_GUARD=ha ;;
    # Rev. 2 (S3): C07 = связка до наблюдателей (meet_first), без токенов: нет, NeedToken / NeedToken.
    C07) ROW_X=ha; ROW_Y=hb; ROW_TA=PR; ROW_TB=PR; ROW_FLOW=meet_first; ROW_TOK=""; ROW_EXP=no; ROW_EXX=NeedToken; ROW_EXY=NeedToken ;;
    # C07H = прежний порядок rev. 1 (наблюдатели, затем связка), без токенов: да, SimultaneousOpen, причин нет.
    C07H) ROW_X=ha; ROW_Y=hb; ROW_TA=PR; ROW_TB=PR; ROW_FLOW=meet; ROW_TOK=""; ROW_EXP=yes; ROW_PATH=SimultaneousOpen; ROW_EXX=none; ROW_EXY=none ;;
    C08) ROW_X=ha; ROW_Y=wa; ROW_TA=SYM; ROW_FLOW=obs; ROW_ACT=killwa; ROW_EXP=yes_unreach; ROW_EXX=SymmetricNat ;;
    C09) ROW_X=ha; ROW_Y=hb; ROW_TA=SYM; ROW_TB=FC; ROW_FLOW=meet; ROW_TOK="yx xy"; ROW_EXP=yes ;;
    C10) ROW_X=ha; ROW_Y=hb; ROW_TA=SYM; ROW_TB=AR; ROW_FLOW=meet; ROW_TOK="yx"; ROW_EXP=no; ROW_EXX=SymmetricNat; ROW_EXY=NeedToken ;;
    C11) ROW_X=ha; ROW_Y=hb; ROW_TA=SYM; ROW_TB=PR; ROW_FLOW=meet; ROW_TOK="yx"; ROW_EXP=no; ROW_EXX=SymmetricNat; ROW_EXY=NeedToken ;;
    C12) ROW_X=ha; ROW_Y=hb; ROW_TA=SYM; ROW_TB=SYM; ROW_FLOW=meet; ROW_TOK="xy yx"; ROW_EXP=no; ROW_EXX=SymmetricNat; ROW_EXY=SymmetricNat ;;
    C13) ROW_X=hc; ROW_Y=wa; ROW_FLOW=obs; ROW_ACT=killwa; ROW_EXP=yes_unreach; ROW_EXX="BehindCgnat+rv"; ROW_GUARD=hc ;;
    C14) ROW_X=hc; ROW_Y=hb; ROW_TB=PR; ROW_FLOW=meet; ROW_TOK="yx xy"; ROW_EXP=no; ROW_EXX="BehindCgnat+rv"; ROW_EXY=NeedToken ;;
    C15) ROW_X=hc; ROW_Y=hc2; ROW_FLOW=meet; ROW_TOK="xy yx"; ROW_EXP=no; ROW_EXX=BehindCgnat; ROW_EXY=BehindCgnat ;;
    C16) ROW_X=hd; ROW_Y=wa; ROW_FLOW=obs; ROW_EXP=yes; ROW_NV=Eim ;;
    C17) ROW_X=hd; ROW_Y=hb; ROW_TB=PR; ROW_FLOW=meet; ROW_TOK="xy yx"; ROW_EXP=yes ;;
    C18) ROW_X=hr; ROW_Y=hb; ROW_TB=PR; ROW_FLOW=upnp; ROW_EXP=yes; ROW_PATH="PortMapped|SimultaneousOpen"; ROW_NV=PortMapped; AX=(--upnp-router "$UDN") ;;
    C19) ROW_X=ha; ROW_Y=wa; ROW_TA=PR; ROW_FLOW=obs; ROW_ACT=drop; ROW_EXP=no; ROW_EXX=UdpBlockedSuspected; XA_EXTRA=(--udp-window 60) ;;
    *) return 1 ;;
  esac
  return 0
}

CX=0; CY=0; T_CONNECT="-"; LX=""; LY=""; MX=0; MY=0; WHY=""
await_connect() { # секунды
  local t0 el
  t0="$(now_s)"
  while :; do
    CX="$(cnt_after "$ROW_X" "EVENT connected pair=$LX " "$MX")"
    CY="$(cnt_after "$ROW_Y" "EVENT connected pair=$LY " "$MY")"
    if (( CX > 0 && CY > 0 )); then T_CONNECT=$(( $(now_s) - t0 )); return 0; fi
    el=$(( $(now_s) - t0 ))
    (( el >= $1 )) && return 1
    over_cap && return 1
    sleep 1
  done
}
win_left() { # окно не дольше остатка капа строки
  local left=$(( ROW_END - $(now_s) - 10 ))
  (( left < 5 )) && left=5
  (( WIN < left )) && echo "$WIN" || echo "$left"
}

conn_run() { # id
  local id="$1" cap guard_peers="" rxg ryg gf="" v=PASS notes="" actual="" exp_txt="" pth nv left p1="" unreach=0 t
  conn_def "$id" || { echo "нет строки $id" >&2; return 1; }
  WHY=""; TOKRES=""; T_CONNECT="-"; CX=0; CY=0; MX=0; MY=0
  XA_MARK_MX=0; XA_MARK_MY=0
  if [[ "$ROW_EXP" == yes ]]; then cap=300; else cap=420; fi
  [[ "$id" == C18 && $HAVE_MPD != 1 ]] && { vd "$id" conn INCONCLUSIVE "-" "CHV_MINIUPNPD не задан"; return 0; }
  if [[ -n "$ROW_TA" ]] && nat_type_bad "$ROW_TA@na"; then vd "$id" conn INCONCLUSIVE "-" "контроль типа $ROW_TA не прошёл"; return 0; fi
  if [[ -n "$ROW_TB" ]] && nat_type_bad "$ROW_TB@nb" ; then vd "$id" conn INCONCLUSIVE "-" "контроль типа $ROW_TB не прошёл"; return 0; fi
  row_begin "$id" "$cap" || { vd "$id" conn INCONCLUSIVE "-" "топология не поднялась"; row_end; return 0; }
  [[ -z "$ROW_TA" ]] || nat_load na "$ROW_TA"
  [[ -z "$ROW_TB" ]] || nat_load nb "$ROW_TB"
  if [[ "$id" == C06 ]]; then
    # X01: захват пакетов хоста ha (только исходящие UDP считаются при разборе)
    bg_start "$RD/tcpdump.pid" ha tcpdump -i any -Q out -nn -U -Z root -w "$STATE/ha.pcap"
    TCPD_REAL="$BG_REAL"; TCPD_WRAP="$BG_WRAP"
  fi
  if [[ -n "$ROW_GUARD" ]]; then
    guard_peers="$CORE.50, $CORE.51, 10.99.0.1, 10.99.0.2"
    [[ "$ROW_FLOW" != meet ]] || guard_peers+=", $(wan_of "$ROW_Y")"
    nft_guard "$ROW_GUARD" "$guard_peers"
  fi
  [[ "$id" != C18 ]] || { mpd_start || WHY="miniupnpd не запустился"; }
  if [[ -z "$WHY" ]]; then
    case "$ROW_FLOW" in
      white|lan|upnp) flow_pair "$ROW_X" "$ROW_Y" && { LX=o1; LY=i1; } ;;
      obs) flow_obs "$ROW_X" && { LX=i1; LY=o1; } ;;
      meet) flow_meet "$ROW_X" "$ROW_Y" "$ROW_TOK" && { LX=o1; LY=i3; MX="$XA_MARK_MX"; MY="$XA_MARK_MY"; } ;;
      meet_first) flow_meet_first "$ROW_X" "$ROW_Y" "$ROW_TOK" && { LX=o1; LY=i1; MX="$XA_MARK_MX"; MY="$XA_MARK_MY"; } ;;
    esac
  fi
  if [[ -n "$WHY" ]]; then
    row_end
    vd "$id" conn INCONCLUSIVE "-" "$WHY"
    return 0
  fi
  left="$(win_left)"
  # действия после связи
  case "$ROW_ACT" in
    killwa)
      if await_connect 120; then
        p1=ok
        node_sigkill wa
        t="$(lines_of "$ROW_X")"
        for _ in $(seq 1 "$left"); do
          [[ "$(cnt_after "$ROW_X" "EVENT unreachable pair=$LX " "$t")" -gt 0 ]] && break
          over_cap && break
          sleep 1
        done
        unreach="$(cnt_after "$ROW_X" "EVENT unreachable pair=$LX " "$t")"
      fi ;;
    drop)
      if await_connect 120; then
        p1=ok
        MX="$(lines_of "$ROW_X")"; MY="$(lines_of "$ROW_Y")"
        drop_on "$ROW_X" "$CORE.50, $CORE.51"
        sleep "$left"
        await_connect 1 || true
      fi ;;
    *)
      await_connect "$left" || true
      [[ "$id" != C06 ]] || sleep 8 ;;
  esac
  # сбор
  rxg="$(reason_of "$ROW_X" "$LX")"; ryg="$(reason_of "$ROW_Y" "$LY")"
  pth="$(path_of "$ROW_X" "$LX")"; pth="${pth:--}"
  nv="$(nat_view_of "$ROW_X")"
  if [[ -n "$ROW_GUARD" ]]; then gf="$(guard_fail "$ROW_GUARD")"; guard_record "$id" "$ROW_GUARD"; fi
  case "$ROW_EXP" in
    yes)
      exp_txt="yes"
      if (( CX > 0 && CY > 0 )); then actual=yes
      elif (( CX > 0 || CY > 0 )); then actual="one side only"; v=FAIL
      else actual=no; v=FAIL
      fi ;;
    no)
      exp_txt="no"
      [[ "$ROW_ACT" != drop ]] || exp_txt="no (after block)"
      if [[ "$ROW_ACT" == drop && -z "$p1" ]]; then v=INCONCLUSIVE; actual="no initial connection"
      elif (( CX == 0 && CY == 0 )); then actual="${exp_txt}"
      else actual="yes"; v=FAIL
      fi ;;
    yes_unreach)
      exp_txt="yes, then unreachable"
      if [[ -z "$p1" ]]; then v=INCONCLUSIVE; actual="no initial connection"
      elif (( unreach > 0 )); then actual="yes, then unreachable"
      else actual="yes, then not unreachable in window"; v=FAIL
      fi ;;
  esac
  if [[ "$v" == PASS || "$v" == MISMATCH ]]; then
    rcmp "$ROW_EXX" "$rxg" || { v=MISMATCH; notes+="reason X; "; }
    rcmp "$ROW_EXY" "$ryg" || { v=MISMATCH; notes+="reason Y; "; }
    if [[ "$ROW_PATH" != "-" && "$ROW_EXP" == yes && "|$ROW_PATH|" != *"|$pth|"* ]]; then v=MISMATCH; notes+="path got $pth; "; fi
    if [[ -n "$ROW_NV" && "$nv" != "$ROW_NV" ]]; then v=MISMATCH; notes+="nat_view got ${nv:-none}; "; fi
  fi
  if [[ -n "${gf// /}" ]]; then [[ "$v" != INCONCLUSIVE ]] && v=FAIL; notes+="guard: $gf; "; fi
  [[ "$id" != C06 ]] || x01_check
  if [[ "$id" == C18 ]]; then
    node_stop "$ROW_X"
    if nsx nr nft list table inet nat16 2>/dev/null | grep -Eq "(udp|th) dport $PORT .*dnat"; then
      v=FAIL; notes+="mapping left in router after stop; "
    else notes+="mapping removed after stop; "
    fi
  fi
  over_cap && [[ "$v" == PASS ]] && { v=INCONCLUSIVE; notes+="timeout; "; }
  verdict "$id" conn "$v" "$exp_txt" "$actual" "$ROW_EXX" "$rxg" "$ROW_EXY" "$ryg" "$pth" "$T_CONNECT" \
    "tokens: ${TOKRES:-none}; nat_view_x=${nv:-none}; ${notes}"
  row_end
}

# X01: назначения исходящих UDP пакетов ha за время C06 — подмножество {WA, WB, NAT-B WAN, партнёр по связке}.
x01_check() {
  local f="$STATE/ha.pcap" dst role other=0 probe=0 dns=0 total=0 v6=0 txt n
  tcpd_stop
  if [[ ! -s "$f" ]]; then vd X01 extra NOTRUN "tcpdump не записал файл" "захват не удался"; return 0; fi
  txt="$(tcpdump -nn -r "$f" udp 2>/dev/null || true)"
  while read -r dst n; do
    total=$(( total + n ))
    case "$dst" in
      "$CORE.50"|"$CORE.51"|"$CORE.30"|10.99.0.2) ;;
      192.0.2.1) probe=$(( probe + n )) ;;
      *) other=$(( other + n )) ;;
    esac
  done < <(awk '{ for (i = 1; i < NF; i++) if ($i == ">") { d = $(i + 1); sub(/:$/, "", d); sub(/\.[0-9]+$/, "", d); c[d]++ } } END { for (k in c) print k, c[k] }' <<<"$txt")
  dns="$(grep -Ec '\.53(:| )' <<<"$txt" || true)"
  v6="$(tcpdump -nn -r "$f" ip6 2>/dev/null | grep -c '2001:db8::1' || true)"
  if (( total > 0 && other == 0 && probe == 0 && ${dns:-0} == 0 && ${v6:-0} == 0 )); then
    vd X01 extra PASS "udp-пакетов ha: $total, все к WA, WB, NAT-B WAN или партнёру по связке; к зонду маршрута 0, DNS 0" "pcap не сохраняется"
  else
    vd X01 extra FAIL "udp=$total, к чужим назначениям=$other, к зонду=$probe, dns=${dns:-0}, ipv6-зонд=${v6:-0}" "escalate to security"
  fi
  rm -f -- "$f"
}

# ---------------------------------------------------------------- передача: общие шаги (скорость, G7)
SRC_SHA=""
src_make() { # МиБ
  nice -n "$NODE_NICE" head -c "$(( $1 * 1048576 ))" /dev/urandom > "$W/src.bin"
  SRC_SHA="$(nice -n "$NODE_NICE" sha256sum "$W/src.bin" | awk '{print $1}')"
}
XA=(); RX=(); SX=()
xfer_start() { # метка rcvns sndns sndlabel deadline
  local t="$1" r="$2" s="$3"
  rm -rf -- "$W/$r/dest" "$W/$r/partial"; mkdir -p "$W/$r/dest" "$W/$r/partial" "$W/$s/dest" "$W/$s/partial"
  node_start "rb$t" "$r" --port "$PORT" --book-dir "$W/$r" --dest "$W/$r/dest" --partial "$W/$r/partial" \
    --accept --expect-complete 1 --deadline "$5" --hold 2 "${XA[@]}" "${RX[@]}"
  sleep 1
  node_start "sa$t" "$s" --port "$PORT" --book-dir "$W/$s" --dest "$W/$s/dest" --partial "$W/$s/partial" \
    --send "$W/src.bin" --send-to "$4" --expect-complete 1 --deadline "$5" --hold 2 "${XA[@]}" "${SX[@]}"
}
xfer_wait() { # метка секунды
  local i
  for i in $(seq 1 "$(( $2 * 2 ))"); do
    has "rb$1" '^RESULT xfer ' && return 0
    node_alive "rb$1" || { has "rb$1" '^RESULT xfer ' && return 0; return 1; }
    over_cap && return 1
    sleep 0.5
  done
  return 1
}
xfer_end() { # метка
  node_wait_exit "rb$1" 30 || node_kill "rb$1"
  node_wait_exit "sa$1" 30 || node_kill "sa$1"
}
# Целостность: cmp и sha256 получателя; пишет X_CMP (ok|DIFF|nofile) и X_NOTE.
X_CMP=""; X_NOTE=""
xfer_check() { # метка rcvns
  local f n h
  X_CMP=ok; X_NOTE=""
  f="$(find "$W/$2/dest" -maxdepth 1 -type f -name 'chervo-*-0' | head -n 1)"
  if [[ -z "$f" ]]; then X_CMP=nofile; return 0; fi
  cmp -s -- "$W/src.bin" "$f" || X_CMP=DIFF
  n="$(find "$W/$2/dest" -mindepth 1 -maxdepth 1 | wc -l)"
  [[ "$n" == 1 ]] || X_NOTE+="extra_in_dest($n) "
  h="$(sed -n 's/.*RESULT received index=0 .*sha256=\([0-9a-f]*\).*/\1/p' "$(lgf "rb$1")" | tail -n1)"
  if [[ -n "$h" && "$h" != "$SRC_SHA" ]]; then X_CMP=DIFF; fi
  return 0
}
# Несовпадение cmp/sha256: остановка speed/g7, логи остаются, эскалация (спецификация п. 16).
integrity_fail() { # id
  vd "$1" "${2:-speed}" FAIL "cmp или sha256 не совпали" "INTEGRITY: остановка, эскалация (целостность важнее скорости)"
  row_end
  echo "INTEGRITY FAIL в строке $1: остановка" >&2
  exit 6
}
cpu_pct() { # лог
  local s ts e te
  read -r s ts <<<"$(grep '^EVENT cpu phase=start ' "$1" | head -n1 | sed -n 's/.*ticks=\([0-9]*\) t=\([0-9]*\)$/\1 \2/p')"
  read -r e te <<<"$(grep '^EVENT cpu phase=end ' "$1" | tail -n1 | sed -n 's/.*ticks=\([0-9]*\) t=\([0-9]*\)$/\1 \2/p')"
  if [[ -n "${s:-}" && -n "${e:-}" ]]; then
    awk -v s="$s" -v e="$e" -v ts="$ts" -v te="$te" -v hz="$CLK_TCK" 'BEGIN { d = (te - ts) / 1000; if (d > 0) printf "%.0f", (e - s) / hz / d * 100; else printf "-" }'
  else
    printf '%s' "-"
  fi
}
cpu_snap() { awk '/^cpu / { idle = $5 + $6; tot = 0; for (i = 2; i <= 9; i++) tot += $i; print idle, tot; exit }' /proc/stat; }
# Максимальный простой между растущими строками progress, секунды
stall_of() { # метка
  awk '/^EVENT progress done=/ { split($3, a, "="); d = a[2] + 0; t = $NF; sub(/^t=/, "", t); t += 0
    if (d > last) { if (lt > 0 && t - lt > mx) mx = t - lt; last = d; lt = t } }
    END { printf "%.1f", mx / 1000 }' "$(lgf "$1")" 2>/dev/null
}
pct_of() { # метка
  awk '/^EVENT progress done=/ { split($3, a, "="); split($4, b, "="); if (b[2] > 0) p = int(a[2] * 100 / b[2]) } END { print p + 0 }' "$(lgf "$1")" 2>/dev/null || echo 0
}
wait_pct() { # метка мин секунды
  local i
  for i in $(seq 1 "$(( $3 * 5 ))"); do
    [[ "$(pct_of "$1")" -ge "$2" ]] && return 0
    over_cap && return 1
    sleep 0.2
  done
  return 1
}

# ---------------------------------------------------------------- G7 (задержка D20) и C20
g7_netem() { # ns...
  local n
  for n in "$@"; do netem_set "$n" 10 100mbit 500 ""; done
}
g7_finish_note() { # id tag rcv tstart
  local conns pz rs st tot
  conns="$(cntl "sa$2" '^EVENT connected pair=')"
  pz="$(( $(cntl "rb$2" '^EVENT paused') + $(cntl "sa$2" '^EVENT paused') ))"
  rs="$(( $(cntl "rb$2" '^EVENT resumed') + $(cntl "sa$2" '^EVENT resumed') ))"
  st="$(stall_of "rb$2")"
  tot=$(( $(now_s) - $4 ))
  G7_NOTE="connections=$conns paused=$pz resumed=$rs max_stall_s=$st total_s=$tot cmp=$X_CMP $X_NOTE"
  G7_PZ="$pz"; G7_RS="$rs"; G7_CONNS="$conns"; G7_STALL="$st"
}
G7_NOTE=""; G7_PZ=0; G7_RS=0; G7_CONNS=0; G7_STALL=0

g7_run() { # id тип
  local id="$1" kind="$2" r s lab t0 v=PASS ports="" ev="" exp="completes, cmp equal" i rbnv=""
  XA=(); RX=(); SX=(); AX=(); BX=(); XA_EXTRA=(); WHY=""; TOKRES=""
  case "$kind" in
    DROP15) exp="completes without pause, cmp equal, no connection events after the drop, paused=0, max_stall_s<=30" ;;
    DROP45) exp="paused, resumed, cmp equal" ;;
    REBIND) exp="completes, cmp equal, HA nat_view not Conflicting 60 s after NAT-A WAN change" ;;
  esac
  if [[ "$kind" == REBIND ]] && nat_type_bad PR@na; then vd "$id" g7 INCONCLUSIVE "-" "контроль типа PR не прошёл"; return 0; fi
  row_begin "$id" 600 || { vd "$id" g7 INCONCLUSIVE "-" "топология не поднялась"; row_end; return 0; }
  case "$kind" in
    BASE|CALLEE|DROP15|DROP45) r=wb; s=wa; lab=o1; ports="wa wb"; flow_pair wa wb || true ;;
    LAPTOP) r=wa; s=ha; lab=i1; ports="wa na na2"; flow_pair wa ha || true ;;
    REBIND) r=wa; s=ha; lab=i1; ports="wa na"; flow_pair wa ha || true ;;
  esac
  nodes_stop_all
  if [[ -n "$WHY" ]]; then row_end; vd "$id" g7 INCONCLUSIVE "-" "$WHY"; return 0; fi
  # задержка D20 включается после пары: приглашение не должно зависеть от неё
  # shellcheck disable=SC2086
  g7_netem $ports
  src_make 256
  xfer_start 1 "$r" "$s" "$lab" 560
  t0="$(now_s)"
  if [[ "$kind" != BASE ]]; then
    if wait_pct rb1 30 200; then
      case "$kind" in
        CALLEE) ipn wb addr add "$CORE.52/24" dev wan; ipn wb addr del "$CORE.51/24" dev wan; ev="IP wb changed" ;;
        DROP15)
          # Rev. 3 (S4): события соединения считаются только после метки перед обрывом
          # (дубль одновременного открытия на старте в счёт не идёт)
          G7_MARK="$(( $(cntl sa1 '^EVENT (connected|disconnected) pair=') + $(cntl rb1 '^EVENT (connected|disconnected) pair=') ))"
          drop_on wa "$CORE.51"; sleep 15; drop_off wa; ev="UDP dropped 15 s" ;;
        DROP45) drop_on wa "$CORE.51"; sleep 45; drop_off wa; ev="UDP dropped 45 s" ;;
        REBIND)
          ipn na addr add "$CORE.11/24" dev wan
          ipn na addr del "$CORE.10/24" dev wan
          ev="NAT-A wan changed"
          for i in $(seq 1 60); do node_alive sa1 || break; over_cap && break; sleep 1; done
          rbnv="$(nat_view_of sa1)" ;;
        LAPTOP)
          ipn ha link set eth1 up
          ipn ha route replace default via 192.168.12.1 dev eth1
          ipn ha link set eth0 down; ev="eth0 -> eth1" ;;
        *) ;;
      esac
    else
      v=INCONCLUSIVE; ev="30% not reached"
    fi
  fi
  xfer_wait 1 420 || { [[ "$v" == PASS ]] && v=FAIL; }
  xfer_end 1
  xfer_check 1 "$r"
  g7_finish_note "$id" 1 "$r" "$t0"
  [[ "$X_CMP" == DIFF ]] && integrity_fail "$id" g7
  if [[ "$X_CMP" != ok && "$v" == PASS ]]; then v=FAIL; fi
  # Rev. 2 (S3): простой QUIC 30 с, keep-alive 10 с: обрыв 15 с не закрывает соединение (пауз нет), обрыв 45 с закрывает.
  if [[ "$kind" == DROP15 && "$v" == PASS ]]; then
    local after
    after=$(( $(cntl sa1 '^EVENT (connected|disconnected) pair=') + $(cntl rb1 '^EVENT (connected|disconnected) pair=') - ${G7_MARK:-0} ))
    G7_NOTE+="conn_events_after_drop=$after; "
    if (( after != 0 || G7_PZ != 0 )) || ! awk -v s="$G7_STALL" 'BEGIN { exit (s + 0 <= 30) ? 0 : 1 }'; then
      v=FAIL; G7_NOTE+="expected conn_events_after_drop=0 paused=0 max_stall_s<=30; "
    fi
  fi
  if [[ "$kind" == DROP45 && "$v" == PASS ]] && ! (( G7_PZ > 0 && G7_RS > 0 )); then v=FAIL; G7_NOTE+="no paused/resumed; "; fi
  if [[ "$kind" == REBIND && "$v" == PASS ]]; then
    G7_NOTE+="nat_view_ha_60s=${rbnv:-none}; "
    [[ "$rbnv" != Conflicting ]] || { v=FAIL; G7_NOTE+="nat_view Conflicting 60 s after change; "; }
  fi
  if over_cap && [[ "$v" == PASS ]]; then v=INCONCLUSIVE; G7_NOTE+="timeout; "; fi
  verdict "$id" g7 "$v" "$exp" "$([[ "$v" == PASS ]] && echo completed || echo "see note")" - - - - - \
    "$(( $(now_s) - t0 ))" "event: ${ev:-none}; $G7_NOTE"
  row_end
}

# C20: HA -> HB (PR-PR по токенам), NAT-A меняет внешний адрес на ~30 %.
c20_run() {
  local id=C20 t0 v=PASS note="" first="$STATE/tok-first" ok=0 tstart n stale=no k
  XA=(); RX=(); SX=(); XA_EXTRA=(); AX=(); BX=(); WHY=""; TOKRES=""
  if nat_type_bad PR@na || nat_type_bad PR@nb; then vd $id g7 INCONCLUSIVE "-" "контроль типа PR не прошёл"; return 0; fi
  row_begin $id 600 || { vd $id g7 INCONCLUSIVE "-" "топология не поднялась"; row_end; return 0; }
  flow_meet ha hb "" || true
  if [[ -z "$WHY" ]]; then
    token_pass ha hb "$first"
    [[ $TOKOK == 1 ]] || WHY="токен ha->hb не доставлен: $TOKRES"
  fi
  if [[ -z "$WHY" ]]; then
    token_pass hb ha
    [[ $TOKOK == 1 ]] || WHY="токен hb->ha не доставлен: $TOKRES"
  fi
  if [[ -n "$WHY" ]]; then row_end; vd $id g7 INCONCLUSIVE "-" "$WHY"; return 0; fi
  # узлы пары перезапускаются для передачи; наблюдатели wa, wb остаются
  node_stop ha; node_stop hb
  rm -f -- "$W/hb/tok-in" "$W/ha/tok-in"
  g7_netem na nb wa wb
  src_make 256
  RX=(--token-in "$W/hb/tok-in")
  SX=(--token-to o1 --token-out "$W/ha/tok")
  xfer_start 1 hb ha o1 560
  t0="$(now_s)"
  if wait_pct rb1 30 240; then
    ipn na addr add "$CORE.11/24" dev wan
    ipn na addr del "$CORE.10/24" dev wan
    note+="NAT-A wan changed; "
    tstart="$(now_s)"
    # ha узнаёт новый внешний адрес от наблюдателей; токен выпускается и доставляется, пока hb его не увидит
    while (( $(now_s) - tstart < 130 )); do
      token_pass2 sa1 ha rb1 hb
      if grep '^STATE ' "$(lgf rb1)" | tail -n1 | grep -o 'friend:i3=\[[^]]*\]' | grep -q "$CORE.11:"; then ok=2; break; fi
      over_cap && break
      sleep 10
    done
    if [[ "$ok" == 2 ]]; then
      # повторная доставка первого токена: ожидается StaleSeq
      n="$(cntl rb1 '^EVENT token_rejected error=.*StaleSeq')"
      cp -- "$first" "$W/hb/tok-in.tmp" && mv -- "$W/hb/tok-in.tmp" "$W/hb/tok-in"
      for k in $(seq 1 40); do
        [[ "$(cntl rb1 '^EVENT token_rejected error=.*StaleSeq')" -gt "$n" ]] && { stale=yes; break; }
        sleep 0.5
      done
      note+="first token redelivered: StaleSeq=$stale; "
      [[ "$stale" == yes ]] || v=FAIL
    else
      v=FAIL; note+="observed address not refreshed after NAT rebinding; "
    fi
  else
    v=INCONCLUSIVE; note+="30% not reached; "
  fi
  xfer_wait 1 300 || { [[ "$v" == PASS ]] && v=FAIL; note+="transfer not completed; "; }
  xfer_end 1
  xfer_check 1 hb
  g7_finish_note $id 1 hb "$t0"
  [[ "$X_CMP" == DIFF ]] && integrity_fail $id g7
  if [[ "$X_CMP" != ok && "$v" == PASS ]]; then v=FAIL; note+="cmp $X_CMP; "; fi
  (( G7_PZ > 0 )) || note+="no paused seen; "
  if (( G7_RS == 0 )) && [[ "$v" == PASS ]]; then v=FAIL; note+="no resumed seen; "; fi
  verdict $id g7 "$v" "paused, resumed, cmp equal, stale first token rejected" "$([[ "$v" == PASS ]] && echo completed || echo "see note")" \
    - - - - - "$(( $(now_s) - t0 ))" "$G7_NOTE; ${note}tokens: ${TOKRES:-none}"
  row_end
}

# ---------------------------------------------------------------- скорость
P_DELAY=0; P_RATE=""; P_LIMIT=0; P_LOSS=""; P_MIB=0; P_RATE_MBIT=0
prof_load() { # профиль; XA задаёт окно/потоки
  local free
  XA=()
  P_DELAY=0; P_RATE=""; P_LIMIT=0; P_LOSS=""; P_RATE_MBIT=0
  case "$1" in
    N0) P_MIB=1024 ;;
    R1) P_DELAY=10; P_RATE=100mbit; P_LIMIT=500; P_RATE_MBIT=100; P_MIB=128 ;;
    R2) P_DELAY=40; P_RATE=100mbit; P_LIMIT=1700; P_RATE_MBIT=100; P_MIB=128 ;;
    R2-W1) P_DELAY=40; P_RATE=100mbit; P_LIMIT=1700; P_RATE_MBIT=100; P_MIB=128; XA=(--streams 1 --window 1) ;;
    R3) P_DELAY=20; P_RATE=100mbit; P_LIMIT=900; P_LOSS=0.5; P_RATE_MBIT=100; P_MIB=64 ;;
    R4) P_DELAY=10; P_RATE=1gbit; P_LIMIT=4200; P_RATE_MBIT=1000; P_MIB=512 ;;
    P1) P_DELAY=75; P_RATE=50mbit; P_LIMIT=1500; P_RATE_MBIT=50; P_MIB=128 ;;
    P2) P_DELAY=75; P_RATE=50mbit; P_LIMIT=1500; P_LOSS=1; P_RATE_MBIT=50; P_MIB=64 ;;
    P3) P_DELAY=25; P_RATE=50mbit; P_LIMIT=800; P_LOSS=3; P_RATE_MBIT=50; P_MIB=64 ;;
    *) return 1 ;;
  esac
  # места мало: N0 и R4 уменьшаются (записывается в байтах строки)
  free="$(df -Pk "$STATE" | awk 'NR == 2 { print int($4 / 1048576) }')"
  if (( ${free:-0} < 4 )); then
    [[ "$1" != N0 ]] || P_MIB=512
    [[ "$1" != R4 ]] || P_MIB=256
  fi
  return 0
}
port_addr() { # ns порта -> адрес для ping с i
  case "$1" in
    wa) echo "$CORE.50" ;; wb) echo "$CORE.51" ;; nr) echo "$CORE.20" ;;
    na) echo "$CORE.10" ;; nb) echo "$CORE.30" ;; *) echo "$CORE.254" ;;
  esac
}
# ping с i: среднее RTT в мс; пусто, если не вышло
ping_avg() { # ns порта
  nsx i ping -c 5 -i 0.2 -W 2 -q "$(port_addr "$1")" 2>/dev/null | sed -n 's|^rtt [^=]*= [0-9.]*/\([0-9.]*\)/.*|\1|p' | head -n1
}

speed_cfg() { # путь профиль
  local path="$1" prof="$2" id="S-$1-$2" r s lab sp="" rp="" k off=1 ctl_rtt="-" ctl_loss="-" avg d
  local fin=0 mib ms bytes mibps lines=() cs=() cr=() cores load1 i0 t0_ i1 t1_ cpu_s cpu_r ctl_rate st0 st1 sent dropped ratio conn_ms
  local rates=() flagbad=0 notes=""
  WHY=""; TOKRES=""; RX=(); SX=(); AX=(); BX=(); XA_EXTRA=()
  prof_load "$prof" || { vd "$id" speed NOTRUN "-" "нет профиля $prof"; return 0; }
  case "$path" in
    UPNP) [[ $HAVE_MPD == 1 ]] || { vd "$id" speed INCONCLUSIVE "-" "CHV_MINIUPNPD не задан"; return 0; } ;;
  esac
  case "$path" in
    PUNCH) if nat_type_bad PR@na || nat_type_bad PR@nb; then vd "$id" speed INCONCLUSIVE "-" "контроль типа PR не прошёл"; return 0; fi ;;
  esac
  row_begin "$id" 900 || { vd "$id" speed INCONCLUSIVE "-" "топология не поднялась"; row_end; return 0; }
  NODE_NICE="$NICE_N"
  case "$path" in
    LAN) r=ha2; s=ha; lab=o1; AX=(--invite-lan); flow_pair ha ha2 || true ;;
    WHITE) r=wb; s=wa; lab=o1; sp=wa; rp=wb; flow_pair wa wb || true ;;
    UPNP)
      r=hr; s=wa; lab=i1; sp=wa; rp=nr
      mpd_start || WHY="miniupnpd не запустился"
      AX=(--upnp-router "$UDN")
      [[ -n "$WHY" ]] || flow_pair hr wa || true ;;
    PUNCH)
      r=hb; s=ha; lab=o1; sp=na; rp=nb
      flow_meet ha hb "xy yx" || true
      if [[ -z "$WHY" && "$TOKRES" != *"ha>hb:ok"* ]]; then WHY="токены не доставлены: $TOKRES"; fi ;;
    *) WHY="неизвестный путь $path" ;;
  esac
  nodes_stop_all
  if [[ -n "$WHY" ]]; then row_end; vd "$id" speed INCONCLUSIVE "-" "$WHY"; return 0; fi
  [[ "$path" != UPNP ]] || RX=(--upnp-router "$UDN")
  offloads_off || off=0
  if [[ $off == 0 && -n "$P_LOSS" ]]; then row_end; vd "$id" speed INCONCLUSIVE "-" "offload not disabled: ${OFF_WHY:-причина не определена}"; return 0; fi
  [[ $off == 1 ]] || notes+="offload not disabled (${OFF_WHY:-?}); "
  if [[ -n "$P_RATE" && -n "$sp" ]]; then
    netem_set "$sp" "$P_DELAY" "$P_RATE" "$P_LIMIT" ""
    netem_set "$rp" "$P_DELAY" "$P_RATE" "$P_LIMIT" "$P_LOSS"
    for k in "$sp" "$rp"; do
      avg="$(ping_avg "$k")"
      if [[ -z "$avg" ]]; then ctl_rtt=FAIL
      elif awk -v a="$avg" -v d="$P_DELAY" 'BEGIN { exit (a >= d * 0.75 - 1 && a <= d * 1.25 + 1) ? 0 : 1 }'; then
        [[ "$ctl_rtt" == FAIL ]] || ctl_rtt=ok
      else ctl_rtt=FAIL
      fi
    done
  fi
  src_make "$P_MIB"
  [[ -z "$rp" ]] || st0="$(tc_stat "$rp")"
  conn_ms=()
  for k in $(seq 1 "$REPEATS"); do
    over_cap && { notes+="cap 15 min reached before rep $k; "; break; }
    load1="$(awk '{print $1}' /proc/loadavg)"
    read -r i0 t0_ <<<"$(cpu_snap)"
    xfer_start "$k" "$r" "$s" "$lab" 240
    if [[ "$path" == UPNP ]]; then wait_grep "rb$k" 'mapping=Mapped' 40 || true; fi
    xfer_wait "$k" 180 && fin=1 || fin=0
    xfer_end "$k"
    read -r i1 t1_ <<<"$(cpu_snap)"
    xfer_check "$k" "$r"
    [[ "$X_CMP" != DIFF ]] || integrity_fail "$id" speed
    cores="$(awk -v i0="$i0" -v t0="$t0_" -v i1="$i1" -v t1="$t1_" -v n="$(nproc)" 'BEGIN { dt = t1 - t0; if (dt > 0) printf "%.1f", (1 - (i1 - i0) / dt) * n; else printf "-" }')"
    cpu_s="$(cpu_pct "$(lgf "sa$k")")"; cpu_r="$(cpu_pct "$(lgf "rb$k")")"
    conn_ms+=("$(grep '^EVENT connected ' "$(lgf "sa$k")" | head -n1 | tms)")
    if (( fin == 1 )); then
      read -r bytes ms <<<"$(grep '^RESULT xfer ' "$(lgf "rb$k")" | tail -n1 | sed -n 's/.*bytes=\([0-9]*\) ms=\([0-9]*\).*/\1 \2/p')"
      mibps="$(awk -v b="$bytes" -v m="$ms" 'BEGIN { if (m > 0) printf "%.2f", b / 1048576 / (m / 1000); else printf "-" }')"
      ctl_rate="-"
      if [[ "$P_RATE_MBIT" -gt 0 && "$mibps" != "-" ]]; then
        ctl_rate="$(awk -v v="$mibps" -v r="$P_RATE_MBIT" 'BEGIN { print (v * 8 * 1.048576 <= r * 1.05) ? "ok" : "FAIL" }')"
      fi
      rates+=("$mibps")
    else
      bytes="$(grep '^EVENT progress done=' "$(lgf "rb$k")" | tail -n1 | sed -n 's/.*done=\([0-9]*\).*/\1/p')"
      bytes="${bytes:-0}"; ms="-"; mibps="-"; ctl_rate="-"
      notes+="rep $k not finished in 180 s; "
    fi
    lines+=("$path"$'\t'"$prof"$'\t'"$k"$'\t'"$bytes"$'\t'"$ms"$'\t'"$mibps"$'\t'"$cpu_s"$'\t'"$cpu_r"$'\t'"$cores"$'\t'"$load1"$'\t'"$X_CMP"$'\t'"$ctl_rate")
    rm -rf -- "$W/$r/dest" "$W/$r/partial"
  done
  if [[ -n "$P_LOSS" && -n "$rp" ]]; then
    st1="$(tc_stat "$rp")"
    sent=$(( ${st1%% *} - ${st0%% *} )); dropped=$(( ${st1##* } - ${st0##* } ))
    ratio="$(awk -v s="$sent" -v d="$dropped" 'BEGIN { if (s + d > 0) printf "%.3f", 100 * d / (s + d); else printf "0" }')"
    if awk -v r="$ratio" -v p="$P_LOSS" 'BEGIN { exit (r >= 0.5 * p && r <= 2 * p) ? 0 : 1 }'; then ctl_loss=ok; else ctl_loss=FAIL; fi
    notes+="loss ratio ${ratio}% (target ${P_LOSS}%); "
  fi
  # запись строк speed16.tsv (старые строки этой конфигурации заменяются)
  mkdir -p -- "$LOGS"; touch "$SPEEDTSV"
  awk -F'\t' -v p="$path" -v q="$prof" '!($1 == p && $2 == q)' "$SPEEDTSV" > "$SPEEDTSV.tmp" || true
  mv -- "$SPEEDTSV.tmp" "$SPEEDTSV"
  local ln
  for ln in "${lines[@]}"; do printf '%s\t%s\t%s\n' "$ln" "$ctl_rtt" "$ctl_loss" >> "$SPEEDTSV"; done
  local med v=PASS cms
  med="$(printf '%s\n' "${rates[@]}" | median)"
  cms="$(printf '%s\n' "${conn_ms[@]}" | median)"
  [[ ${#rates[@]} -ge 1 ]] || v=INCONCLUSIVE
  [[ ${#rates[@]} -ge "$REPEATS" ]] || { v=INCONCLUSIVE; notes+="не все повторы завершены; "; }
  grep -Eq 'FAIL|nofile' <<<"$ctl_rtt $ctl_loss $(printf '%s ' "${lines[@]}" | tr '\t' ' ')" && { v=INCONCLUSIVE; notes+="control failed (числа сохранены с пометкой); "; }
  verdict "$id" speed "$v" "справочно, cmp равен" "median ${med} MiB/s (repeats=${#rates[@]}), connect_ms=${cms}" - - - - - "-" \
    "под nice ${NICE_N}; ${notes}"
  row_end
}

SPEED_CONFIGS=(
  "LAN N0"
  "WHITE N0" "WHITE R1" "WHITE R2" "WHITE R2-W1" "WHITE R3" "WHITE R4" "WHITE P1" "WHITE P2" "WHITE P3"
  "UPNP N0" "UPNP R1"
  "PUNCH N0" "PUNCH R1"
)
do_speed() {
  local c
  for c in "${SPEED_CONFIGS[@]}"; do
    # shellcheck disable=SC2086
    speed_cfg $c
  done
  verdict S-IPV6 speed NOTRUN "-" "-" - - - - - - "IPv6 listening deferred by owner"
}

# ---------------------------------------------------------------- прочие строки
x02_row() {
  verdict X02 extra NOTRUN "-" "-" - - - - - - \
    "поток из спецификации не определён однозначно: WB одновременно получатель подсказки и честный наблюдатель; в спецификации место подмены addrinfo.rs, но адрес в кадр пишет crates/chervo-token/src/addr_flow.rs; нужно решение архитектора (build-liar для addr_flow.rs готов)"
}

do_build_liar() {
  [[ "$(id -u)" != 0 ]] || die "build-liar запускается от обычного пользователя, не от root"
  command -v cargo >/dev/null 2>&1 || die "нет cargo"
  local d f n1 n2 e1 e2
  d="$(mktemp -d /tmp/chervo-liar.XXXXXX)"; chmod 700 -- "$d"
  cp -r "$REPO/crates" "$REPO/Cargo.toml" "$REPO/Cargo.lock" "$REPO/rust-toolchain.toml" "$d/"
  f="$d/crates/chervo-token/src/addr_flow.rs"
  e1='let frame = encode_addr_info(normalize(conn.remote_addr()), ours)?;'
  e2='let frame = encode_addr_info(via, ours)?;'
  n1="$(grep -cF -- "$e1" "$f" || true)"; n2="$(grep -cF -- "$e2" "$f" || true)"
  if [[ "$n1" != 1 || "$n2" != 1 ]]; then
    rm -rf -- "$d"
    echo "NOTRUN: выражения подмены найдены $n1 и $n2 раз (нужно по одному): код изменился, X02 не собирается" >&2
    exit 3
  fi
  sed -i \
    -e "s|let frame = encode_addr_info(normalize(conn.remote_addr()), ours)?;|let frame = encode_addr_info(\"$CORE.66:4433\".parse().expect(\"liar\"), ours)?;|" \
    -e "s|let frame = encode_addr_info(via, ours)?;|let frame = encode_addr_info(\"$CORE.66:4433\".parse().expect(\"liar\"), ours)?;|" \
    "$f"
  ( cd "$d" && CARGO_TARGET_DIR="$d/target" cargo build --release --locked -p chervo-transfer --example node16 ) >&2 \
    || { echo "сборка не удалась; каталог $d оставлен для разбора" >&2; exit 3; }
  echo "$d/target/release/examples/node16"
  echo "после использования: rm -rf '$d'" >&2
}

# ---------------------------------------------------------------- preflight
do_preflight() {
  local t miss="" free ok=1 v
  for t in ip nft tc tcpdump; do
    command -v "$t" >/dev/null 2>&1 || { echo "PREFLIGHT FAIL: нет $t" >&2; ok=0; }
  done
  [[ $ok == 1 ]] || exit 3
  # netem на одноразовой паре veth в своём ns
  if ip netns add "${PFX}pf" 2>/dev/null; then
    if ! { ip -n "${PFX}pf" link add pf0 type veth peer name pf1 \
        && ip -n "${PFX}pf" link set pf0 up \
        && nsx pf tc qdisc add dev pf0 root netem delay 1ms limit 100 rate 100mbit \
        && nsx pf nft list ruleset >/dev/null; } 2>/dev/null; then
      ok=0; echo "PREFLIGHT FAIL: tc netem или nft внутри ns не работают" >&2
    fi
    ip netns del "${PFX}pf" 2>/dev/null || true
  else
    ok=0; echo "PREFLIGHT FAIL: не удалось создать ns ${PFX}pf" >&2
  fi
  [[ $ok == 1 ]] || exit 3
  for t in ping ethtool getconf sha256sum cmp nice awk sed; do
    command -v "$t" >/dev/null 2>&1 || miss+="$t "
  done
  free="$(df -Pk "$STATE" | awk 'NR == 2 { print int($4 / 1048576) }')"
  echo "PREFLIGHT: root ok; ip nft tc tcpdump ok; netem в ns ok; отсутствуют: ${miss:-ничего}; свободно в STATE: ${free:-?} ГиБ"
  echo "PREFLIGHT: бинарники: node16 ok; spike8=$HAVE_SPIKE8 miniupnpd=$HAVE_MPD liar=$HAVE_LIAR"
  [[ -z "$miss" ]] || echo "PREFLIGHT: зависимые строки будут помечены (ping: контроль RTT; ethtool: offload и строки с потерями; getconf: CPU)" >&2
  (( ${free:-0} >= 4 )) || echo "PREFLIGHT: места меньше 4 ГиБ: N0 и R4 уменьшатся до 512 и 256 МиБ" >&2
  mkdir -p -- "$LOGS"
  v="$(systemd-detect-virt 2>/dev/null || true)"
  {
    echo "date=$(date +%F)"
    echo "commit=$(git -c safe.directory="$REPO" -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "kernel=$(uname -r)"
    echo "nproc=$(nproc)"
    echo "cpu=$(awk -F': ' '/model name/ { print $2; exit }' /proc/cpuinfo)"
    echo "virt=${v:-unknown}"
    echo "nft=$(nft --version 2>&1 | head -n1)"
    echo "tc=$(tc -V 2>&1 | head -n1)"
    echo "iproute2=$(ip -V 2>&1 | head -n1)"
    echo "miniupnpd=${CHV_MINIUPNPD_VERSION:-не определена (передайте CHV_MINIUPNPD_VERSION)}"
    echo "rustc=${CHV_RUSTC_VERSION:-не определена (передайте CHV_RUSTC_VERSION)}"
    echo "nice=$NICE_N"
    echo "repeats=$REPEATS"
    echo "clk_tck=$(getconf CLK_TCK 2>/dev/null || echo 100)"
  } > "$LOGS/meta16.txt"
}

# ---------------------------------------------------------------- диспетчер строк
run_row() { # id
  case "$1" in
    NATCHECK) do_natcheck ;;
    C02) verdict C02 conn NOTRUN "NOTRUN" "-" - - - - - - "IPv6 listening deferred by owner" ;;
    V01) verdict V01 via NOTRUN "yes (EIM both)" "-" - - - - - - "stage 13b deferred by owner" ;;
    V02) verdict V02 via NOTRUN "depends on both CGNATs being EIM" "-" - - - - - - "stage 13b deferred by owner" ;;
    V03) verdict V03 via NOTRUN "no" "-" - - - - - - "stage 13b deferred by owner" ;;
    V04) verdict V04 via NOTRUN "no" "-" - - - - - - "stage 13b deferred by owner" ;;
    V05) verdict V05 via NOTRUN "yes" "-" - - - - - - "stage 13b deferred by owner" ;;
    C20) c20_run ;;
    C0[1-9]|C1[0-9]|C07H) conn_run "$1" ;;
    X01) conn_run C06 ;;
    X02) x02_row ;;
    G7-BASE) g7_run G7-BASE BASE ;;
    G7-CALLEE) g7_run G7-CALLEE CALLEE ;;
    G7-LAPTOP) g7_run G7-LAPTOP LAPTOP ;;
    G7-DROP15) g7_run G7-DROP15 DROP15 ;;
    G7-DROP45) g7_run G7-DROP45 DROP45 ;;
    G7-REBIND) g7_run G7-REBIND REBIND ;; # ожидание спецификации 20.3; запуск имеет смысл после этапа 16a (П1)
    S-IPV6) verdict S-IPV6 speed NOTRUN "-" "-" - - - - - - "IPv6 listening deferred by owner" ;;
    S-*)
      local rest="${1#S-}"
      speed_cfg "${rest%%-*}" "${rest#*-}" ;;
    *) return 2 ;;
  esac
}

do_conn() {
  local id
  for id in "${CONN_IDS[@]}"; do run_row "$id"; done
  for id in V01 V02 V03 V04 V05; do run_row "$id"; done
}
do_g7() {
  local id
  # G7-REBIND в `g7` и `all` не входит: его ожидание проверяется после этапа 16a (запуск вручную: stage16.sh G7-REBIND)
  for id in G7-BASE G7-CALLEE G7-LAPTOP G7-DROP15 G7-DROP45 C20; do run_row "$id"; done
}

usage() {
  echo "использование: stage16.sh <preflight|natcheck|conn|speed|g7|extra|quick|all|id строки|teardown|build-liar>" >&2
  echo "id строки: NATCHECK C01..C20 C07H V01..V05 G7-BASE G7-CALLEE G7-LAPTOP G7-DROP15 G7-DROP45 G7-REBIND S-<ПУТЬ>-<ПРОФИЛЬ> X01 X02" >&2
}

# ---------------------------------------------------------------- вход и уборка
cleanup() {
  local l
  if [[ "$STARTED" == 1 ]]; then
    for l in "${!NODE_REAL[@]}"; do node_kill "$l"; done
    mpd_stop 2>/dev/null || true
    tcpd_stop 2>/dev/null || true
    do_teardown || true
    if [[ -n "${SUDO_UID:-}" && -d "$LOGS" ]]; then chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" -- "$LOGS" 2>/dev/null || true; fi
  fi
  if [[ "$STATE_OWNED" == 1 && "${CHV_KEEP:-0}" != 1 && -n "$STATE" && "$STATE" != / ]]; then rm -rf -- "$STATE"; fi
}

main() {
  case "$CMD" in
    build-liar) do_build_liar; exit 0 ;;
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
    preflight) do_preflight ;;
    natcheck) do_natcheck ;;
    conn) do_conn ;;
    speed) do_speed ;;
    g7) do_g7 ;;
    extra) run_row C06; x02_row ;;
    quick)
      REPEATS=1
      do_natcheck
      for id in C03 C06 C11 C13 C19 S-WHITE-N0; do run_row "$id"; done ;;
    all)
      do_preflight
      do_natcheck
      do_conn
      do_g7
      do_speed
      x02_row
      echo "--- $SUMMARY"; cat -- "$SUMMARY" ;;
    *)
      run_row "$CMD"
      if [[ $? == 2 ]]; then usage; exit 2; fi ;;
  esac
  hostsafe_end "$CMD"
}
main
