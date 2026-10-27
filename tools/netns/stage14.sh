#!/usr/bin/env bash
# Стенд netns этапа 14 (часть X4): передача файлов chervo-transfer между двумя белыми узлами.
# Использование:
#   sudo bash tools/netns/stage14.sh <xfer|drop|addrchange|killrecv|tbf|capture|all|teardown>
# Требуется Linux, root, ip, nft; для строк с ограничением скорости (drop, addrchange, killrecv, tbf) ещё tc.
# Узел: пример node14 крейта chervo-transfer. Бинарник можно передать готовым:
#   CHV_NODE14=/путь/к/node14   (владелец root или SUDO_UID, без записи для группы и остальных)
# иначе (если есть cargo) он собирается: cargo build --release --locked -p chervo-transfer --example node14.
# У root на Linux-машине cargo может не быть: тогда собрать узел от обычного пользователя и передать CHV_NODE14.
# Каталог логов: CHV_LOGS=/путь (по умолчанию tools/netns/logs14). Адресное пространство стенда: CORE=11.0.0.
# Размеры (МиБ): CHV_XFER_MIB=1024 (xfer), CHV_ROW_MIB=256 (drop, addrchange, killrecv), CHV_TBF_MIB=128 (tbf),
# CHV_CAP_MIB=64 (capture). Скорость отправителя в строках drop, addrchange, killrecv: CHV_ROW_RATE=100mbit
# (иначе передача по veth кончается быстрее, чем стенд успевает её прервать).
#
# НЕ ПРОГОНЯЛСЯ на машине сборки (Windows): здесь проверен только `bash -n`. Прогон на Linux делает дирижёр.
#
# Хозяйство стенда скопировано из stage13.sh (log, nsx, spk_in, bg_start, bg_stop, cnt, kv, verdict) без изменения
# смысла; префикс ns другой (chv14-), чтобы стенды разных этапов не мешали друг другу. Стенд трогает только
# свои ns chv14-*, их каталоги /etc/netns/chv14-*; nft и sysctl только внутри ns (`ip netns exec`).
# Узлы запускаются только внутри ns (env -i). Ключи пар узла лежат в простых файлах его book-dir (пример node14),
# поэтому узел можно перезапустить (строка killrecv) с теми же друзьями.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
# Рабочий каталог (бинарники и данные строк): непредсказуемое имя, режим 700. Своё значение CHV_STATE допускается,
# только если оно не символьная ссылка и принадлежит запускающему; проверки идут до mkdir и chmod.
STATE_OWNED=0
if [[ -n "${CHV_STATE:-}" ]]; then
  STATE="$CHV_STATE"
  [[ ! -L "$STATE" ]] || { echo "CHV_STATE не должен быть символьной ссылкой" >&2; exit 2; }
  if [[ -e "$STATE" ]]; then
    [[ -d "$STATE" && "$(stat -c %u -- "$STATE")" == "$(id -u)" ]] || { echo "CHV_STATE не каталог или не принадлежит текущему пользователю" >&2; exit 2; }
  fi
  mkdir -p -- "$STATE"
  [[ ! -L "$STATE" && "$(stat -c %u -- "$STATE")" == "$(id -u)" ]] || { echo "CHV_STATE не принадлежит текущему пользователю" >&2; exit 2; }
  chmod 700 -- "$STATE"
else
  STATE="$(mktemp -d /tmp/chervo-stage14.XXXXXX)"
  chmod 700 -- "$STATE"
  STATE_OWNED=1
fi
LOGS="${CHV_LOGS:-$ROOT/logs14}"
BIN="$STATE/bin"
NODE="$BIN/node14"
CORE="${CORE:-11.0.0}"
PORT=4433
XFER_MIB="${CHV_XFER_MIB:-1024}"
ROW_MIB="${CHV_ROW_MIB:-256}"
TBF_MIB="${CHV_TBF_MIB:-128}"
CAP_MIB="${CHV_CAP_MIB:-64}"
ROW_RATE="${CHV_ROW_RATE:-100mbit}"
SUMMARY="$LOGS/summary14.txt"
CMD="${1:-}"
# белые узлы: wa (отправитель), wb (получатель); i — «интернет» (мост)
NSL=(i wa wb)
RD=""
W=""
declare -A NODE_REAL=() NODE_WRAP=()
BG_REAL=""; BG_WRAP=""

log() { echo "[stage14.sh] $*" >&2; }
nsx() { local ns="$1"; shift; ip netns exec "chv14-$ns" "$@"; }
spk_in() { local ns="$1"; shift; nsx "$ns" env -i PATH="$PATH" "$@"; }
mkdirs() { mkdir -p "$LOGS"; }
ipn() { local ns="$1"; shift; ip -n "chv14-$ns" "$@"; }
kv() { sed -n "s/.* $2=\([^ ]*\).*/\1/p" | head -n1; }

# ---------------------------------------------------------------- сборка или готовый узел
do_node() {
  mkdir -p "$BIN"
  if [[ -n "${CHV_NODE14:-}" ]]; then
    local src="$CHV_NODE14" own mode
    [[ -f "$src" && -x "$src" && ! -L "$src" ]] || { echo "CHV_NODE14: нужен исполняемый обычный файл (не ссылка)" >&2; exit 2; }
    own="$(stat -c %u -- "$src")"; mode="$(stat -c %a -- "$src")"
    [[ "$own" == 0 || "$own" == "${SUDO_UID:-0}" ]] || { echo "CHV_NODE14: владелец не root и не SUDO_UID" >&2; exit 2; }
    (( (8#$mode & 8#022) == 0 )) || { echo "CHV_NODE14: запись разрешена группе или остальным" >&2; exit 2; }
    cp -- "$src" "$NODE"
  elif command -v cargo >/dev/null 2>&1; then
    log "cargo build (вне ns)"
    ( cd "$REPO"
      cargo build --release --locked -p chervo-transfer --example node14
    ) >&2
    cp "$REPO/target/release/examples/node14" "$NODE"
  else
    echo "INCONCLUSIVE: нет cargo; соберите node14 и передайте CHV_NODE14=/путь" >&2
    exit 3
  fi
  chmod 755 -- "$NODE"
}

# ---------------------------------------------------------------- стенд
do_teardown() {
  set +e
  local n
  for n in "${NSL[@]}"; do
    if ip netns list 2>/dev/null | grep -q "^chv14-$n\b"; then
      ip netns pids "chv14-$n" 2>/dev/null | xargs -r kill 2>/dev/null
    fi
  done
  sleep 0.5
  for n in "${NSL[@]}"; do
    ip netns del "chv14-$n" 2>/dev/null
    rm -rf "/etc/netns/chv14-$n"
  done
  set -e
}

vl() { # ns1 if1 ns2 if2
  ip link add "$2" netns "chv14-$1" type veth peer name "$4" netns "chv14-$3"
}

do_setup() {
  do_teardown
  log "setup netns"
  local n p
  for n in "${NSL[@]}"; do
    ip netns add "chv14-$n"
    ipn "$n" link set lo up
  done
  ipn i link add core0 type bridge
  for n in wa wb; do
    vl "$n" wan i "p-$n"
    ipn i link set "p-$n" master core0
  done
  ipn i addr add "$CORE.254/24" dev core0
  ipn wa addr add "$CORE.50/24" dev wan
  ipn wb addr add "$CORE.51/24" dev wan
  for n in "${NSL[@]}"; do
    local ifs
    ifs="$(ipn "$n" -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$')"
    for p in $ifs; do ipn "$n" link set "$p" up; done
  done
  ipn i link set core0 up
  # маршрут по умолчанию нужен зонду маршрута (connect без отправки); пакетов на 192.0.2.1 быть не должно
  for n in wa wb; do ipn "$n" route add default via "$CORE.254"; done
  # смена адреса в строке addrchange: без этого удаление основного адреса снесёт и вторичный
  for n in wa wb; do
    nsx "$n" sysctl -qw net.ipv4.conf.all.promote_secondaries=1 net.ipv4.conf.wan.promote_secondaries=1
  done
  # DNS-заглушка: любой запрос к резолверу виден счётчиком dns
  for n in wa wb; do
    mkdir -p "/etc/netns/chv14-$n"
    echo "nameserver 192.0.2.53" > "/etc/netns/chv14-$n/resolv.conf"
  done
  log "стенд готов"
}

# ---------------------------------------------------------------- ограничение скорости и обрыв
need_tc() { command -v tc >/dev/null 2>&1; }
shape() { nsx "$1" tc qdisc replace dev wan root tbf rate "$2" burst 256kb latency 200ms; }
unshape() { nsx "$1" tc qdisc del dev wan root 2>/dev/null || true; }

# Обрыв UDP между узлами в одном ns (обе стороны); одна строка в цепи: `;` перед `}`.
drop_on() { # ns адрес_друга
  nsx "$1" nft -f - <<NFT
table inet chv14drop {
  chain out14 { type filter hook output priority -10; policy accept; ip daddr $2 drop; }
  chain inp14 { type filter hook input priority -10; policy accept; ip saddr $2 drop; }
}
NFT
}
drop_off() { nsx "$1" nft delete table inet chv14drop 2>/dev/null || true; }

# Счётчики трафика узла: допустимые получатели (peers) отдельно от всего прочего, в обе стороны.
# dns: порты 53 и 853; probe: адреса зонда маршрута; other, other_in: всё остальное.
nft_guard() { # ns peers4(через запятую)
  local ns="$1" p4="$2" P6="" ND6="" M6=""
  if [[ -e /proc/net/if_inet6 ]]; then
    P6='ip6 daddr 2001:db8::1 counter name "probe"'
    ND6='icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } counter name "nd" accept'
    M6='icmpv6 type mld2-listener-report counter name "mcast_kernel" accept'
  fi
  nsx "$ns" nft flush ruleset 2>/dev/null || true
  nsx "$ns" nft -f - <<NFT
table inet chv14g {
  set peers4 { type ipv4_addr; elements = { $p4 } }
  counter dns { }
  counter probe { }
  counter peer { }
  counter peer_in { }
  counter nd { }
  counter mcast_kernel { }
  counter other { }
  counter other_in { }
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
  chain input {
    type filter hook input priority 0; policy accept;
    iifname "lo" accept
    ip saddr @peers4 counter name "peer_in" accept
    $ND6
    $M6
    ip protocol igmp counter name "mcast_kernel" accept
    counter name "other_in" accept
  }
}
NFT
}

cnt() { # файл-счётчиков имя
  awk -v n="$2" '$1 == "counter" && $2 == n { f = 1 } f && $1 == "packets" { print $2; exit }' "$1"
}

# Итог счётчиков узла: пустая строка, если dns = probe = other = other_in = 0 и peer, peer_in > 0.
guard_fail() { # ns метка
  local ns="$1" f="$RD/nft-$2.txt" v out=""
  nsx "$ns" nft list counters > "$f"
  for v in dns probe other other_in; do
    [[ "$(cnt "$f" "$v")" == 0 ]] || out+="$v@$2=$(cnt "$f" "$v") "
  done
  for v in peer peer_in; do
    [[ "$(cnt "$f" "$v")" -gt 0 ]] || out+="$v@$2=0 "
  done
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
node_sigkill() { bg_stop "${NODE_REAL[$1]:-}" "${NODE_WRAP[$1]:-}" KILL; }

# Ждёт строку в логе узла; 0 — нашлась, 1 — нет за secs.
wait_grep() { # метка regex secs
  local f="$RD/$1.log" i
  for i in $(seq 1 "$(( $3 * 5 ))"); do
    grep -Eq "$2" "$f" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

# Процент выполнения по последней строке `EVENT progress done=D total=T` в логе получателя.
pct() { # метка
  awk '/^EVENT progress done=/ { split($3, a, "="); split($4, b, "="); if (b[2] > 0) p = int(a[2] * 100 / b[2]) } END { print p + 0 }' "$RD/$1.log" 2>/dev/null || echo 0
}

# Ждёт, пока получатель дойдёт до min процентов; 0 — дошёл, 1 — нет за secs.
wait_pct() { # метка min secs
  local i
  for i in $(seq 1 "$(( $3 * 5 ))"); do
    [[ "$(pct "$1")" -ge "$2" ]] && return 0
    sleep 0.2
  done
  return 1
}

res_ok() { grep -q '^RESULT ok' "$RD/$1.log" 2>/dev/null; }
has_ev() { grep -q "^EVENT $2" "$RD/$1.log" 2>/dev/null; }

# ---------------------------------------------------------------- данные и сверка
make_src() { # МиБ
  head -c "$(( $1 * 1048576 ))" /dev/urandom > "$W/src.bin"
}

# Итоговый файл получателя: единственный `chervo-*-0` в dest, остальное в dest недопустимо.
dest_file() { # каталог dest
  local f
  f="$(find "$1" -maxdepth 1 -type f -name 'chervo-*-0' | head -n 1)"
  echo "$f"
}

# Пустая строка, если принятый файл равен исходному побайтно и лишних файлов в dest нет.
check_dest() {
  local d="$W/wb/dest" f out="" n
  f="$(dest_file "$d")"
  if [[ -z "$f" ]]; then echo "нет_итогового_файла "; return 0; fi
  cmp -s -- "$W/src.bin" "$f" || out+="cmp_differs "
  n="$(find "$d" -mindepth 1 -maxdepth 1 | wc -l)"
  [[ "$n" == 1 ]] || out+="extra_in_dest($n) "
  echo "$out"
}

# Дружба wa (пригласивший, отправитель) и wb; затем оба узла выходят. Результат в f через код возврата.
pair_nodes() {
  mkdir -p "$W/wa" "$W/wb/dest" "$W/wb/partial"
  node_start pa wa --port $PORT --book-dir "$W/wa" --invite-out "$W/inv" --sas-auto-confirm \
    --dest "$W/wa/dest" --partial "$W/wa/partial" \
    --expect-connected 1 --deadline 90 --hold 2
  node_start pb wb --port $PORT --book-dir "$W/wb" --invite-in "$W/inv" --sas-auto-confirm \
    --dest "$W/wb/dest" --partial "$W/wb/partial" \
    --expect-connected 1 --deadline 90 --hold 2
  node_wait pa; node_wait pb
  res_ok pa && res_ok pb
}

start_sender() { # метка deadline
  node_start "$1" wa --port $PORT --book-dir "$W/wa" --dest "$W/wa/dest" --partial "$W/wa/partial" \
    --send "$W/src.bin" \
    --expect-complete 1 --deadline "$2" --hold 2
}

start_receiver() { # метка deadline
  node_start "$1" wb --port $PORT --book-dir "$W/wb" --dest "$W/wb/dest" --partial "$W/wb/partial" \
    --accept --expect-complete 1 --deadline "$2" --hold 2
}

row_begin() {
  mkdirs
  RD="$LOGS/$1"; rm -rf "$RD"; mkdir -p "$RD"
  W="$STATE/$1"; rm -rf "$W"; mkdir -p "$W"
  [[ -x "$NODE" ]] || do_node
  ip netns list | grep -q '^chv14-i\b' || do_setup
}

row_end() {
  local l
  for l in "${!NODE_REAL[@]}"; do node_kill "$l"; done
  NODE_REAL=(); NODE_WRAP=()
  unshape wa; unshape wb
  drop_off wa; drop_off wb
  nsx wa nft flush ruleset 2>/dev/null || true
  nsx wb nft flush ruleset 2>/dev/null || true
  [[ -z "$W" ]] || rm -rf -- "$W"
}

verdict() { # СТРОКА PASS|FAIL|INCONCLUSIVE|NOTRUN причина
  mkdirs; touch "$SUMMARY"
  grep -v "^$1 " "$SUMMARY" > "$SUMMARY.tmp" || true
  mv "$SUMMARY.tmp" "$SUMMARY"
  echo "$1 $2 ${RD#"$ROOT"/} $3" >> "$SUMMARY"
  log "$1 $2: $3"
}

now() { date +%s.%N; }

# ---------------------------------------------------------------- строки
# XFER: белый-белый, случайный файл (по умолчанию 1 ГиБ), побайтная сверка `cmp`
row_xfer() {
  row_begin xfer
  local f="" t0 t1
  pair_nodes || f+="pair_failed "
  if [[ -z "$f" ]]; then
    make_src "$XFER_MIB"
    t0="$(now)"
    start_receiver rb 600; start_sender sa 600
    node_wait sa; node_wait rb
    t1="$(now)"
    res_ok sa || f+="sender_not_completed "
    res_ok rb || f+="receiver_not_completed "
    f+="$(check_dest)"
  fi
  row_end
  if [[ -n "${f// /}" ]]; then verdict XFER FAIL "$f"
  else verdict XFER PASS "белый-белый, $XFER_MIB МиБ случайных байт, cmp равен, лишних файлов нет; $(awk -v s="$XFER_MIB" -v a="$t0" -v b="$t1" 'BEGIN { printf "%.1f МиБ/с (справка)", s / (b - a) }')"
  fi
}

# DROP: на ~30 % nft бросает UDP между узлами 45 с (дольше простоя соединения 30 с): новое соединение,
# возобновление, cmp
row_drop() {
  if ! need_tc; then RD="$LOGS/drop"; verdict DROP INCONCLUSIVE "нет tc"; return 0; fi
  row_begin drop
  local f=""
  pair_nodes || f+="pair_failed "
  if [[ -z "$f" ]]; then
    make_src "$ROW_MIB"
    shape wa "$ROW_RATE"
    start_receiver rb 400; start_sender sa 400
    if wait_pct rb 30 120; then
      drop_on wa "$CORE.51"
      sleep 45
      drop_off wa
    else
      f+="no_30pct_in_120s "
    fi
    node_wait sa; node_wait rb
    res_ok sa || f+="sender_not_completed "
    res_ok rb || f+="receiver_not_completed "
    has_ev rb paused || f+="no_pause_seen "
    has_ev rb resumed || f+="no_resume_seen "
    f+="$(check_dest)"
  fi
  row_end
  if [[ -n "${f// /}" ]]; then verdict DROP FAIL "$f"
  else verdict DROP PASS "обрыв 45 с на ~30 %: пауза, возобновление, cmp равен"
  fi
}

# ADDRCHANGE: получатель меняет адрес (ip addr add/del) на ~30 %; миграция или новое соединение, cmp
row_addrchange() {
  if ! need_tc; then RD="$LOGS/addrchange"; verdict ADDRCHANGE INCONCLUSIVE "нет tc"; return 0; fi
  row_begin addrchange
  local f=""
  pair_nodes || f+="pair_failed "
  if [[ -z "$f" ]]; then
    make_src "$ROW_MIB"
    shape wa "$ROW_RATE"
    start_receiver rb 400; start_sender sa 400
    if wait_pct rb 30 120; then
      ipn wb addr add "$CORE.52/24" dev wan
      ipn wb addr del "$CORE.51/24" dev wan
    else
      f+="no_30pct_in_120s "
    fi
    node_wait sa; node_wait rb
    res_ok sa || f+="sender_not_completed "
    res_ok rb || f+="receiver_not_completed "
    f+="$(check_dest)"
  fi
  row_end
  # вернуть исходный адрес wb: стенд общий для строк, следующие (KILLRECV, CAPTURE) ждут wb = $CORE.51
  ipn wb addr add "$CORE.51/24" dev wan 2>/dev/null || true
  ipn wb addr del "$CORE.52/24" dev wan 2>/dev/null || true
  if [[ -n "${f// /}" ]]; then verdict ADDRCHANGE FAIL "$f"
  else verdict ADDRCHANGE PASS "смена адреса получателя на ~30 %: передача закончена, cmp равен (пауза была: $(has_ev_txt))"
  fi
}
has_ev_txt() { if has_ev rb paused; then echo да; else echo нет; fi; }

# KILLRECV: `kill -9` получателя на ~50 %, перезапуск, перепроверка принятого, cmp
row_killrecv() {
  if ! need_tc; then RD="$LOGS/killrecv"; verdict KILLRECV INCONCLUSIVE "нет tc"; return 0; fi
  row_begin killrecv
  local f=""
  pair_nodes || f+="pair_failed "
  if [[ -z "$f" ]]; then
    make_src "$ROW_MIB"
    shape wa "$ROW_RATE"
    start_receiver rb 400; start_sender sa 400
    if wait_pct rb 50 120; then
      node_sigkill rb
      sleep 1
      start_receiver rb2 400
    else
      f+="no_50pct_in_120s "
    fi
    node_wait sa
    if [[ -n "${NODE_WRAP[rb2]:-}" ]]; then node_wait rb2; fi
    res_ok sa || f+="sender_not_completed "
    res_ok rb2 || f+="receiver_not_completed_after_restart "
    has_ev rb2 verifying || f+="no_reverify_seen "
    f+="$(check_dest)"
  fi
  row_end
  if [[ -n "${f// /}" ]]; then verdict KILLRECV FAIL "$f"
  else verdict KILLRECV PASS "kill -9 получателя на ~50 %: перезапуск, перепроверка (verifying), cmp равен"
  fi
}

# TBF: tc tbf 50 Мбит/с на отправителе; МиБ/с только справка, не критерий
row_tbf() {
  if ! need_tc; then RD="$LOGS/tbf"; verdict TBF INCONCLUSIVE "нет tc"; return 0; fi
  row_begin tbf
  local f="" t0 t1
  pair_nodes || f+="pair_failed "
  if [[ -z "$f" ]]; then
    make_src "$TBF_MIB"
    shape wa 50mbit
    t0="$(now)"
    start_receiver rb 600; start_sender sa 600
    node_wait sa; node_wait rb
    t1="$(now)"
    res_ok sa || f+="sender_not_completed "
    res_ok rb || f+="receiver_not_completed "
    f+="$(check_dest)"
  fi
  row_end
  if [[ -n "${f// /}" ]]; then verdict TBF FAIL "$f"
  else verdict TBF PASS "tbf 50 Мбит/с, $TBF_MIB МиБ, cmp равен; $(awk -v s="$TBF_MIB" -v a="$t0" -v b="$t1" 'BEGIN { printf "%.2f МиБ/с (справка, не критерий)", s / (b - a) }')"
  fi
}

# CAPTURE: счётчики nft на обоих узлах: пакеты только между двумя узлами (dns, probe, other, other_in равны 0)
row_capture() {
  row_begin capture
  local f=""
  pair_nodes || f+="pair_failed "
  if [[ -z "$f" ]]; then
    make_src "$CAP_MIB"
    nft_guard wa "$CORE.51"
    nft_guard wb "$CORE.50"
    start_receiver rb 300; start_sender sa 300
    node_wait sa; node_wait rb
    res_ok sa || f+="sender_not_completed "
    res_ok rb || f+="receiver_not_completed "
    f+="$(check_dest)"
    f+="$(guard_fail wa wa)"
    f+="$(guard_fail wb wb)"
  fi
  row_end
  if [[ -n "${f// /}" ]]; then verdict CAPTURE FAIL "$f"
  else verdict CAPTURE PASS "во время передачи у wa и wb пакеты только к другу и от друга (dns, probe, other, other_in равны 0); cmp равен"
  fi
}

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
  xfer) need_privs; row_xfer ;;
  drop) need_privs; row_drop ;;
  addrchange) need_privs; row_addrchange ;;
  killrecv) need_privs; row_killrecv ;;
  tbf) need_privs; row_tbf ;;
  capture) need_privs; row_capture ;;
  all)
    need_privs
    TEARDOWN_ON_EXIT=1
    mkdirs
    row_xfer; row_drop; row_addrchange; row_killrecv; row_tbf; row_capture
    echo "--- $SUMMARY"; cat "$SUMMARY"
    do_teardown
    TEARDOWN_ON_EXIT=0
    ;;
  *) echo "использование: stage14.sh <xfer|drop|addrchange|killrecv|tbf|capture|all|teardown>" >&2; exit 2 ;;
esac
