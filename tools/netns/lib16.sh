#!/usr/bin/env bash
# lib16.sh: общие функции стенда этапа 16 (netns, nftables, tc netem). Подключается из stage16.sh (source).
#
# НЕ ЗАПУСКАЛСЯ НА LINUX СБОРЩИКОМ (not run on Linux by the builder): на машине сборки (Windows) проверен только `bash -n`.
# Прогон на Linux делает дирижёр (docs/specs/stage-16-nettest.md, п. 15.4).
#
# Хозяйство скопировано из stage14.sh и stage13a.sh без изменения смысла (state, nsx, bg_start, bg_stop, cnt, nft_guard,
# verdict). Безопасность (спецификация п. 5): трогаются только ns с префиксом chv16-; nft, sysctl, tc, ethtool, tcpdump,
# miniupnpd запускаются только через `ip netns exec`; на хосте не меняется ничего, кроме создания и удаления своих ns и
# каталогов /etc/netns/chv16-<ns> (сам /etc/netns не удаляется никогда).

PFX="chv16-"
CORE="${CORE:-11.0.0}"
PORT=4433
NICE_N="${CHV_NICE:-10}"
SAFE_PATH="/usr/sbin:/usr/bin:/sbin:/bin"
# все ns стенда (X02 добавляет v)
NSL=(i wa wb m na ha ha2 na2 nb hb nr hr cg hc nd hd cg2 hc2)

log() { echo "[stage16.sh] $*" >&2; }
die() { echo "$*" >&2; exit 2; }
nsx() { local ns="$1"; shift; ip netns exec "$PFX$ns" "$@"; }
ipn() { local ns="$1"; shift; ip -n "$PFX$ns" "$@"; }
kv() { sed -n "s/.* $1=\([^ ]*\).*/\1/p" | tail -n1; }
tms() { sed -n 's/.* t=\([0-9]*\)$/\1/p'; }

# ---------------------------------------------------------------- рабочий каталог
# Своё CHV_STATE допускается, только если не символьная ссылка и принадлежит запускающему; проверки идут до mkdir и chmod.
STATE_OWNED=0
STATE=""
BIN=""
state_init() {
  if [[ -n "${CHV_STATE:-}" ]]; then
    STATE="$CHV_STATE"
    [[ ! -L "$STATE" ]] || die "CHV_STATE не должен быть символьной ссылкой"
    if [[ -e "$STATE" ]]; then
      [[ -d "$STATE" && "$(stat -c %u -- "$STATE")" == "$(id -u)" ]] || die "CHV_STATE не каталог или не принадлежит текущему пользователю"
    fi
    mkdir -p -- "$STATE"
    [[ ! -L "$STATE" && "$(stat -c %u -- "$STATE")" == "$(id -u)" ]] || die "CHV_STATE не принадлежит текущему пользователю"
    chmod 700 -- "$STATE"
  else
    STATE="$(mktemp -d /tmp/chervo-stage16.XXXXXX)"
    chmod 700 -- "$STATE"
    STATE_OWNED=1
  fi
  BIN="$STATE/bin"
  mkdir -p -- "$BIN"
}

# Бинарник из переменной окружения: обычный файл, не ссылка, владелец root или SUDO_UID, без записи для группы и остальных,
# каталог-родитель тоже. Копия в STATE/bin (root, 755); запускается только оттуда.
# Коды: 0 принят; 1 не задан (необязательный); 2 не прошёл проверку.
bin_import() { # ИМЯ_ПЕРЕМЕННОЙ имя_файла обязателен(0|1)
  local var="$1" dst="$2" req="$3" src own mode dir dmode down
  src="${!var:-}"
  if [[ -z "$src" ]]; then
    if [[ "$req" == 1 ]]; then echo "$var: не задан" >&2; return 2; fi
    return 1
  fi
  if [[ ! -f "$src" || -L "$src" || ! -x "$src" ]]; then echo "$var: нужен исполняемый обычный файл (не ссылка)" >&2; return 2; fi
  own="$(stat -c %u -- "$src")"; mode="$(stat -c %a -- "$src")"
  if [[ "$own" != 0 && "$own" != "${SUDO_UID:-0}" ]]; then echo "$var: владелец не root и не SUDO_UID" >&2; return 2; fi
  if (( (8#$mode & 8#022) != 0 )); then echo "$var: запись разрешена группе или остальным" >&2; return 2; fi
  dir="$(dirname -- "$src")"
  dmode="$(stat -c %a -- "$dir")"; down="$(stat -c %u -- "$dir")"
  if [[ "$down" != 0 && "$down" != "${SUDO_UID:-0}" ]]; then echo "$var: владелец каталога не root и не SUDO_UID" >&2; return 2; fi
  if (( (8#$dmode & 8#022) != 0 )); then echo "$var: каталог доступен на запись группе или остальным" >&2; return 2; fi
  cp -- "$src" "$BIN/$dst"
  cmp -s -- "$src" "$BIN/$dst" || { echo "$var: копия отличается от источника" >&2; return 2; }
  chmod 755 -- "$BIN/$dst"
  return 0
}

# ---------------------------------------------------------------- стенд: ns и veth
# Имена наших ns из `ip netns list` (только с префиксом chv16-).
ours_ns() { ip netns list 2>/dev/null | awk '{print $1}' | grep -E "^${PFX}[a-z0-9]+\$" || true; }

do_teardown() {
  local n name
  for name in $(ours_ns); do
    ip netns pids "$name" 2>/dev/null | xargs -r kill 2>/dev/null || true
  done
  sleep 0.5
  for name in $(ours_ns); do
    ip netns pids "$name" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
  done
  for name in $(ours_ns); do
    ip netns del "$name" 2>/dev/null || true
  done
  # каталоги resolv.conf: только свои, по списку и по именам, которые только что были; сам /etc/netns не трогаем
  for n in "${NSL[@]}" v pf; do
    if [[ -d "/etc/netns/$PFX$n" && ! -L "/etc/netns/$PFX$n" ]]; then rm -rf -- "/etc/netns/$PFX$n"; fi
  done
}

vl() { # ns1 if1 ns2 if2
  ip link add "$2" netns "$PFX$1" type veth peer name "$4" netns "$PFX$3"
}

# ---------------------------------------------------------------- снимок хоста (HOSTSAFE)
# Хэш правил nft хоста считается по тексту без счётчиков пакетов и без содержимого наборов (`nft -t`): иначе брандмауэр
# или fail2ban умного дома дают ложное расхождение. Сырой текст остаётся в каталоге снимка для разбора.
snap_take() { # каталог
  local d="$1"
  mkdir -p -- "$d"
  { nft -t list ruleset 2>&1 || true; } | sed -E 's/packets [0-9]+ bytes [0-9]+/packets _ bytes _/g' > "$d/nft"
  { ip -o link 2>&1 || true; } | grep -v "$PFX" > "$d/link" || true
  { ip netns list 2>&1 || true; } | awk '{print $1}' | grep -v "^$PFX" > "$d/netns" || true
  { sysctl -n net.ipv4.ip_forward net.ipv4.conf.all.forwarding 2>&1 || true; } > "$d/sysctl"
}
# Пусто, если снимки равны; иначе имена отличающихся частей.
snap_diff() { # каталог1 каталог2
  local p out=""
  for p in nft link netns sysctl; do
    cmp -s -- "$1/$p" "$2/$p" || out+="$p "
  done
  echo "$out"
}

# ---------------------------------------------------------------- вердикты
# summary16.tsv: id group verdict expected actual reason_x_exp reason_x_got reason_y_exp reason_y_got path t_connect_s note
LOGS=""
SUMMARY=""
tsv_clean() {
  local v="${1:-}"
  v="${v//$'\t'/ }"; v="${v//$'\n'/ }"
  [[ -n "$v" ]] || v="-"
  printf '%s' "$v"
}
verdict() { # 12 полей, см. выше
  local line="" i
  mkdir -p -- "$LOGS"; touch "$SUMMARY"
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    line+="$(tsv_clean "${!i:-}")"
    if (( i < 12 )); then line+=$'\t'; fi
  done
  awk -F'\t' -v id="$1" '$1 != id' "$SUMMARY" > "$SUMMARY.tmp" || true
  mv -- "$SUMMARY.tmp" "$SUMMARY"
  printf '%s\n' "$line" >> "$SUMMARY"
  log "$1 $3: ${5:-}"
}
# Короткая форма: id group verdict actual note
vd() { verdict "$1" "$2" "$3" "-" "$4" "-" "-" "-" "-" "-" "-" "${5:-}"; }

# ---------------------------------------------------------------- процессы
RD=""
W=""
declare -A NODE_REAL=() NODE_WRAP=()
BG_REAL=""; BG_WRAP=""
NODE_NICE=0
NODE=""

bg_start() { # pidfile ns cmd...
  local pf="$1" ns="$2" i; shift 2
  rm -f -- "$pf"
  nsx "$ns" sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$pf" "$@" &
  BG_WRAP=$!
  for i in $(seq 1 50); do [[ -s "$pf" ]] && break; sleep 0.05; done
  BG_REAL="$(cat -- "$pf" 2>/dev/null || true)"
}

bg_stop() { # real wrap [сигнал]
  if [[ -n "${1:-}" ]]; then kill "-${3:-TERM}" "$1" 2>/dev/null || true; fi
  if [[ -n "${2:-}" ]]; then { wait "$2"; } 2>/dev/null || true; fi
}

# Узел: только внутри ns, `env -i`, под nice при NODE_NICE > 0 (строки скорости).
node_start() { # метка ns аргументы...
  local label="$1" ns="$2"; shift 2
  bg_start "$RD/$label.pid" "$ns" sh -c 'n="$1"; p="$2"; l="$3"; shift 3; exec nice -n "$n" env -i PATH="$p" "$@" >"$l" 2>"$l.err"' sh \
    "$NODE_NICE" "$SAFE_PATH" "$RD/$label.log" "$NODE" "$@"
  NODE_REAL[$label]="$BG_REAL"
  NODE_WRAP[$label]="$BG_WRAP"
}
node_alive() { local r="${NODE_REAL[$1]:-}"; [[ -n "$r" ]] && kill -0 "$r" 2>/dev/null; }
node_wait_exit() { # метка секунды; 0 — вышел, 1 — ещё работает
  local i
  for i in $(seq 1 "$(( $2 * 5 ))"); do
    node_alive "$1" || { { wait "${NODE_WRAP[$1]:-}"; } 2>/dev/null || true; return 0; }
    sleep 0.2
  done
  return 1
}
node_kill() { bg_stop "${NODE_REAL[$1]:-}" "${NODE_WRAP[$1]:-}"; }
node_sigkill() { bg_stop "${NODE_REAL[$1]:-}" "${NODE_WRAP[$1]:-}" KILL; }
# Чистая остановка по стоп-файлу, затем TERM, затем KILL.
node_stop() { # метка
  local l="$1"
  [[ -n "${NODE_REAL[$l]:-}" ]] || return 0
  : > "$W/$l.stop" 2>/dev/null || true
  node_wait_exit "$l" 15 && return 0
  node_kill "$l"
  node_wait_exit "$l" 3 && return 0
  node_sigkill "$l"
}
nodes_stop_all() {
  local l
  for l in "${!NODE_REAL[@]}"; do node_stop "$l"; done
  NODE_REAL=(); NODE_WRAP=()
}

# ---------------------------------------------------------------- разбор логов узлов
lgf() { echo "$RD/$1.log"; }
has() { grep -Eq "$2" "$(lgf "$1")" 2>/dev/null; }
cntl() { local n; n="$(grep -Ec "$2" "$(lgf "$1")" 2>/dev/null || true)"; echo "${n:-0}"; }
lines_of() { local n; n="$(wc -l < "$(lgf "$1")" 2>/dev/null || true)"; echo "${n:-0}"; }
# число строк с регулярным выражением после первых N строк лога
cnt_after() { # метка regex N
  local n
  n="$(tail -n +"$(( $3 + 1 ))" "$(lgf "$1")" 2>/dev/null | grep -Ec "$2" || true)"
  echo "${n:-0}"
}
wait_grep() { # метка regex секунды
  local i
  for i in $(seq 1 "$(( $3 * 5 ))"); do
    has "$1" "$2" && return 0
    over_cap && return 1
    sleep 0.2
  done
  return 1
}
# Последнее значение nat_view в строках STATE узла.
nat_view_of() { grep '^STATE ' "$(lgf "$1")" 2>/dev/null | tail -n1 | kv nat_view; }

ROW_END=0
over_cap() { (( ROW_END > 0 && $(date +%s) >= ROW_END )); }

# Файл на месте целиком (запись во временный и переименование).
deliver() { # источник назначение секунды
  local i
  for i in $(seq 1 "$(( $3 * 5 ))"); do [[ -s "$1" ]] && break; sleep 0.2; done
  [[ -s "$1" ]] || return 1
  cp -- "$1" "$2.tmp" && mv -- "$2.tmp" "$2"
}

# ---------------------------------------------------------------- охрана хоста (счётчики nft)
# Копия nft_guard из stage14.sh + счётчики icmp_unreach (выход) и icmp_unreach_in (вход) ПЕРЕД other и other_in (ядро или
# маршрутизатор отвечает «недоступно» само, это не программа). Rev. 2 (S1): адреса и порты назначений other и источников
# other_in пишутся в динамические наборы other_d, other_dn (не UDP/TCP: только адрес), other_s; отчёт показывает роли.
# Проход: dns = probe = other = other_in = 0 и peer > 0.
nft_guard() { # ns peers4 (через запятую)
  local ns="$1" p4="$2" P6="" ND6="" M6="" U6="" U6I=""
  if [[ -e /proc/net/if_inet6 ]]; then
    P6='ip6 daddr 2001:db8::1 counter name "probe"'
    ND6='icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } counter name "nd" accept'
    M6='icmpv6 type mld2-listener-report counter name "mcast_kernel" accept'
    U6='icmpv6 type destination-unreachable counter name "icmp_unreach" accept'
    U6I='icmpv6 type destination-unreachable counter name "icmp_unreach_in" accept'
  fi
  nsx "$ns" nft flush ruleset 2>/dev/null || true
  nsx "$ns" nft -f - <<NFT
table inet chv16g {
  set peers4 { type ipv4_addr; elements = { $p4 } }
  counter dns { }
  counter probe { }
  counter peer { }
  counter peer_in { }
  counter nd { }
  counter mcast_kernel { }
  counter icmp_unreach { }
  counter icmp_unreach_in { }
  counter other { }
  counter other_in { }
  set other_d { type ipv4_addr . inet_service; flags dynamic; size 64; }
  set other_dn { type ipv4_addr; flags dynamic; size 64; }
  set other_s { type ipv4_addr; flags dynamic; size 64; }
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
    ip protocol icmp icmp type destination-unreachable counter name "icmp_unreach" accept
    $U6
    meta nfproto ipv4 meta l4proto { tcp, udp } update @other_d { ip daddr . th dport }
    meta nfproto ipv4 meta l4proto != tcp meta l4proto != udp update @other_dn { ip daddr }
    counter name "other" accept
  }
  chain input {
    type filter hook input priority 0; policy accept;
    iifname "lo" accept
    ip saddr @peers4 counter name "peer_in" accept
    $ND6
    $M6
    ip protocol igmp counter name "mcast_kernel" accept
    ip protocol icmp icmp type destination-unreachable counter name "icmp_unreach_in" accept
    $U6I
    meta nfproto ipv4 update @other_s { ip saddr }
    counter name "other_in" accept
  }
}
NFT
}

cnt() { # файл-счётчиков имя
  awk -v n="$2" '$1 == "counter" && $2 == n { f = 1 } f && $1 == "packets" { print $2; exit }' "$1"
}

# Пустая строка, если охрана прошла; иначе перечень нарушений. Счётчики сохраняются в $RD/nft-<ns>.txt.
guard_fail() { # ns
  local ns="$1" f="$RD/nft-$1.txt" v out="" c
  nsx "$ns" nft list counters > "$f" 2>/dev/null || { echo "guard_unreadable@$ns "; return 0; }
  for v in dns probe other other_in; do
    c="$(cnt "$f" "$v")"
    [[ "${c:-x}" == 0 ]] || out+="$v@$ns=${c:-?} "
  done
  c="$(cnt "$f" peer)"; [[ "${c:-0}" -gt 0 ]] || out+="peer@$ns=0 "
  echo "$out"
}
guard_val() { cnt "$RD/nft-$1.txt" "$2"; }

# Элементы набора охраны одной строкой: "адрес:порт адрес:порт" или "-". Пишется только в журнал guard16.tsv; отчёт заменяет
# адреса ролями, а адрес вне карты ролей заставляет генератор отказаться писать отчёт.
guard_set_elems() { # ns набор
  local e
  e="$(nsx "$1" nft list set inet chv16g "$2" 2>/dev/null | tr '\n' ' ' | sed -n 's/.*elements = {\([^}]*\)}.*/\1/p' \
    | sed -E 's/ \. /:/g; s/,/ /g; s/[[:space:]]+/ /g; s/^ //; s/ $//')"
  printf '%s' "${e:--}"
}
# Строка guard16.tsv: id ns icmp_unreach icmp_unreach_in other other_in other_d other_dn other_s. Вызывать после guard_fail.
guard_record() { # id ns
  local id="$1" ns="$2" f="$RD/nft-$2.txt" c line="" k
  mkdir -p -- "$LOGS"; touch "$LOGS/guard16.tsv"
  line="$id"$'\t'"$ns"
  for k in icmp_unreach icmp_unreach_in other other_in; do
    c="$(cnt "$f" "$k")"; line+=$'\t'"${c:-?}"
  done
  line+=$'\t'"$(guard_set_elems "$ns" other_d)"$'\t'"$(guard_set_elems "$ns" other_dn)"$'\t'"$(guard_set_elems "$ns" other_s)"
  awk -F'\t' -v id="$id" '$1 != id' "$LOGS/guard16.tsv" > "$LOGS/guard16.tsv.tmp" || true
  mv -- "$LOGS/guard16.tsv.tmp" "$LOGS/guard16.tsv"
  printf '%s\n' "$line" >> "$LOGS/guard16.tsv"
}

# Обрыв всего UDP между узлом и перечисленными адресами (в обе стороны); одна строка в цепи: `;` перед `}`.
drop_on() { # ns адреса(через запятую)
  nsx "$1" nft -f - <<NFT
table inet chv16drop {
  chain out16 { type filter hook output priority -10; policy accept; ip daddr { $2 } drop; }
  chain inp16 { type filter hook input priority -10; policy accept; ip saddr { $2 } drop; }
}
NFT
}
drop_off() { nsx "$1" nft delete table inet chv16drop 2>/dev/null || true; }

# ---------------------------------------------------------------- netem и счётчики tc
# Порты «интернета» p-<ns> в ns i. Данные идут на порт получателя, подтверждения на порт отправителя.
netem_set() { # ns delay_ms rate limit loss(в процентах, пусто — нет)
  local args=(limit "$4")
  [[ "$2" == 0 ]] || args+=(delay "${2}ms")
  [[ -z "${5:-}" ]] || args+=(loss "${5}%")
  args+=(rate "$3")
  nsx i tc qdisc replace dev "p-$1" root netem "${args[@]}"
}
netem_clear() { nsx i tc qdisc del dev "p-$1" root 2>/dev/null || true; }
# "пакетов_отправлено отброшено" корневой qdisc порта
tc_stat() { # ns
  nsx i tc -s qdisc show dev "p-$1" 2>/dev/null | awk '/Sent/ { gsub(/[(),]/, ""); print $4, $7; exit }'
}
# Отключение offload на всех не-lo интерфейсах всех ns стенда (rev. 2, S2). Каждая опция отдельно: «fixed» и «не поддерживается»
# не ошибка. Затем ethtool -k внутри ns: tx-udp-segmentation должен быть off на wan, eth0 и портах p-*. 0 — проверено;
# иначе 1 и причина в OFF_WHY (строки с потерями тогда INCONCLUSIVE: quinn шлёт UDP GSO, netem считает потерю на весь skb).
OFF_WHY=""
offloads_off() {
  local n p ifs ok=0 f out
  OFF_WHY=""
  if ! command -v ethtool >/dev/null 2>&1; then OFF_WHY="нет ethtool"; return 1; fi
  for n in "${NSL[@]}"; do
    ifs="$(ipn "$n" -o link show 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -Ev '^(lo|core0|lan)$' || true)"
    for p in $ifs; do
      nsx "$n" ethtool -K "$p" gso off tso off gro off >/dev/null 2>&1 && ok=1
      for f in tx-udp-segmentation rx-udp-gro-forwarding rx-gro-list; do
        nsx "$n" ethtool -K "$p" "$f" off >/dev/null 2>&1 || true
      done
    done
  done
  if [[ "$ok" != 1 ]]; then OFF_WHY="ethtool -K не сработал ни на одном интерфейсе"; return 1; fi
  for n in "${NSL[@]}"; do
    ifs="$(ipn "$n" -o link show 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -E '^(wan|eth0|p-.+)$' || true)"
    for p in $ifs; do
      out="$(nsx "$n" ethtool -k "$p" 2>/dev/null | sed -n 's/^tx-udp-segmentation: *\([a-z]*\).*/\1/p' | head -n1)"
      if [[ "$out" != off ]]; then OFF_WHY="UDP GSO не отключается ($n/$p: tx-udp-segmentation=${out:-нет в ethtool -k})"; return 1; fi
    done
  done
  return 0
}

# ---------------------------------------------------------------- прочее
now_s() { date +%s; }
median() { # числа в строках на stdin
  sort -g | awk '{ a[NR] = $1 } END { if (NR == 0) print "-"; else if (NR % 2) print a[(NR + 1) / 2]; else print (a[NR / 2] + a[NR / 2 + 1]) / 2 }'
}
