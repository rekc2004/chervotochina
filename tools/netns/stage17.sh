#!/usr/bin/env bash
# Stage 17 stand (netns, nftables): rows X02a, X02b, X02c (lying friend / lying inviter), DOS1, DOS2, DOS3 (pre-auth DoS)
# per docs/specs/stage-17-security.md, sec. 2 decision 10 and sec. 4 part B5. Reuses tools/netns/lib16.sh.
#
# Usage (root, Linux box):
#   sudo CHV_NODE16=... [CHV_NODE17_LIAR_A=...] [CHV_NODE17_LIAR_B=...] [CHV_NODE17_LIAR_C=...] [CHV_KNOCKFLOOD=...] bash tools/netns/stage17.sh <command>
# Commands: preflight | X02a | X02b | X02c | DOS1 | DOS2 | DOS3 | x02 | dos | all | teardown | build-liar a|b|c
#   build-liar runs as a normal user (needs cargo), everything else as root.
# Binaries come only from the environment (root has no cargo): regular file, not a symlink, owner root or SUDO_UID,
# no group/other write (file and parent directory); copied to STATE/bin and run only from there with `env -i`.
#   CHV_NODE16        honest node16 example (chervo-transfer) - required
#   CHV_NODE17_LIAR_A node16 built by `build-liar a` (X02a: signed address update lists the victim)
#   CHV_NODE17_LIAR_B node16 built by `build-liar b` (X02b: observed address in ADDR_INFO is the victim)
#   CHV_NODE17_LIAR_C node16 built by `build-liar c` (X02c: the invite token lists the victim next to the inviter's own address)
#   CHV_KNOCKFLOOD    sender for DOS1-DOS3 (see "KNOCKFLOOD CONTRACT" below)
# Variables: CHV_LOGS (default tools/netns/logs/stage17), CHV_STATE, CHV_KEEP=1, CHV_NICE (10),
#   CHV_X02_WIN (300 s, victim observation window), CHV_BURST_GAP (5 s: packets closer than this are one burst),
#   CHV_BURST_MAX (15 s: longest allowed burst), CHV_FLOOD_SECS (120), CHV_FLOOD_PPS (4000 total, split over the two modes),
#   CHV_HOLD_CONNS (64), CHV_HOLD_SECS (120), CHV_MSG1_MS (5000: msg1_deadline of the build under test; the code default
#   is 5 s today, the spec says 3 s - set what the build uses), CHV_INVITE_TTL (900), CHV_CONN_FACTOR (5).
#
# NOT RUN ON LINUX BY THE BUILDER ("not run on Linux by the builder"): on the build machine (Windows) only `bash -n` was
# run. The conductor runs it on the Linux box. Flows, thresholds marked "assumption" and the flood tool contract are the
# builder's reading of the spec and of node16's options, not measured behaviour.
#
# KNOCKFLOOD CONTRACT (the example crates/chervo-transport-quinn/examples/knockflood.rs does NOT exist yet: the builder was
# told not to touch crates/; it is a dev-only example, no product change). One binary, modes:
#   --mode garbage|knock48 --target IP:PORT --src-net A.B.C --sources N --pps P --secs S
#        sends UDP from A.B.C.0..N-1 (each source bound to its own address) at P datagrams/s in total for S seconds:
#        garbage = random length 1..1200, knock48 = random 48 bytes. Needs no keys. Prints "sent=<n>" at the end.
#   --mode idle-tls --target IP:PORT --book-dir D --label L --conns N --secs S
#        a friend (book dir D made by node16, friend label L) sends a valid knock, completes QUIC+TLS and then stays
#        idle in each of N connections (no msg1). Prints per connection "conn=<k> closed_ms=<ms>" when the callee closes
#        it, and at exit "opened=<n> closed=<m> max_closed_ms=<ms>".
#   --mode invite-hold --target IP:PORT --invite FILE --conns N --secs S
#        holder of an invite (file text) opens N sessions toward the inviter and keeps them unfinished (no SAS decision).
#        Prints at exit "opened=<n>".
# Exit 0 after S seconds. Anything else is an INCONCLUSIVE row, never a PASS.
#
# Safety (smart home on the same box): only ns chv17-*; nft, sysctl, tc, tcpdump and all test processes run via
# `ip netns exec`; STATE from mktemp -d (mode 700; a given CHV_STATE must be a real directory of the caller, no symlink,
# checked before chmod); no files under /etc/netns are created or removed, /etc/netns itself is never touched; host
# snapshot (nft without counters, links, netns, ip_forward) before and after every command and row (HOSTSAFE);
# the ns are torn down on exit. No `set -e` on purpose: a row must not take the stand down.
# nft 1.0.9 syntax: no chain named `fwd`, `;` before `}` in one-line chains.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
# shellcheck source=lib16.sh
source "$ROOT/lib16.sh"

# ---- overrides of lib16 constants (own prefix; lib16 functions read these at call time)
PFX="chv17-"
CORE="11.0.0"
NSL=(i lw wb v na ha ce fr pk fl)
log() { echo "[stage17.sh] $*" >&2; }

LOGS="${CHV_LOGS:-$ROOT/logs/stage17}"
SUMMARY="$LOGS/summary17.tsv"
HSTSV="$LOGS/hostsafe17.tsv"
CMD="${1:-}"
ARG2="${2:-}"
STARTED=0
HAVE_LIAR_A=0; HAVE_LIAR_B=0; HAVE_LIAR_C=0; HAVE_KF=0
ROW_ID=""
DL=900
CLK_TCK=100
TCPD_REAL=""; TCPD_WRAP=""
KF=""
declare -A FL_REAL=() FL_WRAP=()

num() { # name default -> validated integer from the environment
  local v="${!1:-$2}"
  [[ "$v" =~ ^[0-9]+$ ]] || die "$1 must be a non-negative integer"
  echo "$v"
}
WIN="$(num CHV_X02_WIN 300)"
BURST_GAP="$(num CHV_BURST_GAP 5)"
BURST_MAX="$(num CHV_BURST_MAX 15)"
FLOOD_SECS="$(num CHV_FLOOD_SECS 120)"
FLOOD_PPS="$(num CHV_FLOOD_PPS 4000)"
HOLD_CONNS="$(num CHV_HOLD_CONNS 64)"
HOLD_SECS="$(num CHV_HOLD_SECS 120)"
MSG1_MS="$(num CHV_MSG1_MS 5000)"
INVITE_TTL="$(num CHV_INVITE_TTL 900)"
CONN_FACTOR="$(num CHV_CONN_FACTOR 5)"
VICTIM="$CORE.66"
CALLEE="$CORE.20"

# ---------------------------------------------------------------- work dir (lib16 state_init, own mktemp name)
state_init() {
  if [[ -n "${CHV_STATE:-}" ]]; then
    STATE="$CHV_STATE"
    [[ ! -L "$STATE" ]] || die "CHV_STATE must not be a symlink"
    if [[ -e "$STATE" ]]; then
      [[ -d "$STATE" && "$(stat -c %u -- "$STATE")" == "$(id -u)" ]] || die "CHV_STATE is not a directory of the caller"
    fi
    mkdir -p -- "$STATE"
    [[ ! -L "$STATE" && "$(stat -c %u -- "$STATE")" == "$(id -u)" ]] || die "CHV_STATE is not owned by the caller"
    chmod 700 -- "$STATE"
  else
    STATE="$(mktemp -d /tmp/chervo-stage17.XXXXXX)"
    chmod 700 -- "$STATE"
    STATE_OWNED=1
  fi
  BIN="$STATE/bin"
  mkdir -p -- "$BIN"
}

# ---------------------------------------------------------------- teardown: only chv17-* ns (no /etc/netns at all)
do_teardown() {
  local name
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
}

# ---------------------------------------------------------------- entry checks
need_root() {
  [[ "$(id -u)" == 0 ]] || { echo "INCONCLUSIVE: root required (netns, nftables)" >&2; exit 3; }
  command -v ip >/dev/null && command -v nft >/dev/null || { echo "INCONCLUSIVE: ip and nft required" >&2; exit 3; }
}

bins_import() {
  local rc
  bin_import CHV_NODE16 node16 1 || { echo "INCONCLUSIVE: CHV_NODE16 rejected" >&2; exit 3; }
  NODE="$BIN/node16"
  bin_import CHV_NODE17_LIAR_A node17-liar-a 0; rc=$?
  if [[ $rc == 0 ]]; then HAVE_LIAR_A=1; elif [[ $rc == 2 ]]; then exit 3; fi
  bin_import CHV_NODE17_LIAR_B node17-liar-b 0; rc=$?
  if [[ $rc == 0 ]]; then HAVE_LIAR_B=1; elif [[ $rc == 2 ]]; then exit 3; fi
  bin_import CHV_NODE17_LIAR_C node17-liar-c 0; rc=$?
  if [[ $rc == 0 ]]; then HAVE_LIAR_C=1; elif [[ $rc == 2 ]]; then exit 3; fi
  bin_import CHV_KNOCKFLOOD knockflood 0; rc=$?
  if [[ $rc == 0 ]]; then HAVE_KF=1; KF="$BIN/knockflood"; elif [[ $rc == 2 ]]; then exit 3; fi
  return 0
}

# ---------------------------------------------------------------- HOSTSAFE (as stage16)
HS_DIR=""
hostsafe_begin() { HS_DIR="$STATE/hs"; rm -rf -- "$HS_DIR"; snap_take "$HS_DIR/a"; }
hostsafe_check() { # label
  local d
  [[ -n "$HS_DIR" ]] || return 0
  snap_take "$HS_DIR/b"
  d="$(snap_diff "$HS_DIR/a" "$HS_DIR/b")"
  if [[ -n "${d// /}" ]]; then
    mkdir -p -- "$LOGS"
    rm -rf -- "$LOGS/hostsafe-fail"; cp -r -- "$HS_DIR" "$LOGS/hostsafe-fail" 2>/dev/null || true
    printf '%s\t%s\t%s\t%s\n' "$(date +%F)" "$1" FAIL "$d" >> "$HSTSV"
    hostsafe_summary
    echo "HOSTSAFE FAIL after $1: host changed: $d. Stopping, the host is not repaired; tell the conductor (logs in hostsafe-fail)." >&2
    exit 5
  fi
  return 0
}
hostsafe_end() { # command label
  hostsafe_check "$1"
  printf '%s\t%s\t%s\t%s\n' "$(date +%F)" "$1" PASS "-" >> "$HSTSV"
  hostsafe_summary
}
hostsafe_summary() {
  local n f
  n="$(awk -F'\t' '$3 == "PASS"' "$HSTSV" 2>/dev/null | wc -l)"
  f="$(awk -F'\t' '$3 == "FAIL"' "$HSTSV" 2>/dev/null | wc -l)"
  if (( f > 0 )); then vd HOSTSAFE ctl FAIL "host changed" "see hostsafe17.tsv"
  else vd HOSTSAFE ctl PASS "before and after ${n} commands: host nft, links, ns, ip_forward unchanged" "nft compared without counters and set contents"
  fi
}

# ---------------------------------------------------------------- topology
# core bridge in ns i, 11.0.0.0/16: lw .50, wb .51, v .66 (victim), na .10 (NAT-A wan), ce .20 (callee), fr .30 (friend),
# pk .31 (knock-passing peer / invite holder), fl .40 (flooder, plus 11.0.1.0 .. 11.0.1.255 as 256 source addresses).
# ha 192.168.10.2 sits behind na (port-restricted NAT: masquerade, nothing inbound).
topo17() {
  set -e
  local n p ifs k
  for n in "${NSL[@]}"; do
    ip netns add "$PFX$n"
    ipn "$n" link set lo up
  done
  ipn i link add core0 type bridge
  for n in lw wb v na ce fr pk fl; do
    vl "$n" wan i "p-$n"
    ipn i link set "p-$n" master core0
  done
  ipn i addr add "$CORE.254/16" dev core0
  ipn lw addr add "$CORE.50/16" dev wan
  ipn wb addr add "$CORE.51/16" dev wan
  ipn v addr add "$VICTIM/16" dev wan
  ipn na addr add "$CORE.10/16" dev wan
  ipn ce addr add "$CALLEE/16" dev wan
  ipn fr addr add "$CORE.30/16" dev wan
  ipn pk addr add "$CORE.31/16" dev wan
  ipn fl addr add "$CORE.40/16" dev wan
  { for k in $(seq 0 255); do echo "addr add 11.0.1.$k/16 dev wan"; done; } | ip -n "${PFX}fl" -batch -
  ipn na link add lan type bridge
  vl na lh ha eth0; ipn na link set lh master lan
  ipn na addr add 192.168.10.1/24 dev lan
  ipn ha addr add 192.168.10.2/24 dev eth0
  for n in "${NSL[@]}"; do
    ifs="$(ipn "$n" -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$' || true)"
    for p in $ifs; do ipn "$n" link set "$p" up; done
  done
  # default routes: the node's route probe needs them (connect without sending); nothing is sent to 192.0.2.1
  for n in lw wb v na ce fr pk fl; do ipn "$n" route add default via "$CORE.254"; done
  ipn ha route add default via 192.168.10.1
  nsx na sysctl -qw net.ipv4.ip_forward=1
}

nat17() { # NAT-A: masquerade, nothing inbound except replies
  nsx na nft flush ruleset
  nsx na nft -f - <<NFT
table inet nat17 {
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "wan" ip saddr 192.168.10.0/24 masquerade
  }
  chain fw17 {
    type filter hook forward priority filter; policy drop;
    iifname "lan" oifname "wan" accept
    iifname "wan" ct state established,related accept
  }
}
NFT
}

# ---------------------------------------------------------------- row begin / end
row_begin() { # id cap_seconds
  local rc
  [[ "$1" =~ ^[A-Za-z0-9-]+$ ]] || die "bad row id: $1"
  ROW_ID="$1"
  RD="$LOGS/$1"; rm -rf -- "$RD"; mkdir -p -- "$RD"
  W="$STATE/$1"; rm -rf -- "$W"; mkdir -p -- "$W"
  ROW_END=$(( $(now_s) + $2 ))
  DL=$(( $2 + 120 ))
  NODE_REAL=(); NODE_WRAP=(); FL_REAL=(); FL_WRAP=(); TCPD_REAL=""; TCPD_WRAP=""
  NODE_NICE=0
  mkdir -p -- "$LOGS"
  do_teardown
  ( topo17 ) >> "$RD/setup.log" 2>&1; rc=$?
  if [[ $rc != 0 ]]; then log "$1: topology failed (see setup.log)"; return 1; fi
  nat17 >> "$RD/setup.log" 2>&1 || { log "$1: NAT rules failed"; return 1; }
  return 0
}

tcpd_stop() {
  bg_stop "$TCPD_REAL" "$TCPD_WRAP"
  TCPD_REAL=""; TCPD_WRAP=""
}
tools_stop() {
  local l
  for l in "${!FL_REAL[@]}"; do bg_stop "${FL_REAL[$l]}" "${FL_WRAP[$l]:-}"; done
  FL_REAL=(); FL_WRAP=()
}
row_end() {
  local l
  for l in "${!NODE_REAL[@]}"; do node_stop "$l"; done
  NODE_REAL=(); NODE_WRAP=()
  tools_stop; tcpd_stop
  do_teardown
  if [[ -n "$W" ]]; then rm -rf -- "$W"; fi
  ROW_END=0
  hostsafe_check "$ROW_ID"
}

# ---------------------------------------------------------------- node helpers (copied from stage16.sh)
CA=()
ca() { # ns deadline
  mkdir -p "$W/$1/dest" "$W/$1/partial"
  CA=(--port 4433 --book-dir "$W/$1" --dest "$W/$1/dest" --partial "$W/$1/partial" --sas-auto-confirm
      --diag-every 5 --stop-file "$W/$1.stop" --deadline "$2")
}
node_start_as() { # binary label ns args...
  local save="$NODE" bin="$1"; shift
  NODE="$bin"
  node_start "$@"
  NODE="$save"
}
wait_nat_view() { # label seconds
  local i v
  for i in $(seq 1 "$(( $2 * 2 ))"); do
    v="$(nat_view_of "$1")"
    [[ -n "$v" && "$v" != Unknown ]] && return 0
    over_cap && return 1
    sleep 0.5
  done
  return 1
}
TOKRES=""; TOKOK=0
token_pass2() { # src_label src_dir dst_label dst_dir (token via file, the stand is the "messenger"; only the size is logged)
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
token_pass() { token_pass2 "$1" "$1" "$2" "$2"; }

# ---------------------------------------------------------------- X02: victim capture and verdict
WHY=""
victim_capture_start() {
  bg_start "$RD/tcpd.pid" v tcpdump -i any -Q in -nn -tt -U -Z root -w "$W/v.pcap" udp
  TCPD_REAL="$BG_REAL"; TCPD_WRAP="$BG_WRAP"
  sleep 1
}
# "bursts min_spacing_s max_burst_s packets sources" of inbound UDP at the victim.
# A burst = packets each closer than BURST_GAP s to the previous one; spacing = start to start of consecutive bursts.
victim_parse() {
  local f="$W/v.pcap"
  [[ -s "$f" ]] || { echo "0 - 0 0 0"; return 0; }
  tcpdump -nn -tt -r "$f" 2>/dev/null | awk -v bg="$BURST_GAP" '
    /^[0-9]+\.[0-9]+ / {
      ts = $1 + 0
      if (n == 0 || ts - last > bg) { n++; st[n] = ts }
      last = ts; en[n] = ts; pk++
      for (i = 1; i < NF; i++) if ($i == ">") { s = $(i - 1); sub(/\.[0-9]+$/, "", s); src[s] = 1 }
    }
    END {
      minsp = "-"
      for (i = 2; i <= n; i++) { d = st[i] - st[i - 1]; if (minsp == "-" || d < minsp) minsp = d }
      maxd = 0
      for (i = 1; i <= n; i++) { d = en[i] - st[i]; if (d > maxd) maxd = d }
      ns = 0; for (s in src) ns++
      printf "%d %s %.1f %d %d\n", n + 0, minsp, maxd, pk + 0, ns
    }'
}
wait_secs() { # seconds (sleeps in 1 s steps)
  local end=$(( $(now_s) + $1 ))
  while (( $(now_s) < end )); do sleep 1; done
}
# Verdict by packets at the victim only (spec decision 10): PASS = bursts spaced >= 30 s and <= 11 bursts (and no burst
# longer than BURST_MAX - assumption: a knock plus Initial retransmits is a few seconds; a longer one is a stream);
# 0 bursts = PASS with a note; closer spacing = FAIL to security.
x02_verdict() { # id note_prefix
  local id="$1" pre="$2" b sp md pk ns v=PASS act note
  read -r b sp md pk ns <<<"$(victim_parse)"
  tcpd_stop
  act="bursts=$b min_spacing_s=$sp max_burst_s=$md packets=$pk sources=$ns window_s=$WIN"
  note="$pre"
  if (( b == 0 )); then
    note+="0 bursts at the victim = PASS (nothing sent: e.g. Conflicting or nothing published); "
  else
    if (( b > 11 )); then v=FAIL; note+="more than 11 bursts; "; fi
    if [[ "$sp" != "-" ]] && awk -v s="$sp" 'BEGIN { exit (s < 30) ? 0 : 1 }'; then v=FAIL; note+="bursts closer than 30 s; "; fi
    if awk -v m="$md" -v x="$BURST_MAX" 'BEGIN { exit (m > x) ? 0 : 1 }'; then v=FAIL; note+="burst longer than ${BURST_MAX} s; "; fi
  fi
  [[ "$v" == FAIL ]] && note+="escalate to security; "
  over_cap && [[ "$v" == PASS ]] && { v=INCONCLUSIVE; note+="row cap reached; "; }
  verdict "$id" x02 "$v" "bursts>=30s apart, <=11" "$act" - - - - - - "$note tokens: ${TOKRES:-none}"
}

# X02a: self-address lie. LW (build A: the signed update lists the victim as LW's own address) pairs with HA, hands HA a
# token (CHA1), then disconnects; HA, behind NAT-A, redials LW's addresses.
x02a_run() {
  local pre=""
  if [[ $HAVE_LIAR_A != 1 ]]; then
    vd X02a x02 NOTRUN "-" "CHV_NODE17_LIAR_A not set (run: bash tools/netns/stage17.sh build-liar a)"
    return 0
  fi
  WHY=""; TOKRES=""; TOKOK=0
  row_begin X02a $(( WIN + 360 )) || { vd X02a x02 INCONCLUSIVE "-" "topology did not come up"; row_end; return 0; }
  ca lw "$DL"
  node_start_as "$BIN/node17-liar-a" lw lw "${CA[@]}" --invite-out "$W/lw/inv" --token-to o1 --token-out "$W/lw/tok"
  ca ha "$DL"
  node_start ha ha "${CA[@]}" --invite-in "$W/ha/inv" --token-in "$W/ha/tok-in"
  if ! deliver "$W/lw/inv" "$W/ha/inv" 60; then WHY="invite not issued"
  elif ! wait_grep ha '^EVENT (invite_finished pair=i1 outcome=Added|connected pair=i1 )' 60; then WHY="HA: invite not finished"
  elif ! wait_grep lw '^EVENT connected pair=o1 ' 60; then WHY="LW: not connected after invite"
  fi
  if [[ -z "$WHY" ]]; then
    token_pass lw ha
    [[ $TOKOK == 1 ]] || WHY="token from LW not delivered (lie not tested)"
  fi
  if [[ -n "$WHY" ]]; then
    row_end
    vd X02a x02 INCONCLUSIVE "-" "$WHY"
    return 0
  fi
  has ha '^EVENT token_applied ' && pre+="HA applied the update; " || pre+="HA did not report token_applied; "
  # trigger: LW goes away, HA dials; the victim counts packets for WIN seconds
  victim_capture_start
  node_stop lw
  wait_secs "$WIN"
  x02_verdict X02a "$pre"
  row_end
}

# X02c (stage 17 fix round 2, M1): lying inviter. LW (build C: the invite token lists the victim next to LW's own address)
# invites HA; HA becomes LW's friend (the book keeps the token addresses as Invite entries) and then LW goes away. The
# victim counts packets for WIN seconds; the capture starts only after the friendship exists (the guest phase legitimately
# dials the token addresses). Same verdict as X02a: bursts >= 30 s apart, <= 11.
x02c_run() {
  local pre=""
  if [[ $HAVE_LIAR_C != 1 ]]; then
    vd X02c x02 NOTRUN "-" "CHV_NODE17_LIAR_C not set (run: bash tools/netns/stage17.sh build-liar c)"
    return 0
  fi
  WHY=""; TOKRES=""; TOKOK=0
  row_begin X02c $(( WIN + 360 )) || { vd X02c x02 INCONCLUSIVE "-" "topology did not come up"; row_end; return 0; }
  ca lw "$DL"
  node_start_as "$BIN/node17-liar-c" lw lw "${CA[@]}" --invite-out "$W/lw/inv"
  ca ha "$DL"
  node_start ha ha "${CA[@]}" --invite-in "$W/ha/inv"
  if ! deliver "$W/lw/inv" "$W/ha/inv" 60; then WHY="invite not issued"
  elif ! wait_grep ha '^EVENT (invite_finished pair=i1 outcome=Added|connected pair=i1 )' 60; then WHY="HA: invite not finished"
  elif ! wait_grep lw '^EVENT connected pair=o1 ' 60; then WHY="LW: not connected after invite"
  fi
  if [[ -n "$WHY" ]]; then
    row_end
    vd X02c x02 INCONCLUSIVE "-" "$WHY"
    return 0
  fi
  pre+="HA is a friend of LW via the lying invite; "
  # trigger: LW goes away, HA redials the Invite entries (LW and the victim); the victim counts packets
  victim_capture_start
  node_stop lw
  wait_secs "$WIN"
  x02_verdict X02c "$pre"
  row_end
}

# X02b: observed-hint lie. LW (build B: ADDR_INFO carries the victim as "your address") is HA's only observer; WB joins HA
# afterwards, receives HA's token, and when HA is gone redials HA's published addresses (incl. the hint).
x02b_run() {
  local pre="" nv=""
  if [[ $HAVE_LIAR_B != 1 ]]; then
    vd X02b x02 NOTRUN "-" "CHV_NODE17_LIAR_B not set (run: bash tools/netns/stage17.sh build-liar b)"
    return 0
  fi
  WHY=""; TOKRES=""; TOKOK=0
  row_begin X02b $(( WIN + 420 )) || { vd X02b x02 INCONCLUSIVE "-" "topology did not come up"; row_end; return 0; }
  ca lw "$DL"
  node_start_as "$BIN/node17-liar-b" lw lw "${CA[@]}" --invite-out "$W/lw/inv"
  ca ha "$DL"
  node_start ha ha "${CA[@]}" --invite-in "$W/ha/inv-lw" --invite-in "$W/ha/inv-wb" --token-to i2 --token-out "$W/ha/tok"
  if ! deliver "$W/lw/inv" "$W/ha/inv-lw" 60; then WHY="invite from LW not issued"
  elif ! wait_grep ha '^EVENT (invite_finished pair=i1 outcome=Added|connected pair=i1 )' 60; then WHY="HA: invite from LW not finished"
  elif ! wait_nat_view ha 60; then WHY="HA: nat_view Unknown (no observation from LW)"
  fi
  if [[ -z "$WHY" ]]; then
    nv="$(nat_view_of ha)"
    # WB only now: it invites HA, connects to HA and becomes a second (honest) observer
    ca wb "$DL"
    node_start wb wb "${CA[@]}" --invite-out "$W/wb/inv" --token-in "$W/wb/tok-in"
    if ! deliver "$W/wb/inv" "$W/ha/inv-wb" 60; then WHY="invite from WB not issued"
    elif ! wait_grep ha '^EVENT (invite_finished pair=i2 outcome=Added|connected pair=i2 )' 60; then WHY="HA: invite from WB not finished"
    fi
  fi
  if [[ -z "$WHY" ]]; then
    token_pass2 ha ha wb wb
    [[ $TOKOK == 1 ]] || WHY="token HA -> WB not delivered"
  fi
  if [[ -n "$WHY" ]]; then
    row_end
    vd X02b x02 INCONCLUSIVE "-" "$WHY"
    return 0
  fi
  pre+="nat_view_ha_after_LW=${nv:-none}; nat_view_ha_final=$(nat_view_of ha); "
  victim_capture_start
  node_stop ha
  wait_secs "$WIN"
  x02_verdict X02b "$pre"
  row_end
}

# ---------------------------------------------------------------- DOS rows
cpu_ticks() { awk '{ print $14 + $15 }' "/proc/$1/stat" 2>/dev/null || echo 0; }
dos_guard() { # callee ns: counters for the flood sources (inside the ns only)
  nsx ce nft flush ruleset 2>/dev/null || true
  nsx ce nft -f - <<NFT
table inet chv17f {
  counter flood_in { }
  counter flood_out { }
  chain in17 { type filter hook input priority -50; policy accept; ip saddr 11.0.1.0/24 counter name "flood_in"; }
  chain out17 { type filter hook output priority -50; policy accept; ip daddr 11.0.1.0/24 counter name "flood_out"; }
}
NFT
}
tool_start() { # label ns args...
  local label="$1" ns="$2"; shift 2
  bg_start "$RD/$label.pid" "$ns" sh -c 'n="$1"; p="$2"; l="$3"; shift 3; exec nice -n "$n" env -i PATH="$p" "$@" >"$l" 2>&1' sh \
    "$NICE_N" "$SAFE_PATH" "$RD/$label.log" "$KF" "$@"
  FL_REAL[$label]="$BG_REAL"; FL_WRAP[$label]="$BG_WRAP"
}
tool_alive() { local r="${FL_REAL[$1]:-}"; [[ -n "$r" ]] && kill -0 "$r" 2>/dev/null; }
tool_wait() { # label seconds; 0 = exited
  local i
  for i in $(seq 1 "$(( $2 * 5 ))"); do
    tool_alive "$1" || { { wait "${FL_WRAP[$1]:-}"; } 2>/dev/null || true; return 0; }
    sleep 0.2
  done
  return 1
}
FR_MS="-"
fr_connect() { # seconds: restart the friend with its persisted book and time "connected" (ms since its start)
  rm -f -- "$W/fr.stop"
  ca fr "$DL"
  node_start fr fr "${CA[@]}"
  if wait_grep fr '^EVENT connected pair=i1 ' "$1"; then
    FR_MS="$(grep '^EVENT connected pair=i1 ' "$(lgf fr)" | head -n1 | tms)"
    FR_MS="${FR_MS:--}"
  else
    FR_MS="-"
  fi
  node_stop fr
}
# Callee CE plus friend FR (and, if $1 = pk, a second friend PK): pairing by invites, then the friends stop.
dos_pairs() { # with_pk(0|1)
  local extra=()
  [[ "$1" == 1 ]] && extra=(--invite-out "$W/ce/inv-pk")
  ca ce "$DL"
  node_start ce ce "${CA[@]}" --invite-out "$W/ce/inv-fr" ${extra[@]+"${extra[@]}"}
  ca fr "$DL"
  node_start fr fr "${CA[@]}" --invite-in "$W/fr/inv"
  deliver "$W/ce/inv-fr" "$W/fr/inv" 60 || { WHY="invite for FR not issued"; return 1; }
  wait_grep fr '^EVENT (invite_finished pair=i1 outcome=Added|connected pair=i1 )' 60 || { WHY="FR: invite not finished"; return 1; }
  wait_grep ce '^EVENT connected pair=o1 ' 60 || { WHY="CE: FR not connected"; return 1; }
  node_stop fr
  if [[ "$1" == 1 ]]; then
    ca pk "$DL"
    node_start pk pk "${CA[@]}" --invite-in "$W/pk/inv"
    deliver "$W/ce/inv-pk" "$W/pk/inv" 60 || { WHY="invite for PK not issued"; return 1; }
    wait_grep pk '^EVENT (invite_finished pair=i1 outcome=Added|connected pair=i1 )' 60 || { WHY="PK: invite not finished"; return 1; }
    node_stop pk
  fi
  return 0
}
secs_of_ms() { [[ "$1" =~ ^[0-9]+$ ]] && awk -v m="$1" 'BEGIN { printf "%.1f", m / 1000 }' || echo "-"; }

dos1_run() {
  local b_ms f_ms c0 c1 t0 t1 b_cpu f_cpu fin fout v=PASS notes="" act pid
  if [[ $HAVE_KF != 1 ]]; then vd DOS1 dos NOTRUN "-" "CHV_KNOCKFLOOD not set (example knockflood does not exist yet)"; return 0; fi
  WHY=""
  row_begin DOS1 $(( FLOOD_SECS + 600 )) || { vd DOS1 dos INCONCLUSIVE "-" "topology did not come up"; row_end; return 0; }
  dos_pairs 0 || { row_end; vd DOS1 dos INCONCLUSIVE "-" "$WHY"; return 0; }
  pid="${NODE_REAL[ce]:-}"
  # baseline: friend connect time and callee CPU without flood
  c0="$(cpu_ticks "$pid")"; t0="$(now_s)"
  fr_connect 60; b_ms="$FR_MS"
  sleep 10
  c1="$(cpu_ticks "$pid")"; t1="$(now_s)"
  b_cpu="$(awk -v a="$c0" -v b="$c1" -v t="$(( t1 - t0 ))" -v h="$CLK_TCK" 'BEGIN { if (t < 1) t = 1; printf "%.2f", (b - a) / h / t * 100 }')"
  dos_guard
  # flood: garbage and 48-byte fake knocks from 256 source addresses, fixed rate, FLOOD_SECS
  c0="$(cpu_ticks "$pid")"; t0="$(now_s)"
  tool_start flood-garbage fl --mode garbage --target "$CALLEE:4433" --src-net 11.0.1 --sources 256 --pps $(( FLOOD_PPS / 2 )) --secs "$FLOOD_SECS"
  tool_start flood-knock48 fl --mode knock48 --target "$CALLEE:4433" --src-net 11.0.1 --sources 256 --pps $(( FLOOD_PPS / 2 )) --secs "$FLOOD_SECS"
  sleep 10
  fr_connect 90; f_ms="$FR_MS"
  tool_wait flood-garbage $(( FLOOD_SECS + 60 )) || true
  tool_wait flood-knock48 30 || true
  c1="$(cpu_ticks "$pid")"; t1="$(now_s)"
  f_cpu="$(awk -v a="$c0" -v b="$c1" -v t="$(( t1 - t0 ))" -v h="$CLK_TCK" 'BEGIN { if (t < 1) t = 1; printf "%.2f", (b - a) / h / t * 100 }')"
  nsx ce nft list counters > "$RD/nft-ce.txt" 2>/dev/null || true
  fin="$(cnt "$RD/nft-ce.txt" flood_in)"; fout="$(cnt "$RD/nft-ce.txt" flood_out)"
  notes+="callee_cpu_pct baseline=$b_cpu flood=$f_cpu; connect_ms baseline=$b_ms flood=$f_ms; flood_in=${fin:-?} flood_out=${fout:-?}; "
  notes+="$(cat "$RD/flood-garbage.log" "$RD/flood-knock48.log" 2>/dev/null | tr '\n' ' '); "
  if [[ "$b_ms" == "-" ]]; then v=INCONCLUSIVE; notes+="baseline connect failed; "
  elif [[ "${fin:-0}" == 0 ]]; then v=INCONCLUSIVE; notes+="flood did not reach the callee; "
  else
    [[ "${fout:-x}" == 0 ]] || { v=FAIL; notes+="callee answered flood sources; "; }
    if [[ "$f_ms" == "-" ]]; then v=FAIL; notes+="friend did not connect under flood; "
    elif (( f_ms > b_ms * CONN_FACTOR + 10000 )); then v=FAIL; notes+="connect time over ${CONN_FACTOR}x baseline + 10 s (assumption); "
    fi
  fi
  act="answers_to_flood=${fout:-?} friend_connect_ms=$f_ms (baseline $b_ms)"
  verdict DOS1 dos "$v" "answers=0, friend connects" "$act" - - - - - "$(secs_of_ms "$f_ms")" "$notes"
  row_end
}

dos2_run() {
  local f_ms v=PASS notes="" line opened closed maxc
  if [[ $HAVE_KF != 1 ]]; then vd DOS2 dos NOTRUN "-" "CHV_KNOCKFLOOD not set (example knockflood does not exist yet)"; return 0; fi
  WHY=""
  row_begin DOS2 $(( HOLD_SECS + 600 )) || { vd DOS2 dos INCONCLUSIVE "-" "topology did not come up"; row_end; return 0; }
  dos_pairs 1 || { row_end; vd DOS2 dos INCONCLUSIVE "-" "$WHY"; return 0; }
  tool_start hold-idle pk --mode idle-tls --target "$CALLEE:4433" --book-dir "$W/pk" --label i1 --conns "$HOLD_CONNS" --secs "$HOLD_SECS"
  sleep 5
  fr_connect 60; f_ms="$FR_MS"
  tool_wait hold-idle $(( HOLD_SECS + 60 )) || true
  line="$(grep -E 'opened=[0-9]+ closed=[0-9]+ max_closed_ms=[0-9]+' "$RD/hold-idle.log" 2>/dev/null | tail -n1 || true)"
  opened="$(kv opened <<<" $line")"; closed="$(kv closed <<<" $line")"; maxc="$(kv max_closed_ms <<<" $line")"
  notes+="idle conns opened=${opened:--} closed=${closed:--} max_closed_ms=${maxc:--} (msg1_deadline ${MSG1_MS} ms); friend connect_ms=$f_ms; "
  if [[ -z "$line" || "${opened:-0}" == 0 ]]; then v=INCONCLUSIVE; notes+="tool opened no idle connection; "
  else
    [[ "$f_ms" != "-" ]] || { v=FAIL; notes+="friend from another key did not connect; "; }
    [[ "$closed" == "$opened" ]] || { v=FAIL; notes+="idle connections left open; "; }
    (( ${maxc:-0} <= MSG1_MS + 2000 )) || { v=FAIL; notes+="idle closed later than msg1_deadline + 2 s (assumption); "; }
  fi
  verdict DOS2 dos "$v" "friend connects; idle closed at msg1_deadline" "friend_connect_ms=$f_ms idle_max_closed_ms=${maxc:--}" - - - - - "$(secs_of_ms "$f_ms")" "$notes"
  row_end
}

dos3_run() {
  local t0 el ok=0 v=PASS notes="" line opened alive=0
  if [[ $HAVE_KF != 1 ]]; then vd DOS3 dos NOTRUN "-" "CHV_KNOCKFLOOD not set (example knockflood does not exist yet)"; return 0; fi
  WHY=""
  row_begin DOS3 $(( HOLD_SECS + 600 )) || { vd DOS3 dos INCONCLUSIVE "-" "topology did not come up"; row_end; return 0; }
  ca ce "$DL"
  node_start ce ce "${CA[@]}" --invite-out "$W/ce/inv-real" --invite-out "$W/ce/inv-hold"
  mkdir -p "$W/pk"
  deliver "$W/ce/inv-hold" "$W/pk/inv-hold" 60 || WHY="invite for the holder not issued"
  if [[ -z "$WHY" ]]; then
    tool_start hold-invite pk --mode invite-hold --target "$CALLEE:4433" --invite "$W/pk/inv-hold" --conns "$HOLD_CONNS" --secs "$HOLD_SECS"
    sleep 5
    tool_alive hold-invite || WHY="holder tool exited early"
  fi
  if [[ -n "$WHY" ]]; then row_end; vd DOS3 dos INCONCLUSIVE "-" "$WHY"; return 0; fi
  # the real invitee starts while the holder is holding
  ca fr "$DL"
  deliver "$W/ce/inv-real" "$W/fr/inv" 60 || { row_end; vd DOS3 dos INCONCLUSIVE "-" "invite for FR not issued"; return 0; }
  t0="$(now_s)"
  node_start fr fr "${CA[@]}" --invite-in "$W/fr/inv"
  if wait_grep fr '^EVENT (invite_finished pair=i1 outcome=Added|connected pair=i1 )' $(( HOLD_SECS + 60 )); then
    ok=1; el=$(( $(now_s) - t0 ))
    tool_alive hold-invite && alive=1
  fi
  tool_wait hold-invite $(( HOLD_SECS + 60 )) || true
  line="$(grep -E 'opened=[0-9]+' "$RD/hold-invite.log" 2>/dev/null | tail -n1 || true)"
  opened="$(kv opened <<<" $line")"
  notes+="holder sessions opened=${opened:--}; invite TTL ${INVITE_TTL} s (assumption: default); "
  if [[ "${opened:-0}" == 0 ]]; then v=INCONCLUSIVE; notes+="holder opened no session; "
  elif [[ $ok != 1 ]]; then v=FAIL; notes+="real invitee did not complete; "
  elif [[ $alive != 1 ]]; then v=FAIL; notes+="real invitee completed only after the holders left; "
  elif (( el > INVITE_TTL )); then v=FAIL; notes+="completed after the TTL; "
  fi
  verdict DOS3 dos "$v" "invitee completes within TTL while holders hold" "completed=$ok after_s=${el:--} holders_alive=$alive" - - - - - "${el:--}" "$notes"
  row_end
}

# ---------------------------------------------------------------- build-liar (normal user; sources are COPIED, never edited in place)
# Patch points, each exactly one occurrence or NOTRUN:
#  a) crates/chervo-token/src/addr_update.rs  `match e.addr.ip() {`  - the single place where the update builder takes the
#     own address of the signer; the port stays the signer's own (4433 in this stand, equal to the victim's port).
#  b) crates/chervo-token/src/addr_flow.rs    the two `encode_addr_info(<observed>, ours)` calls (initiator and answerer).
#  c) crates/chervo-connect/src/invite.rs     `let expires_at = unix.saturating_add(ttl_secs);` in create_invite - the single
#     place where the token address list is final; one statement is inserted before it that appends the victim (port 4433).
do_build_liar() { # a|b|c
  [[ "$(id -u)" != 0 ]] || die "build-liar runs as a normal user, not root"
  command -v cargo >/dev/null 2>&1 || die "no cargo"
  local v="${1:-}" d f n n2 e1 e2 tag
  [[ "$v" == a || "$v" == b || "$v" == c ]] || die "usage: stage17.sh build-liar a|b|c"
  d="$(mktemp -d /tmp/chervo-liar17.XXXXXX)"; chmod 700 -- "$d"
  cp -r "$REPO/crates" "$REPO/Cargo.toml" "$REPO/Cargo.lock" "$REPO/rust-toolchain.toml" "$d/"
  if [[ "$v" == a ]]; then
    f="$d/crates/chervo-token/src/addr_update.rs"
    e1='match e.addr.ip() {'
    n="$(grep -cF -- "$e1" "$f" || true)"
    if [[ "$n" != 1 ]]; then
      rm -rf -- "$d"; echo "NOTRUN: patch expression found $n times (need 1): the code changed, X02a is not built" >&2; exit 3
    fi
    sed -i "s|match e.addr.ip() {|match std::net::IpAddr::V4(std::net::Ipv4Addr::new(11, 0, 0, 66)) {|" "$f"
    tag=a
  elif [[ "$v" == c ]]; then
    f="$d/crates/chervo-connect/src/invite.rs"
    e1='let expires_at = unix.saturating_add(ttl_secs);'
    n="$(grep -cF -- "$e1" "$f" || true)"
    if [[ "$n" != 1 ]]; then
      rm -rf -- "$d"; echo "NOTRUN: patch expression found $n times (need 1): the code changed, X02c is not built" >&2; exit 3
    fi
    sed -i 's|let expires_at = unix.saturating_add(ttl_secs);|let mut addrs = addrs; addrs.push("'"$VICTIM"':4433".parse().expect("liar")); let expires_at = unix.saturating_add(ttl_secs);|' "$f"
    tag=c
  else
    f="$d/crates/chervo-token/src/addr_flow.rs"
    e1='let frame = encode_addr_info(normalize(conn.remote_addr()), ours)?;'
    e2='let frame = encode_addr_info(via, ours)?;'
    n="$(grep -cF -- "$e1" "$f" || true)"; n2="$(grep -cF -- "$e2" "$f" || true)"
    if [[ "$n" != 1 || "$n2" != 1 ]]; then
      rm -rf -- "$d"; echo "NOTRUN: patch expressions found $n and $n2 times (need 1 and 1): the code changed, X02b is not built" >&2; exit 3
    fi
    sed -i \
      -e "s|let frame = encode_addr_info(normalize(conn.remote_addr()), ours)?;|let frame = encode_addr_info(\"$VICTIM:4433\".parse().expect(\"liar\"), ours)?;|" \
      -e "s|let frame = encode_addr_info(via, ours)?;|let frame = encode_addr_info(\"$VICTIM:4433\".parse().expect(\"liar\"), ours)?;|" \
      "$f"
    tag=b
  fi
  ( cd "$d" && CARGO_TARGET_DIR="$d/target" cargo build --release --locked -p chervo-transfer --example node16 ) >&2 \
    || { echo "build failed; directory $d kept for inspection" >&2; exit 3; }
  echo "$d/target/release/examples/node16"
  echo "CHV_NODE17_LIAR_${tag^^}=<path above>; the build must be root-owned and not group/other-writable (cp it to a root-owned dir); afterwards: rm -rf '$d'" >&2
}

# ---------------------------------------------------------------- preflight, dispatcher
do_preflight() {
  local t ok=1 free
  for t in ip nft tcpdump awk sed; do
    command -v "$t" >/dev/null 2>&1 || { echo "PREFLIGHT FAIL: no $t" >&2; ok=0; }
  done
  [[ $ok == 1 ]] || exit 3
  if ip netns add "${PFX}pf" 2>/dev/null; then
    nsx pf nft list ruleset >/dev/null 2>&1 || { ok=0; echo "PREFLIGHT FAIL: nft inside ns does not work" >&2; }
    ip netns del "${PFX}pf" 2>/dev/null || true
  else
    ok=0; echo "PREFLIGHT FAIL: cannot create ns ${PFX}pf" >&2
  fi
  [[ $ok == 1 ]] || exit 3
  free="$(df -Pk "$STATE" | awk 'NR == 2 { print int($4 / 1024) }')"
  echo "PREFLIGHT: root ok; ip nft tcpdump ok; nft in ns ok; free in STATE: ${free:-?} MiB"
  echo "PREFLIGHT: binaries: node16 ok; liar_a=$HAVE_LIAR_A liar_b=$HAVE_LIAR_B liar_c=$HAVE_LIAR_C knockflood=$HAVE_KF"
  mkdir -p -- "$LOGS"
  {
    echo "date=$(date +%F)"
    echo "commit=$(git -c safe.directory="$REPO" -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "kernel=$(uname -r)"
    echo "nft=$(nft --version 2>&1 | head -n1)"
    echo "win=$WIN burst_gap=$BURST_GAP burst_max=$BURST_MAX flood_secs=$FLOOD_SECS flood_pps=$FLOOD_PPS hold_conns=$HOLD_CONNS"
    echo "msg1_ms=$MSG1_MS invite_ttl=$INVITE_TTL conn_factor=$CONN_FACTOR nice=$NICE_N"
  } > "$LOGS/meta17.txt"
}

run_row() {
  case "$1" in
    X02a) x02a_run ;;
    X02b) x02b_run ;;
    X02c) x02c_run ;;
    DOS1) dos1_run ;;
    DOS2) dos2_run ;;
    DOS3) dos3_run ;;
    *) return 2 ;;
  esac
}

usage() {
  echo "usage: stage17.sh <preflight|X02a|X02b|X02c|DOS1|DOS2|DOS3|x02|dos|all|teardown|build-liar a|b|c>" >&2
}

cleanup() {
  local l
  if [[ "$STARTED" == 1 ]]; then
    for l in "${!NODE_REAL[@]}"; do node_kill "$l"; done
    tools_stop 2>/dev/null || true
    tcpd_stop 2>/dev/null || true
    do_teardown || true
    if [[ -n "${SUDO_UID:-}" && -d "$LOGS" ]]; then chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" -- "$LOGS" 2>/dev/null || true; fi
  fi
  if [[ "$STATE_OWNED" == 1 && "${CHV_KEEP:-0}" != 1 && -n "$STATE" && "$STATE" != / ]]; then rm -rf -- "$STATE"; fi
}

main() {
  case "$CMD" in
    build-liar) do_build_liar "$ARG2"; exit 0 ;;
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
    x02) run_row X02a; run_row X02b; run_row X02c ;;
    dos) run_row DOS1; run_row DOS2; run_row DOS3 ;;
    all)
      do_preflight
      run_row X02a; run_row X02b; run_row X02c
      run_row DOS1; run_row DOS2; run_row DOS3
      echo "--- $SUMMARY"; cat -- "$SUMMARY" ;;
    *)
      run_row "$CMD"
      if [[ $? == 2 ]]; then usage; exit 2; fi ;;
  esac
  hostsafe_end "$CMD"
}
main
