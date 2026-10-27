#!/usr/bin/env bash
# Stage 17 (B4): libFuzzer runner for the fuzz/ crate (docs/specs/stage-17-security.md, sec. 4, Q2 = yes).
# Normal user, Linux. Runs every target (or TARGETS) for SECS seconds under `nice`.
#
#   bash tools/fuzz/run17.sh [SECS=1200] [NICE=10] [TARGETS="token_decode sntp"] [MAXLEN=4096] [RSS_MB=2048] [SEED=0] [KEEP=1]
#   (ITERS=... is accepted for compatibility with the stable smoke command line and ignored: libFuzzer is time-bound.)
#
# NOT RUN BY THE BUILDER (no nightly and no cargo-fuzz on the build machine; only `bash -n` was run). The conductor runs
# it on the Linux box after the owner's "yes" for nightly + cargo-fuzz (Q2).
#
# Host safety: all writes go to one mktemp -d directory (mode 700): a COPY of the sources (fuzz/, crates/, Cargo.toml),
# the target dir, the working corpus (seeded from fuzz/corpus/<target> if it exists), artifacts (crashes), logs and
# summary.tsv. Nothing is written into the repository. The only thing outside is cargo's own download cache in
# CARGO_HOME (libfuzzer-sys) when the fuzz/Cargo.lock is not committed yet. Nothing is installed: a missing toolchain or
# cargo-fuzz is a stop. The directory is kept (crashes, corpus); remove it by hand. Exit: 0 clean, 1 crash/fail, 2 usage,
# 3 prerequisites.
set -uo pipefail

SECS=1200; NICE=10; TARGETS=""; MAXLEN=4096; RSS_MB=2048; SEED=0
die() { echo "run17: $*" >&2; exit 2; }
need() { echo "run17: STOP: $*" >&2; exit 3; }

for a in "$@"; do
  case "$a" in
    SECS=*) SECS="${a#SECS=}" ;;
    NICE=*) NICE="${a#NICE=}" ;;
    TARGETS=*) TARGETS="${a#TARGETS=}" ;;
    MAXLEN=*) MAXLEN="${a#MAXLEN=}" ;;
    RSS_MB=*) RSS_MB="${a#RSS_MB=}" ;;
    SEED=*) SEED="${a#SEED=}" ;;
    KEEP=*) ;;
    ITERS=*) echo "run17: ITERS ignored (libFuzzer runs by time, use SECS)" >&2 ;;
    *) die "unknown argument: $a" ;;
  esac
done
for v in SECS NICE MAXLEN RSS_MB SEED; do
  [[ "${!v}" =~ ^[0-9]+$ ]] || die "$v must be a non-negative integer"
done
(( SECS >= 1 && NICE >= 0 && NICE <= 19 )) || die "SECS >= 1, NICE 0..19"
[[ "$TARGETS" =~ ^[A-Za-z0-9_\ ]*$ ]] || die "TARGETS: names separated by spaces"

[[ "$(id -u)" != 0 ]] || die "run as a normal user, not root"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ -f "$REPO/fuzz/Cargo.toml" && -f "$REPO/Cargo.toml" && -d "$REPO/crates" ]] || need "no fuzz/Cargo.toml in $REPO"

# prerequisites (nothing is installed here)
command -v cargo >/dev/null 2>&1 || need "no cargo"
command -v rustup >/dev/null 2>&1 || need "no rustup"
TC="$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' "$REPO/fuzz/rust-toolchain.toml" | head -n1)"
[[ "$TC" == nightly* ]] || need "fuzz/rust-toolchain.toml has no nightly channel"
rustup toolchain list 2>/dev/null | awk '{print $1}' | grep -q "^$TC" \
  || need "toolchain $TC is not installed (install needs the owner's yes: rustup toolchain install $TC --profile minimal)"
export RUSTUP_TOOLCHAIN="$TC"
FV="$(cargo fuzz --version 2>/dev/null | head -n1)"
[[ "$FV" == *"0.13.2"* ]] || need "cargo-fuzz 0.13.2 required, found: ${FV:-none} (install needs the owner's yes)"

# target list: from the manifest, so that adding a [[bin]] needs no change here
ALL="$(sed -n 's/^name = "\(.*\)"/\1/p' "$REPO/fuzz/Cargo.toml" | grep -vx 'chervo-fuzz' | tr '\n' ' ')"
[[ -n "$TARGETS" ]] || TARGETS="$ALL"
for t in $TARGETS; do
  [[ " $ALL " == *" $t "* ]] || die "unknown target: $t (have: $ALL)"
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/chervo-fuzz17.XXXXXX")" || need "mktemp failed"
chmod 700 -- "$WORK"
[[ -d "$WORK" && ! -L "$WORK" && "$(stat -c %u -- "$WORK")" == "$(id -u)" ]] || need "work dir is not ours"
mkdir -p -- "$WORK/src" "$WORK/target" "$WORK/corpus" "$WORK/artifacts" "$WORK/logs"
CHILD=""
cleanup() {
  if [[ -n "$CHILD" ]]; then kill "$CHILD" 2>/dev/null || true; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# copy of the sources (the repo is never written)
cp -r -- "$REPO/crates" "$REPO/Cargo.toml" "$WORK/src/" || need "copy of crates failed"
[[ ! -f "$REPO/Cargo.lock" ]] || cp -- "$REPO/Cargo.lock" "$WORK/src/"
mkdir -p -- "$WORK/src/fuzz"
cp -r -- "$REPO/fuzz/Cargo.toml" "$REPO/fuzz/rust-toolchain.toml" "$REPO/fuzz/fuzz_targets" "$WORK/src/fuzz/"
[[ ! -f "$REPO/fuzz/Cargo.lock" ]] || cp -- "$REPO/fuzz/Cargo.lock" "$WORK/src/fuzz/"
export CARGO_TARGET_DIR="$WORK/target"

echo "run17: work dir $WORK (kept); toolchain $TC; $FV; SECS=$SECS NICE=$NICE MAXLEN=$MAXLEN RSS_MB=$RSS_MB SEED=$SEED" >&2
echo "run17: targets: $TARGETS" >&2

cd -- "$WORK/src" || exit 3
echo "run17: building all targets (nice $NICE)" >&2
nice -n "$NICE" cargo fuzz build --fuzz-dir "$WORK/src/fuzz" >"$WORK/logs/build.log" 2>&1 \
  || { tail -n 30 "$WORK/logs/build.log" >&2; need "cargo fuzz build failed (see $WORK/logs/build.log)"; }

printf 'target\tsecs\texecs\tcorpus_files\tcrashes\tresult\n' > "$WORK/summary.tsv"
FAIL=0
for t in $TARGETS; do
  mkdir -p -- "$WORK/corpus/$t" "$WORK/artifacts/$t"
  if [[ -d "$REPO/fuzz/corpus/$t" ]]; then cp -r -- "$REPO/fuzz/corpus/$t/." "$WORK/corpus/$t/" 2>/dev/null || true; fi
  extra=()
  (( SEED == 0 )) || extra+=("-seed=$SEED")
  t0=$(date +%s)
  nice -n "$NICE" timeout --signal=TERM --kill-after=30 "$(( SECS + 300 ))" \
    cargo fuzz run --fuzz-dir "$WORK/src/fuzz" "$t" "$WORK/corpus/$t" -- \
      "-max_total_time=$SECS" "-max_len=$MAXLEN" "-rss_limit_mb=$RSS_MB" "-timeout=10" \
      "-artifact_prefix=$WORK/artifacts/$t/" "-print_final_stats=1" ${extra[@]+"${extra[@]}"} \
      >"$WORK/logs/$t.log" 2>&1 &
  CHILD=$!
  wait "$CHILD"; rc=$?
  CHILD=""
  el=$(( $(date +%s) - t0 ))
  execs="$(sed -n 's/^stat::number_of_executed_units: *\([0-9]*\).*/\1/p' "$WORK/logs/$t.log" | tail -n1)"
  nfiles="$(find "$WORK/corpus/$t" -type f 2>/dev/null | wc -l)"
  ncrash="$(find "$WORK/artifacts/$t" -type f 2>/dev/null | wc -l)"
  if (( rc == 0 && ncrash == 0 )); then res=OK; else res="FAIL(rc=$rc)"; FAIL=1; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$t" "$el" "${execs:--}" "$nfiles" "$ncrash" "$res" >> "$WORK/summary.tsv"
done

echo "---- summary ($WORK/summary.tsv)"
column -t -s "$(printf '\t')" "$WORK/summary.tsv" 2>/dev/null || cat "$WORK/summary.tsv"
if [[ ! -f "$REPO/fuzz/Cargo.lock" && -f "$WORK/src/fuzz/Cargo.lock" ]]; then
  echo "note: fuzz/Cargo.lock is not committed; generated copy: $WORK/src/fuzz/Cargo.lock"
fi
if (( FAIL )); then
  echo "FAIL: crash inputs are in $WORK/artifacts/<target>/ (synthetic data only; triage as a finding, do not edit the fuzzer)"
  exit 1
fi
echo "OK: no crashes. Corpus: $WORK/corpus (for cargo fuzz cmin and commit under fuzz/corpus/<target>/, <= 5 MiB total)"
exit 0
