#!/usr/bin/env bash
# Stage 19e-3 (SPEC 19e R19e-2, 3.3, 5.3 item 3): builds the Windows installer with Inno Setup from the ALREADY BUILT
# window file (the installer packs the same bytes that are signed as the single file; nothing is rebuilt).
#   SOURCE_DATE_EPOCH=<unix time> bash scripts/release/package-windows.sh <gui-exe> <version> <out-dir> <iscc>
#   bash scripts/release/package-windows.sh --self-test
# <iscc> is ISCC.exe of the Inno Setup that fetch-tool.sh downloaded (hash + Authenticode checked by earlier steps).
# Steps: new temp `src` with chervotochina.exe (copy, SHA-256 compared with the input) and chervotochina.ico;
# check-iss.sh on packaging/windows/chervotochina.iss (guard rule 8); ISCC TWICE into two directories; the SHA-256
# of both builds goes to the summary ("совпало"/"не совпало" is only RECORDED: Inno stores time stamps and ids);
# the output is exactly <out-dir>/chervotochina-<version>-windows-x86_64-setup.exe.
# Parameters of ISCC (SPEC 3.3): /DAppVersion /DSrcDir /DTouchDate /DTouchTime /O<dir>; ISPP takes the /D value as a
# plain string (checked in Projects/Src/ISPP.Preprocess.pas of is-6_7_4, ParseDefinition). TouchDate/TouchTime only
# affect [Files] lines with the `touch` flag, the spec has none: so the time stamp of the sources is set to
# SOURCE_DATE_EPOCH here instead. [not verified here: no Inno on this machine; the first check is the trial run in CI]
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=lib.sh
. "$root/scripts/release/lib.sh"

valid_version() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

# epoch_date EPOCH -> YYYY-MM-DD (UTC); epoch_time EPOCH -> HH:MM:SS (UTC)
epoch_date() { date -u -d "@$1" +%Y-%m-%d; }
epoch_time() { date -u -d "@$1" +%H:%M:%S; }

if [[ "${1:-}" == "--self-test" ]]; then
  fail=0
  for v in 1.2.3 0.0.0 10.20.30; do valid_version "$v" || { echo "self-test: FAILED (rejected version $v)" >&2; fail=1; }; done
  for v in 1.2 1.2.3.4 1.2.3-rc1 v1.2.3 '' '1.2.3 ' '$(id)' '1.2.3;x' $'1.2.3\n'; do
    if valid_version "$v"; then echo "self-test: FAILED (accepted version '$v')" >&2; fail=1; fi
  done
  [[ "$(epoch_date 1700000000)" == 2023-11-14 && "$(epoch_time 1700000000)" == 22:13:20 ]] || { echo "self-test: FAILED (epoch to date/time)" >&2; fail=1; }
  [[ -f "$root/packaging/icons/chervotochina.ico" && -f "$root/packaging/windows/chervotochina.iss" ]] || { echo "self-test: FAILED (inputs missing)" >&2; fail=1; }
  rc=0; (SOURCE_DATE_EPOCH=1700000000 bash "$0" /nonexistent 1.2.3 /tmp/x /nonexistent/ISCC.exe >/dev/null 2>&1) || rc=$?
  [[ $rc -ne 0 ]] || { echo "self-test: FAILED (a missing input was accepted)" >&2; fail=1; }
  [[ $fail -eq 0 ]] && echo "self-test: ok"
  exit "$fail"
fi

if [[ $# -ne 4 ]]; then
  echo "usage: package-windows.sh <gui-exe> <version> <out-dir> <iscc> | --self-test" >&2
  exit 2
fi
gui="$1"; ver="$2"; outdir="$3"; iscc="$4"
valid_version "$ver" || { echo "package-windows: bad version '$ver'" >&2; exit 2; }
[[ "${SOURCE_DATE_EPOCH:-}" =~ ^[0-9]+$ ]] || { echo "package-windows: SOURCE_DATE_EPOCH is required (git log -1 --format=%ct)" >&2; exit 2; }
[[ -f "$gui" && ! -L "$gui" ]] || { echo "package-windows: no such file: $gui" >&2; exit 1; }
[[ -f "$iscc" && "${iscc##*[/\\]}" == ISCC.exe ]] || { echo "package-windows: not an ISCC.exe: $iscc" >&2; exit 1; }
[[ "$(head -c 2 "$gui")" == MZ ]] || { echo "package-windows: $gui is not a PE file (no MZ)" >&2; exit 1; }
ico="$root/packaging/icons/chervotochina.ico"
iss="$root/packaging/windows/chervotochina.iss"
[[ -f "$ico" ]] || { echo "package-windows: no $ico" >&2; exit 1; }
name="chervotochina-$ver-windows-x86_64-setup.exe"

mkdir -p "$outdir"
outdir="$(cd "$outdir" && pwd -P)"
[[ ! -e "$outdir/$name" ]] || { echo "package-windows: already exists: $outdir/$name" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
src="$work/src"; mkdir -p "$src"
cp -- "$gui" "$src/chervotochina.exe"
cp -- "$ico" "$src/chervotochina.ico"
[[ "$(sha256_of "$src/chervotochina.exe")" == "$(sha256_of "$gui")" ]] || { echo "package-windows: the copy differs from the input" >&2; exit 1; }
touch -d "@$SOURCE_DATE_EPOCH" "$src/chervotochina.exe" "$src/chervotochina.ico"

bash "$root/scripts/release/check-iss.sh" "$iss"

tdate="$(epoch_date "$SOURCE_DATE_EPOCH")"
ttime="$(epoch_time "$SOURCE_DATE_EPOCH")"
# MSYS must not rewrite the /D and /O arguments as paths.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
build() { # N -> $work/oN/<name>
  local d="$work/o$1"
  mkdir -p "$d"
  "$iscc" "/DAppVersion=$ver" "/DSrcDir=$(native_path "$src")" "/DTouchDate=$tdate" "/DTouchTime=$ttime" \
    "/O$(native_path "$d")" "$(native_path "$iss")" > "$work/iscc$1.log" 2>&1 || {
    echo "package-windows: ISCC failed (build $1); log tail:" >&2; tail -n 40 "$work/iscc$1.log" >&2; return 1; }
  local found=( "$d"/* )
  [[ ${#found[@]} -eq 1 && "${found[0]##*/}" == "$name" && -f "${found[0]}" ]] || {
    echo "package-windows: ISCC output is not exactly $name: ${found[*]}" >&2; return 1; }
}
build 1
build 2
s1="$(sha256_of "$work/o1/$name")"
s2="$(sha256_of "$work/o2/$name")"
if [[ "$s1" == "$s2" ]]; then same="совпало"; else same="не совпало"; fi
cp -- "$work/o1/$name" "$outdir/$name"
summary "### package-windows: $name" "- input sha256:     \`$(sha256_of "$gui")\`" "- installer sha256: \`$s1\`" \
        "- second build:    \`$s2\` ($same; recorded only, Inno puts time stamps and ids into the file)" \
        "- size: $(size_of "$outdir/$name") bytes" "- ISCC banner:" '```' "$(head -n 3 "$work/iscc1.log")" '```'
echo "packaged $outdir/$name"
