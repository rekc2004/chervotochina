#!/usr/bin/env bash
# Stage 19e-3 (SPEC 19e 3.1, 5.3 item 2): independent check of a built .deb (the package is checked by what is IN it,
# not by what the builder meant to put there).
#   bash scripts/release/check-deb.sh <deb> <gui-elf> <cli-elf> <version>
# Checks: the control fields and their ORDER exactly as in 3.1 (no Pre-Depends/Recommends/Enhances/Conflicts/Breaks/
# Provides/Replaces/Essential: any other field fails), Depends by the template, the control part is exactly
# ./ ./control ./md5sums (no maintainer scripts, no conffiles/triggers), the data part is exactly the list of 3.1
# (all root:root = 0/0, modes, no links, setuid, setgid or devices), the binaries inside equal the inputs byte for
# byte, the .desktop and the icons equal the files of packaging/, md5sums matches, Installed-Size matches the data.
# Exit 0 = all ok, 1 = something is wrong (every problem is printed), 2 = usage.
# Uses only dpkg-deb, tar, md5sum, cmp. The negative cases are in `package-deb.sh --self-test`.
set -euo pipefail
export LC_ALL=C

root="$(cd "$(dirname "$0")/../.." && pwd)"
APP_ID=io.github.rekc2004.chervotochina
HOMEPAGE=https://github.com/rekc2004/chervotochina
MAINTAINER='Chervotochina <161205578+rekc2004@users.noreply.github.com>'
DESC1='Червоточина: прямая передача файлов между компьютерами'
SIZES=(16 32 48 64 128 256 512)

if [[ $# -ne 4 ]]; then
  echo "usage: check-deb.sh <deb> <gui-elf> <cli-elf> <version>" >&2
  exit 2
fi
deb="$1"; gui="$2"; cli="$3"; ver="$4"
[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "check-deb: bad version '$ver'" >&2; exit 2; }
for t in dpkg-deb tar md5sum cmp awk; do
  command -v "$t" >/dev/null 2>&1 || { echo "check-deb: '$t' is not available" >&2; exit 1; }
done
[[ -f "$deb" && ! -L "$deb" ]] || { echo "check-deb: no such file: $deb" >&2; exit 1; }

bad=0
err() { echo "check-deb: $*" >&2; bad=1; }

# --- control fields -----------------------------------------------------------------------------------
ctrl="$(dpkg-deb -f "$deb")"
got_names="$(awk '/^[^ \t]/ { sub(/:.*/, ""); print }' <<<"$ctrl" | tr '\n' ' ')"
want_names='Package Version Architecture Maintainer Installed-Size Depends Suggests Section Priority Homepage Description '
[[ "$got_names" == "$want_names" ]] || err "control fields are '$got_names', expected '$want_names' (in this order, nothing else)"
field() { dpkg-deb -f "$deb" "$1" 2>/dev/null || true; }
[[ "$(field Package)" == chervotochina ]] || err "Package is not chervotochina"
[[ "$(field Version)" == "$ver" ]] || err "Version is '$(field Version)', expected '$ver'"
[[ "$(field Architecture)" == amd64 ]] || err "Architecture is not amd64"
[[ "$(field Maintainer)" == "$MAINTAINER" ]] || err "Maintainer is '$(field Maintainer)'"
[[ "$(field Suggests)" == gnome-keyring ]] || err "Suggests is not exactly 'gnome-keyring'"
[[ "$(field Section)" == net ]] || err "Section is not net"
[[ "$(field Priority)" == optional ]] || err "Priority is not optional"
[[ "$(field Homepage)" == "$HOMEPAGE" ]] || err "Homepage is wrong"
dep="$(field Depends)"
dep_re='^libc6 \(>= 2\.[0-9]+\)(, libgcc-s1)?$'
[[ "$dep" =~ $dep_re ]] || err "Depends '$dep' does not match: libc6 (>= 2.N)[, libgcc-s1]"
desc="$(field Description)"
desc="${desc%%$'\n'*}"
[[ "$desc" == "$DESC1" ]] || err "Description (first line) is '$desc'"
for f in Pre-Depends Recommends Enhances Conflicts Breaks Provides Replaces Essential Depends-extra; do
  [[ -z "$(field "$f")" ]] || err "forbidden field $f"
done

# --- tar listings -------------------------------------------------------------------------------------
# list KIND -> lines "perms owner size name" (GNU tar --numeric-owner -tv).
list() { dpkg-deb "--$1" "$deb" | tar --numeric-owner -tvf - | awk '{ n = $0; sub(/^[^ ]+ +[^ ]+ +[0-9]+ +[0-9-]+ +[0-9:]+ /, "", n); print $1, $2, $3, n }'; }

cl="$(list ctrl-tarfile)"
cnames="$(awk '{ print $4 }' <<<"$cl" | LC_ALL=C sort | tr '\n' ' ')"
[[ "$cnames" == './ ./control ./md5sums ' ]] || err "control part is '$cnames', expected exactly './ ./control ./md5sums ' (no maintainer scripts)"
while read -r perms owner size name; do
  [[ -n "$perms" ]] || continue
  [[ "$owner" == 0/0 ]] || err "control part: $name has owner $owner"
  case "$name" in
    ./) [[ "$perms" == drwxr-xr-x ]] || err "control part: ./ has mode $perms" ;;
    *)  [[ "$perms" == -rw-r--r-- ]] || err "control part: $name has mode $perms" ;;
  esac
done <<<"$cl"

want_files=( "usr/bin/chervotochina" "usr/bin/chervo" "usr/share/applications/$APP_ID.desktop" "usr/share/doc/chervotochina/copyright" )
want_dirs=( "" usr usr/bin usr/share usr/share/applications usr/share/icons usr/share/icons/hicolor usr/share/doc usr/share/doc/chervotochina )
for s in "${SIZES[@]}"; do
  want_files+=( "usr/share/icons/hicolor/${s}x${s}/apps/$APP_ID.png" )
  want_dirs+=( "usr/share/icons/hicolor/${s}x${s}" "usr/share/icons/hicolor/${s}x${s}/apps" )
done
want_list="$( { for f in "${want_files[@]}"; do echo "./$f"; done; for d in "${want_dirs[@]}"; do if [[ -z "$d" ]]; then echo "./"; else echo "./$d/"; fi; done; } | LC_ALL=C sort | tr '\n' ' ')"
fl="$(list fsys-tarfile)"
got_list="$(awk '{ print $4 }' <<<"$fl" | LC_ALL=C sort | tr '\n' ' ')"
[[ "$got_list" == "$want_list" ]] || err "data part differs from the list of 3.1. Got: $got_list"$'\n'"  Expected: $want_list"
total=0; nfiles=0
while read -r perms owner size name; do
  [[ -n "$perms" ]] || continue
  [[ "$owner" == 0/0 ]] || err "$name has owner $owner (must be 0/0)"
  case "${perms:0:1}" in
    d) [[ "$perms" == drwxr-xr-x ]] || err "$name: directory mode $perms (must be drwxr-xr-x)" ;;
    -)
      nfiles=$((nfiles + 1)); total=$((total + size))
      if [[ "$name" == ./usr/bin/chervotochina || "$name" == ./usr/bin/chervo ]]; then
        [[ "$perms" == -rwxr-xr-x ]] || err "$name: mode $perms (must be -rwxr-xr-x)"
      else
        [[ "$perms" == -rw-r--r-- ]] || err "$name: mode $perms (must be -rw-r--r--)"
      fi ;;
    *) err "$name: not a plain file or directory (type '${perms:0:1}': link, device or other)" ;;
  esac
done <<<"$fl"
kib=$(((total + 1023) / 1024))
[[ "$(field Installed-Size)" == "$kib" ]] || err "Installed-Size is '$(field Installed-Size)', the data is $kib KiB"

# --- contents -----------------------------------------------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if dpkg-deb -x "$deb" "$tmp/x" && dpkg-deb -e "$deb" "$tmp/c"; then
  cmp -s -- "$gui" "$tmp/x/usr/bin/chervotochina" || err "/usr/bin/chervotochina differs from the input $gui"
  cmp -s -- "$cli" "$tmp/x/usr/bin/chervo" || err "/usr/bin/chervo differs from the input $cli"
  cmp -s -- "$root/packaging/linux/$APP_ID.desktop" "$tmp/x/usr/share/applications/$APP_ID.desktop" || err "the .desktop file differs from packaging/linux"
  for s in "${SIZES[@]}"; do
    cmp -s -- "$root/packaging/icons/chervotochina-$s.png" "$tmp/x/usr/share/icons/hicolor/${s}x${s}/apps/$APP_ID.png" || err "icon $s differs from packaging/icons"
  done
  # review 19e B7: the launcher calls the binary of THIS package by its absolute path, without field codes
  [[ "$(grep -c '^Exec=' "$tmp/x/usr/share/applications/$APP_ID.desktop" || true)" == 1 ]] &&
    grep -qxF 'Exec=/usr/bin/chervotochina' "$tmp/x/usr/share/applications/$APP_ID.desktop" ||
    err "the .desktop file must have exactly one line 'Exec=/usr/bin/chervotochina'"
  [[ -s "$tmp/x/usr/share/doc/chervotochina/copyright" ]] || err "copyright is empty"
  grep -qF "chervo-$ver-third-party-licenses.txt" "$tmp/x/usr/share/doc/chervotochina/copyright" || err "copyright does not name the third-party licences file"
  if [[ -f "$tmp/c/md5sums" ]]; then
    (cd "$tmp/x" && md5sum -c --quiet "$tmp/c/md5sums" >/dev/null 2>&1) || err "md5sums does not match the files"
    n="$(grep -c . "$tmp/c/md5sums" || true)"
    [[ "$n" == "$nfiles" ]] || err "md5sums has $n lines, the package has $nfiles files"
  else
    err "no md5sums"
  fi
else
  err "dpkg-deb cannot unpack the package"
fi

if [[ $bad -eq 0 ]]; then
  echo "check-deb: ok ($deb)"
  exit 0
fi
echo "check-deb: FAILED ($deb)" >&2
exit 1
