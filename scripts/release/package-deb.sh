#!/usr/bin/env bash
# Stage 19e-3 (SPEC 19e R19e-4, 3.1, 5.3 item 1): builds the .deb from the ALREADY BUILT release ELF files
# (the installer packs the same bytes that are signed as single files; nothing is rebuilt).
#   SOURCE_DATE_EPOCH=<unix time> bash scripts/release/package-deb.sh <gui-elf> <cli-elf> <version> <out-dir>
#   bash scripts/release/package-deb.sh --self-test        (Linux only: needs dpkg-deb, tar, xz, ar, readelf, objdump)
# Output: <out-dir>/chervotochina-<version>-linux-x86_64.deb
#   /usr/bin/chervotochina (= <gui-elf>, byte for byte), /usr/bin/chervo (= <cli-elf>), the .desktop file, the icons
#   of packaging/icons, /usr/share/doc/chervotochina/copyright. NO maintainer scripts (no preinst/postinst/prerm/
#   postrm/config/triggers/conffiles): nothing but file copying runs as root. Owner root:root, directories 0755,
#   binaries 0755, the rest 0644, no links, no setuid/setgid, no devices.
# Depends comes from NEEDED of both ELF files by a CLOSED table (libc6, libgcc-s1); another name = stop (exit 1).
# The package is built TWICE in two new directories and compared with cmp: a difference FAILS (R19e-9);
# the result is then checked by check-deb.sh. [not verified on a runner: the dpkg-deb flags are from the man page,
# dpkg 1.21.1 on ubuntu-22.04 supports --root-owner-group, -Zxz and SOURCE_DATE_EPOCH]
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=lib.sh
. "$root/scripts/release/lib.sh"

APP_ID=io.github.rekc2004.chervotochina
HOMEPAGE=https://github.com/rekc2004/chervotochina
MAINTAINER='Chervotochina <161205578+rekc2004@users.noreply.github.com>'
ICON_SIZES=(16 32 48 64 128 256 512)

valid_version() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; }
is_elf() { [[ -f "$1" && ! -L "$1" && "$(head -c 4 "$1" | od -An -tx1 | tr -d ' \n')" == 7f454c46 ]]; }

# --- Depends (closed table) -------------------------------------------------------------------------
# needed_pkgs: stdin = `readelf -d` output; stdout = Debian package per NEEDED library (one per line);
# returns 1 and names the library when it is not in the table.
needed_pkgs() {
  local line lib bad=0
  while IFS= read -r line; do
    [[ "$line" == *'(NEEDED)'* ]] || continue
    lib="${line#*\[}"; lib="${lib%%\]*}"
    case "$lib" in
      libc.so.6|libm.so.6|libpthread.so.0|libdl.so.2|librt.so.1|ld-linux-x86-64.so.2) echo libc6 ;;
      libgcc_s.so.1) echo libgcc-s1 ;;
      *) echo "package-deb: NEEDED library is not in the closed table: $lib" >&2; bad=1 ;;
    esac
  done
  return "$bad"
}

# max_glibc: stdin = `objdump -T` output; stdout = highest GLIBC_a.b as "a.b" (two components), or nothing.
max_glibc() {
  grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/^GLIBC_//' | LC_ALL=C sort -t. -k1,1n -k2,2n -u | tail -n 1
}

# depends_line GUI CLI -> the Depends value on stdout: `libc6 (>= X)[, libgcc-s1]`.
depends_line() {
  local f pkgs="" ver="" v out
  for f in "$1" "$2"; do
    out="$(readelf -d "$f")"
    pkgs+="$(needed_pkgs <<<"$out")"$'\n' || return 1
    v="$(objdump -T "$f" | max_glibc)"
    ver+="$v"$'\n'
  done
  ver="$(grep -E '^[0-9]+\.[0-9]+$' <<<"$ver" | LC_ALL=C sort -t. -k1,1n -k2,2n -u | tail -n 1 || true)"
  [[ -n "$ver" ]] || { echo "package-deb: no GLIBC_x.y version found in objdump -T" >&2; return 1; }
  grep -qx libc6 <<<"$pkgs" || { echo "package-deb: libc6 is not among the NEEDED packages" >&2; return 1; }
  if grep -qx libgcc-s1 <<<"$pkgs"; then
    printf 'libc6 (>= %s), libgcc-s1\n' "$ver"
  else
    printf 'libc6 (>= %s)\n' "$ver"
  fi
}

# --- the package tree ------------------------------------------------------------------------------
# write_copyright VERSION FILE: no licence is invented (the project has none yet: no LICENSE, no `license` field).
write_copyright() {
  {
    printf 'Name: chervotochina\n'
    printf 'Source: %s\n\n' "$HOMEPAGE"
    printf 'Chervotochina (chervotochina, chervo): direct file transfer between computers.\n'
    printf 'Project address: %s\n' "$HOMEPAGE"
    printf 'Лицензия проекта: см. адрес проекта.\n'
    printf 'Лицензии сторонних компонентов: файл chervo-%s-third-party-licenses.txt в выпуске.\n' "$1"
  } > "$2"
}

# build_stage STAGE VERSION GUI CLI DEPENDS: fills STAGE (data tree + DEBIAN/control and md5sums).
build_stage() {
  local stage="$1" ver="$2" gui="$3" cli="$4" deps="$5" s d total=0 f kib
  local desktop="$root/packaging/linux/$APP_ID.desktop"
  [[ -f "$desktop" ]] || { echo "package-deb: no $desktop" >&2; return 1; }
  umask 022
  mkdir -p "$stage/usr/bin" "$stage/usr/share/applications" "$stage/usr/share/doc/chervotochina" "$stage/DEBIAN"
  cp -- "$gui" "$stage/usr/bin/chervotochina"
  cp -- "$cli" "$stage/usr/bin/chervo"
  chmod 0755 "$stage/usr/bin/chervotochina" "$stage/usr/bin/chervo"
  cp -- "$desktop" "$stage/usr/share/applications/$APP_ID.desktop"
  for s in "${ICON_SIZES[@]}"; do
    [[ -f "$root/packaging/icons/chervotochina-$s.png" ]] || { echo "package-deb: no icon $s" >&2; return 1; }
    d="$stage/usr/share/icons/hicolor/${s}x${s}/apps"
    mkdir -p "$d"
    cp -- "$root/packaging/icons/chervotochina-$s.png" "$d/$APP_ID.png"
  done
  write_copyright "$ver" "$stage/usr/share/doc/chervotochina/copyright"
  # directories 0755, regular files 0644 except the two binaries
  find "$stage" -type d -exec chmod 0755 {} +
  find "$stage" -type f ! -path "$stage/usr/bin/*" -exec chmod 0644 {} +
  # Installed-Size: KiB of the data files, rounded up
  while IFS= read -r f; do total=$((total + $(size_of "$f"))); done < <(find "$stage/usr" -type f | LC_ALL=C sort)
  kib=$(((total + 1023) / 1024))
  {
    printf 'Package: chervotochina\n'
    printf 'Version: %s\n' "$ver"
    printf 'Architecture: amd64\n'
    printf 'Maintainer: %s\n' "$MAINTAINER"
    printf 'Installed-Size: %s\n' "$kib"
    printf 'Depends: %s\n' "$deps"
    printf 'Suggests: gnome-keyring\n'
    printf 'Section: net\n'
    printf 'Priority: optional\n'
    printf 'Homepage: %s\n' "$HOMEPAGE"
    printf 'Description: Червоточина: прямая передача файлов между компьютерами\n'
    printf ' Окно chervotochina и консольная программа chervo. Ключи хранятся в\n'
    printf ' Secret Service (gnome-keyring, KWallet, KeePassXC); если его нет,\n'
    printf ' программа скажет об этом при запуске, подробности: chervo doctor.\n'
  } > "$stage/DEBIAN/control"
  # md5sums: relative paths, sorted by path
  (cd "$stage" && find usr -type f | LC_ALL=C sort | while IFS= read -r f; do h="$(md5sum -- "$f")"; printf '%s  %s\n' "${h%% *}" "$f"; done) > "$stage/DEBIAN/md5sums"
  chmod 0644 "$stage/DEBIAN/control" "$stage/DEBIAN/md5sums"
  # normalised mtime for everything (links are not present; -h anyway)
  find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
}

# build_once VERSION GUI CLI DEPENDS OUTDIR -> OUTDIR/chervotochina-<v>-linux-x86_64.deb (new temp stage, removed after)
build_once() {
  local ver="$1" gui="$2" cli="$3" deps="$4" outdir="$5" stage
  stage="$(mktemp -d)"
  mkdir -p "$outdir"
  build_stage "$stage" "$ver" "$gui" "$cli" "$deps" || { rm -rf "$stage"; return 1; }
  dpkg-deb --root-owner-group -Zxz --build "$stage" "$outdir/chervotochina-$ver-linux-x86_64.deb" >/dev/null
  rm -rf "$stage"
}

package() { # GUI CLI VERSION OUTDIR
  local gui="$1" cli="$2" ver="$3" outdir="$4" deps a b out
  valid_version "$ver" || { echo "package-deb: bad version '$ver'" >&2; return 2; }
  is_elf "$gui" || { echo "package-deb: not an ELF regular file: $gui" >&2; return 1; }
  is_elf "$cli" || { echo "package-deb: not an ELF regular file: $cli" >&2; return 1; }
  [[ "${SOURCE_DATE_EPOCH:-}" =~ ^[0-9]+$ ]] || { echo "package-deb: SOURCE_DATE_EPOCH is required (e.g. git log -1 --format=%ct)" >&2; return 2; }
  export SOURCE_DATE_EPOCH
  local tool
  for tool in dpkg-deb readelf objdump md5sum tar; do
    command -v "$tool" >/dev/null 2>&1 || { echo "package-deb: '$tool' is not available" >&2; return 1; }
  done
  deps="$(depends_line "$gui" "$cli")" || return 1
  gui="$(cd "$(dirname "$gui")" && pwd -P)/$(basename "$gui")"
  cli="$(cd "$(dirname "$cli")" && pwd -P)/$(basename "$cli")"
  mkdir -p "$outdir"
  out="$(cd "$outdir" && pwd -P)"
  [[ ! -e "$out/chervotochina-$ver-linux-x86_64.deb" ]] || { echo "package-deb: already exists: $out/chervotochina-$ver-linux-x86_64.deb" >&2; return 1; }
  a="$(mktemp -d)"; b="$(mktemp -d)"
  build_once "$ver" "$gui" "$cli" "$deps" "$a" || { rm -rf "$a" "$b"; return 1; }
  build_once "$ver" "$gui" "$cli" "$deps" "$b" || { rm -rf "$a" "$b"; return 1; }
  if ! cmp -s "$a/chervotochina-$ver-linux-x86_64.deb" "$b/chervotochina-$ver-linux-x86_64.deb"; then
    summary "- deb build twice: NOT identical (this FAILS the job: dpkg-deb must be deterministic, R19e-9)" \
            "  1: $(sha256_of "$a/chervotochina-$ver-linux-x86_64.deb")" "  2: $(sha256_of "$b/chervotochina-$ver-linux-x86_64.deb")"
    rm -rf "$a" "$b"
    return 1
  fi
  cp -- "$a/chervotochina-$ver-linux-x86_64.deb" "$out/"
  rm -rf "$a" "$b"
  summary "- deb build twice: identical (cmp), sha256 $(sha256_of "$out/chervotochina-$ver-linux-x86_64.deb")" "- Depends: $deps" \
          "- dpkg-deb: $(dpkg-deb --version | head -n 1)"
  bash "$root/scripts/release/check-deb.sh" "$out/chervotochina-$ver-linux-x86_64.deb" "$gui" "$cli" "$ver"
  echo "packaged $out/chervotochina-$ver-linux-x86_64.deb"
}

# --- self-test -------------------------------------------------------------------------------------
# raw_deb OUT STAGE UID: a .deb from a prepared STAGE (data tree + DEBIAN) by tar + ar, with the given numeric
# owner of the data (negative cases need an owner other than 0, which dpkg-deb --root-owner-group cannot make).
raw_deb() {
  local out="$1" stage="$2" owner="$3" t
  t="$(mktemp -d)"
  printf '2.0\n' > "$t/debian-binary"
  tar --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" -C "$stage/DEBIAN" -cJf "$t/control.tar.xz" .
  tar --exclude=./DEBIAN --owner="$owner" --group="$owner" --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" -C "$stage" -cJf "$t/data.tar.xz" .
  rm -f "$out"
  ar rc "$out" "$t/debian-binary" "$t/control.tar.xz" "$t/data.tar.xz" 2>/dev/null  # GNU ar keeps base names only
  rm -rf "$t"
}

self_test() {
  local fail=0 tmp v=1.2.3 deps
  # 1. pure functions (any OS)
  local sample_ok sample_bad
  sample_ok=' 0x0000000000000001 (NEEDED)             Shared library: [libgcc_s.so.1]
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000c (INIT)               0x1000'
  sample_bad=' 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x0000000000000001 (NEEDED)             Shared library: [libdbus-1.so.3]'
  [[ "$(needed_pkgs <<<"$sample_ok" | sort | tr '\n' ' ')" == 'libc6 libgcc-s1 ' ]] || { echo "self-test: FAILED (needed_pkgs table)" >&2; fail=1; }
  if needed_pkgs <<<"$sample_bad" >/dev/null 2>&1; then echo "self-test: FAILED (unknown NEEDED accepted)" >&2; fail=1; fi
  [[ "$(printf 'x GLIBC_2.2.5 a\nx GLIBC_2.34 b\nx GLIBC_2.9 c\nx GLIBC_PRIVATE d\n' | max_glibc)" == 2.34 ]] || { echo "self-test: FAILED (max_glibc)" >&2; fail=1; }
  valid_version 1.2.3 && ! valid_version 1.2 && ! valid_version '1.2.3 ' && ! valid_version 'v1.2.3' || { echo "self-test: FAILED (version pattern)" >&2; fail=1; }
  if [[ "$(uname -s)" != Linux ]] || ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "self-test: SKIPPED the package part (needs Linux with dpkg-deb); the pure functions passed: $([[ $fail -eq 0 ]] && echo yes || echo NO)"
    return "$fail"
  fi
  for tool in tar xz ar readelf objdump md5sum cmp; do
    command -v "$tool" >/dev/null 2>&1 || { echo "self-test: FAILED ('$tool' is missing)" >&2; return 1; }
  done
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  export SOURCE_DATE_EPOCH=1700000000
  # 2. positive: a real build with /bin/true standing in for both ELF files
  cp -L /bin/true "$tmp/gui"; cp -L /bin/true "$tmp/cli"
  (package "$tmp/gui" "$tmp/cli" "$v" "$tmp/out" >/dev/null) || { echo "self-test: FAILED (positive build)" >&2; return 1; }
  local deb="$tmp/out/chervotochina-$v-linux-x86_64.deb"
  [[ -f "$deb" ]] || { echo "self-test: FAILED (no output file)" >&2; return 1; }
  bash "$root/scripts/release/check-deb.sh" "$deb" "$tmp/gui" "$tmp/cli" "$v" >/dev/null || { echo "self-test: FAILED (check-deb on the good package)" >&2; fail=1; }
  # 3. the same tree through tar+ar is accepted too (validates the helper of the negative cases)
  deps="$(depends_line "$tmp/gui" "$tmp/cli")"
  neg() { # NAME OWNER MUTATION-COMMAND...: stage -> mutate -> raw_deb -> check-deb must fail (rc 1)
    local name="$1" owner="$2" st rc=0
    shift 2
    st="$(mktemp -d)"
    build_stage "$st" "$v" "$tmp/gui" "$tmp/cli" "$deps"
    "$@" "$st"
    raw_deb "$tmp/neg.deb" "$st" "$owner"
    bash "$root/scripts/release/check-deb.sh" "$tmp/neg.deb" "$tmp/gui" "$tmp/cli" "$v" >/dev/null 2>&1 || rc=$?
    rm -rf "$st"
    if [[ "$name" == baseline ]]; then
      [[ $rc -eq 0 ]] || { echo "self-test: FAILED (baseline tar+ar package rejected, rc=$rc)" >&2; fail=1; }
    else
      [[ $rc -eq 1 ]] || { echo "self-test: FAILED ($name: check-deb rc=$rc, expected 1)" >&2; fail=1; }
    fi
  }
  m_none() { :; }
  m_postinst() { printf '#!/bin/sh\nexit 0\n' > "$1/DEBIAN/postinst"; chmod 0755 "$1/DEBIAN/postinst"; }
  m_depends() { sed -i 's/^Depends: .*/Depends: gnome-keyring/' "$1/DEBIAN/control"; }
  m_depends_extra() { sed -i 's/^Depends: \(.*\)$/Depends: \1, gnome-keyring/' "$1/DEBIAN/control"; }
  m_recommends() { sed -i 's/^Suggests: gnome-keyring$/Recommends: gnome-keyring/' "$1/DEBIAN/control"; }
  m_extra_field() { sed -i 's/^Section: net$/Section: net\nPre-Depends: libc6/' "$1/DEBIAN/control"; }
  m_setuid() { chmod 4755 "$1/usr/bin/chervotochina"; }
  m_extra_file() { mkdir -p "$1/etc"; echo x > "$1/etc/x"; }
  m_byte() { printf 'X' | dd of="$1/usr/bin/chervo" bs=1 seek=100 conv=notrunc 2>/dev/null; }
  m_version() { sed -i 's/^Version: .*/Version: 9.9.9/' "$1/DEBIAN/control"; }
  m_symlink() { ln -s chervo "$1/usr/bin/chervo2"; }
  m_world_writable() { chmod 0666 "$1/usr/share/applications/$APP_ID.desktop"; }
  m_conffiles() { echo /etc/x > "$1/DEBIAN/conffiles"; }
  m_desktop() { echo '# x' >> "$1/usr/share/applications/$APP_ID.desktop"; }
  # review 19e B7: Exec must be the absolute path (check-deb also fails on the byte comparison; both are in force)
  m_exec_relative() { sed -i 's#^Exec=.*#Exec=chervotochina#' "$1/usr/share/applications/$APP_ID.desktop"; }
  m_exec_fields() { sed -i 's#^Exec=.*#Exec=/usr/bin/chervotochina %f#' "$1/usr/share/applications/$APP_ID.desktop"; }
  m_md5() { sed -i -e '1s/^a/b/' -e '1t' -e '1s/^./a/' "$1/DEBIAN/md5sums"; }  # always changes the first hash
  neg baseline 0 m_none
  neg postinst 0 m_postinst
  neg depends-gnome-keyring 0 m_depends
  neg depends-extra-package 0 m_depends_extra
  neg recommends 0 m_recommends
  neg pre-depends-field 0 m_extra_field
  neg owner-1000 1000 m_none
  neg setuid 0 m_setuid
  neg extra-file-etc 0 m_extra_file
  neg changed-binary-byte 0 m_byte
  neg wrong-version 0 m_version
  neg symlink 0 m_symlink
  neg world-writable 0 m_world_writable
  neg conffiles 0 m_conffiles
  neg changed-desktop 0 m_desktop
  neg bad-md5sums 0 m_md5
  neg exec-relative 0 m_exec_relative
  neg exec-with-field-code 0 m_exec_fields
  [[ $fail -eq 0 ]] && echo "self-test: ok"
  return "$fail"
}

if [[ "${1:-}" == "--self-test" ]]; then
  rc=0
  self_test || rc=$?
  exit "$rc"
fi

if [[ $# -ne 4 ]]; then
  echo "usage: package-deb.sh <gui-elf> <cli-elf> <version> <out-dir> | --self-test" >&2
  exit 2
fi
rc=0
package "$1" "$2" "$3" "$4" || rc=$?
exit "$rc"
