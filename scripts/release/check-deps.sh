#!/usr/bin/env bash
# Stage 19b: the release binary may depend only on the system.
#   bash scripts/release/check-deps.sh linux|macos|windows <binary>
#   bash scripts/release/check-deps.sh --self-test
#
# linux:   `ldd` lists only libc, libm, libgcc_s, ld-linux*, linux-vdso.
# macos:   `otool -L` lists only /usr/lib/* and /System/Library/Frameworks/*.
# windows: the imported DLL names are read as ASCII strings of the PE file (grep -a); there must be
#          no VCRUNTIME*, MSVCP*, api-ms-win-crt-*. This is a string search over the file, not a
#          parse of the import table; the tool is grep (Git Bash on the runner).
set -euo pipefail

linux_ok() { # stdin: ldd output
  local line first base bad=0
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" ]] && continue
    first="${line%% *}"
    base="${first##*/}"
    case "$base" in
      libc.so*|libm.so*|libgcc_s.so*|ld-linux*|linux-vdso.so*) ;;
      *) echo "unexpected dependency: $base" >&2; bad=1 ;;
    esac
  done
  return "$bad"
}

macos_ok() { # stdin: otool -L output (first line is the file name with a colon)
  local line path bad=0 skip=1
  while IFS= read -r line; do
    if [[ $skip -eq 1 ]]; then skip=0; continue; fi
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" ]] && continue
    path="${line%% (*}"
    case "$path" in
      /usr/lib/*|/System/Library/Frameworks/*) ;;
      *) echo "unexpected dependency: $path" >&2; bad=1 ;;
    esac
  done
  return "$bad"
}

windows_ok() { # stdin: list of DLL names, one per line
  local name bad=0
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    shopt -s nocasematch
    case "$name" in
      vcruntime*|msvcp*|api-ms-win-crt-*|ucrtbase*|msvcr*) echo "forbidden runtime dependency: $name" >&2; bad=1 ;;
    esac
    shopt -u nocasematch
  done
  return "$bad"
}

dll_names() { # $1 = file
  { grep -aoiE '[A-Za-z0-9_.-]+\.dll' -- "$1" || true; } | LC_ALL=C sort -fu
}

if [[ "${1:-}" == "--self-test" ]]; then
  fail=0
  t() { # name expected-rc function input
    local rc=0
    printf '%s\n' "$4" | "$3" 2>/dev/null || rc=$?
    if [[ $rc -ne $2 ]]; then echo "self-test: FAILED ($1: rc=$rc, expected $2)" >&2; fail=1; fi
  }
  t linux-good 0 linux_ok $'\tlinux-vdso.so.1 (0x00007ffc)\n\tlibgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x1)\n\tlibm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x2)\n\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x3)\n\t/lib64/ld-linux-x86-64.so.2 (0x4)'
  t linux-ssl 1 linux_ok $'\tlibc.so.6 => /lib/libc.so.6 (0x3)\n\tlibssl.so.3 => /lib/libssl.so.3 (0x5)'
  t linux-dbus 1 linux_ok $'\tlibdbus-1.so.3 => /lib/libdbus-1.so.3 (0x5)'
  t macos-good 0 macos_ok $'bin:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n\t/System/Library/Frameworks/Security.framework/Versions/A/Security (compatibility version 1.0.0)'
  t macos-homebrew 1 macos_ok $'bin:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n\t/opt/homebrew/lib/libfoo.dylib (compatibility version 1.0.0)'
  t windows-good 0 windows_ok $'KERNEL32.dll\nntdll.dll\nbcrypt.dll'
  t windows-vcruntime 1 windows_ok $'KERNEL32.dll\nVCRUNTIME140.dll'
  t windows-msvcp 1 windows_ok $'msvcp140.dll'
  t windows-ucrt 1 windows_ok $'api-ms-win-crt-runtime-l1-1-0.dll'
  # dll_names finds names inside a binary-looking file
  tmp="$(mktemp)"
  printf 'MZ\0\0KERNEL32.dll\0\0VCRUNTIME140.dll\0' > "$tmp"
  rc=0; dll_names "$tmp" | windows_ok 2>/dev/null || rc=$?
  rm -f "$tmp"
  [[ $rc -eq 1 ]] || { echo "self-test: FAILED (dll_names did not find VCRUNTIME)" >&2; fail=1; }
  [[ $fail -eq 0 ]] && echo "self-test: ok"
  exit "$fail"
fi

if [[ $# -ne 2 ]]; then
  echo "usage: check-deps.sh linux|macos|windows <binary>" >&2
  exit 2
fi
os="$1"
bin="$2"
[[ -f "$bin" ]] || { echo "no such file: $bin" >&2; exit 2; }

case "$os" in
  linux)
    out="$(ldd "$bin")"
    echo "$out"
    linux_ok <<<"$out"
    ;;
  macos)
    out="$(otool -L "$bin")"
    echo "$out"
    macos_ok <<<"$out"
    ;;
  windows)
    out="$(dll_names "$bin")"
    echo "imported/embedded DLL names (strings, grep -a):"
    echo "$out"
    windows_ok <<<"$out"
    ;;
  *)
    echo "unknown os: $os" >&2
    exit 2
    ;;
esac
echo "deps ($os): ok"
