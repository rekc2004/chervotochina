#!/usr/bin/env bash
# Stage 19e-2 (SPEC 19e, sections 4 and 5.2): the ONLY place where CI downloads a build tool.
#   bash scripts/release/fetch-tool.sh <name> <new-empty-dir>   download + verify, never run
#   bash scripts/release/fetch-tool.sh --get <name> <field>     print a field of packaging/tools.lock
#                                                               (version|url|sha256|size|signer|file)
#   bash scripts/release/fetch-tool.sh --self-test              no network
# The tool, its URL, SHA-256 and size come from packaging/tools.lock (strict parser, exit 2 on any
# deviation). The file is fetched over https only (no downgrade on redirects), then SIZE and SHA-256 are
# checked BEFORE anything else happens with it. On a mismatch the file is deleted, the expected and the
# actual values are printed, exit 1. The file never gets an execute bit and is never started here:
# the next workflow step checks the Authenticode signature and runs it (the downloaded file is
# hostile until the checks pass). Exit codes: 0 ok, 1 verification/usage-of-dir failure, 2 bad input.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=lib.sh
. "$root/scripts/release/lib.sh"

lock_file="$root/packaging/tools.lock"

# parse_lock FILE NAME -> sets L_VERSION L_URL L_SHA L_SIZE L_SIGNER (with "_" turned back into a space)
# and L_FILE (last URL segment). Returns 0, or 2 (message on stderr) on a missing/duplicate name or on
# ANY malformed line of the file (not only the requested one).
parse_lock() {
  local f="$1" want="$2" line n=0 found=0 fld name
  local -a F
  [[ -f "$f" ]] || { echo "fetch-tool: no lock file: $f" >&2; return 2; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n + 1))
    if [[ "$line" == '#'* ]] || [[ -z "${line//[[:space:]]/}" ]]; then
      continue
    fi
    if [[ "$line" == *$'\r'* || "$line" == *$'\t'* || "$line" == *'  '* || "$line" == ' '* || "$line" == *' ' ]]; then
      echo "fetch-tool: $f:$n: only single spaces, no tabs, no CR, no leading/trailing space" >&2; return 2
    fi
    IFS=' ' read -r -a F <<<"$line"
    if [[ "${#F[@]}" -ne 7 ]]; then
      echo "fetch-tool: $f:$n: expected 7 fields, got ${#F[@]}" >&2; return 2
    fi
    [[ "${F[0]}" == tool ]] || { echo "fetch-tool: $f:$n: line does not start with 'tool'" >&2; return 2; }
    name="${F[1]}"
    [[ "$name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || { echo "fetch-tool: $f:$n: bad name" >&2; return 2; }
    [[ "${F[2]}" =~ ^[0-9]+(\.[0-9]+)*$ ]] || { echo "fetch-tool: $f:$n: bad version" >&2; return 2; }
    # https only; a host, an optional port and a path; no userinfo, query or fragment; last segment is a plain file name
    [[ "${F[3]}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._~/%+-]+$ ]] ||
      { echo "fetch-tool: $f:$n: the URL must be https://host/path (no http, userinfo, query)" >&2; return 2; }
    fld="${F[3]##*/}"
    [[ "$fld" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { echo "fetch-tool: $f:$n: bad file name in the URL" >&2; return 2; }
    [[ "${F[4]}" =~ ^[0-9a-f]{64}$ ]] || { echo "fetch-tool: $f:$n: sha256 must be 64 lowercase hex" >&2; return 2; }
    [[ "${F[5]}" =~ ^[1-9][0-9]{0,9}$ ]] || { echo "fetch-tool: $f:$n: bad size" >&2; return 2; }
    [[ "${F[6]}" =~ ^[A-Za-z0-9._=,-]+$ ]] || { echo "fetch-tool: $f:$n: bad signer (no spaces: use _)" >&2; return 2; }
    if [[ "$name" == "$want" ]]; then
      found=$((found + 1))
      L_VERSION="${F[2]}"; L_URL="${F[3]}"; L_SHA="${F[4]}"; L_SIZE="${F[5]}"
      L_SIGNER="${F[6]//_/ }"; L_FILE="$fld"
    fi
  done < "$f"
  [[ "$found" -eq 1 ]] || { echo "fetch-tool: '$want' must be on exactly one line of $f (found $found)" >&2; return 2; }
  return 0
}

# verify_file FILE EXPECTED_SHA256 EXPECTED_SIZE -> 0 if both match; otherwise prints expected/actual,
# DELETES the file and returns 1. Nothing is executed or chmod-ed.
verify_file() {
  local file="$1" want_sha="$2" want_size="$3" got_sha got_size
  [[ -f "$file" && ! -L "$file" ]] || { echo "fetch-tool: not a regular file: $file" >&2; rm -f -- "$file"; return 1; }
  got_size="$(size_of "$file")"
  got_sha="$(sha256_of "$file")"
  if [[ "$got_size" != "$want_size" || "$got_sha" != "$want_sha" ]]; then
    {
      echo "fetch-tool: VERIFICATION FAILED, the file is deleted"
      echo "  expected sha256: $want_sha"
      echo "  actual   sha256: $got_sha"
      echo "  expected size:   $want_size"
      echo "  actual   size:   $got_size"
    } >&2
    rm -f -- "$file"
    return 1
  fi
  return 0
}

# check_new_dir DIR -> 0 if DIR does not exist or is an empty real directory; else 1.
check_new_dir() {
  local d="$1"
  if [[ -L "$d" ]]; then echo "fetch-tool: not a plain directory (symlink): $d" >&2; return 1; fi
  if [[ ! -e "$d" ]]; then return 0; fi
  if [[ ! -d "$d" ]]; then echo "fetch-tool: not a directory: $d" >&2; return 1; fi
  if [[ -n "$(ls -A -- "$d")" ]]; then echo "fetch-tool: directory is not empty: $d" >&2; return 1; fi
  return 0
}

self_test() {
  local tmp fail=0 good_sha good_size
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  expect() { # name expected-rc command...
    local name="$1" want="$2" rc=0
    shift 2
    "$@" >/dev/null 2>&1 || rc=$?
    [[ "$rc" == "$want" ]] || { echo "self-test: FAILED ($name: rc=$rc, expected $want)" >&2; fail=1; }
  }
  local sha64 url size
  sha64=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  url=https://example.invalid/dl/tool-1.0.exe
  size=1234
  mk() { printf '%s\n' "$2" > "$tmp/$1"; } # name line
  mk good.lock "tool t1 1.0 $url $sha64 $size CN=A_B,_O=A_B"
  expect parse-ok 0 parse_lock "$tmp/good.lock" t1
  # the parsed values: file name from the URL, signer with spaces restored
  ( parse_lock "$tmp/good.lock" t1; [[ "$L_FILE" == tool-1.0.exe && "$L_SIGNER" == 'CN=A B, O=A B' && "$L_SIZE" == 1234 && "$L_VERSION" == 1.0 ]] ) ||
    { echo "self-test: FAILED (parsed values)" >&2; fail=1; }
  expect name-missing 2 parse_lock "$tmp/good.lock" t2
  expect no-file 2 parse_lock "$tmp/nosuch.lock" t1
  { cat "$tmp/good.lock"; echo "# comment"; echo; } > "$tmp/c.lock"
  expect comments-and-blank-ok 0 parse_lock "$tmp/c.lock" t1
  { cat "$tmp/good.lock"; cat "$tmp/good.lock"; } > "$tmp/d.lock"
  expect duplicate-name 2 parse_lock "$tmp/d.lock" t1
  { cat "$tmp/good.lock"; echo "tool t3 1.0 http://example.invalid/x $sha64 $size S"; } > "$tmp/o.lock"
  expect bad-line-for-other-tool 2 parse_lock "$tmp/o.lock" t1
  local bad
  for bad in \
    "tool t1 1.0 $url $sha64 $size CN=A extra" \
    "tool t1 1.0 $url $sha64 $size" \
    "tool t1 1.0 http://example.invalid/dl/tool.exe $sha64 $size S" \
    "tool t1 1.0 ftp://example.invalid/dl/tool.exe $sha64 $size S" \
    "tool t1 1.0 https://user@example.invalid/dl/tool.exe $sha64 $size S" \
    "tool t1 1.0 https://example.invalid/dl/tool.exe?x=1 $sha64 $size S" \
    "tool t1 1.0 https://example.invalid/dl/tool.exe#x $sha64 $size S" \
    "tool t1 1.0 https://example.invalid/dl/.. $sha64 $size S" \
    "tool t1 1.0 https://example.invalid/dl/ $sha64 $size S" \
    "tool t1 1.0 $url ${sha64%a} $size S" \
    "tool t1 1.0 $url ${sha64}a $size S" \
    "tool t1 1.0 $url ${sha64^^} $size S" \
    "tool t1 1.0 $url ${sha64%a}g $size S" \
    "tool t1 1.0 $url $sha64 0 S" \
    "tool t1 1.0 $url $sha64 12x S" \
    "tool t1 1.0 $url $sha64 -5 S" \
    "tool t1 1.0 $url $sha64 12345678901 S" \
    "tool t1 1.0 $url $sha64 $size CN=A B" \
    "tool t1 1.0 $url $sha64 $size 'S;rm'" \
    "tool t1 v1 $url $sha64 $size S" \
    "tool T1 1.0 $url $sha64 $size S" \
    "tools t1 1.0 $url $sha64 $size S" \
    "tool  t1 1.0 $url $sha64 $size S" \
    " tool t1 1.0 $url $sha64 $size S" \
    "tool t1 1.0 $url $sha64 $size S " \
    "$(printf 'tool\tt1 1.0 %s %s %s S' "$url" "$sha64" "$size")" \
    "$(printf 'tool t1 1.0 %s %s %s S\r' "$url" "$sha64" "$size")"; do
    mk b.lock "$bad"
    expect "bad-line[$bad]" 2 parse_lock "$tmp/b.lock" t1
  done
  # the real lock file parses, one inno-setup line, https
  expect real-lock-inno-setup 0 parse_lock "$lock_file" inno-setup
  ( parse_lock "$lock_file" inno-setup; [[ "$L_URL" == https://* && "$L_SHA" =~ ^[0-9a-f]{64}$ ]] ) ||
    { echo "self-test: FAILED (real lock: inno-setup fields)" >&2; fail=1; }

  # verification of local files
  printf 'hello tool' > "$tmp/ok.bin"
  good_sha="$(sha256_of "$tmp/ok.bin")"
  good_size="$(size_of "$tmp/ok.bin")"
  expect verify-ok 0 verify_file "$tmp/ok.bin" "$good_sha" "$good_size"
  [[ -f "$tmp/ok.bin" ]] || { echo "self-test: FAILED (a good file was removed)" >&2; fail=1; }
  [[ ! -x "$tmp/ok.bin" || "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]] || { echo "self-test: FAILED (file became executable)" >&2; fail=1; }
  printf 'hello tool' > "$tmp/w1.bin"
  expect verify-wrong-hash 1 verify_file "$tmp/w1.bin" "$sha64" "$good_size"
  [[ ! -e "$tmp/w1.bin" ]] || { echo "self-test: FAILED (file with a wrong hash was not deleted)" >&2; fail=1; }
  printf 'hello tool' > "$tmp/w2.bin"
  expect verify-wrong-size 1 verify_file "$tmp/w2.bin" "$good_sha" $((good_size + 1))
  [[ ! -e "$tmp/w2.bin" ]] || { echo "self-test: FAILED (file with a wrong size was not deleted)" >&2; fail=1; }
  printf 'hello tool!' > "$tmp/w3.bin"
  expect verify-changed-content 1 verify_file "$tmp/w3.bin" "$good_sha" "$good_size"
  expect verify-missing-file 1 verify_file "$tmp/nosuch.bin" "$good_sha" "$good_size"
  # the message names expected and actual values
  printf 'x' > "$tmp/w4.bin"
  local msg
  msg="$(verify_file "$tmp/w4.bin" "$sha64" 1 2>&1 || true)"
  [[ "$msg" == *"expected sha256: $sha64"* && "$msg" == *"actual   sha256: "* && "$msg" == *"actual   size:"* ]] ||
    { echo "self-test: FAILED (the failure message lacks expected/actual values)" >&2; fail=1; }

  # review 19e A1: sha256sum puts a backslash in front of the line when the file name holds a backslash
  # (Git Bash on Windows). The hash must not depend on the name.
  [[ "$(hash_field "\\$good_sha  D:\\\\a\\\\_temp/x.bin")" == "$good_sha" ]] || { echo "self-test: FAILED (hash_field with a leading backslash)" >&2; fail=1; }
  [[ "$(hash_field "$good_sha  x.bin")" == "$good_sha" ]] || { echo "self-test: FAILED (hash_field plain line)" >&2; fail=1; }
  [[ "$(hash_field "$good_sha *x.bin")" == "$good_sha" ]] || { echo "self-test: FAILED (hash_field binary-mode line)" >&2; fail=1; }
  printf 'hello tool' > "$tmp/plain.bin"
  # Windows form of the path (D:\a\_temp\...), as in the CI failure: exists only under Git Bash (cygpath)
  if command -v cygpath >/dev/null 2>&1; then
    local winp
    winp="$(cygpath -w "$tmp/plain.bin")"
    [[ "$(sha256_of "$winp")" == "$good_sha" ]] || { echo "self-test: FAILED (sha256_of of a Windows path with backslashes)" >&2; fail=1; }
    printf 'hello tool' > "$tmp/win.bin"
    expect verify-windows-path 0 verify_file "$(cygpath -w "$tmp/win.bin")" "$good_sha" "$good_size"
  fi
  # a real file name with a backslash or a newline (Linux only: on Windows the shell cannot create them)
  if { printf 'hello tool' > "$tmp/with\\back.bin"; } 2>/dev/null && [[ -f "$tmp/with\\back.bin" ]]; then
    [[ "$(sha256_of "$tmp/with\\back.bin")" == "$good_sha" ]] || { echo "self-test: FAILED (sha256_of of a file name with a backslash)" >&2; fail=1; }
    expect verify-name-with-backslash 0 verify_file "$tmp/with\\back.bin" "$good_sha" "$good_size"
  fi
  if { printf 'hello tool' > "$tmp/nl"$'\n'"x.bin"; } 2>/dev/null && [[ -f "$tmp/nl"$'\n'"x.bin" ]]; then
    [[ "$(sha256_of "$tmp/nl"$'\n'"x.bin")" == "$good_sha" ]] || { echo "self-test: FAILED (sha256_of of a file name with a newline)" >&2; fail=1; }
  fi

  # target directory: absent or empty only
  expect dir-absent 0 check_new_dir "$tmp/newdir"
  mkdir "$tmp/empty"; expect dir-empty 0 check_new_dir "$tmp/empty"
  mkdir "$tmp/full"; : > "$tmp/full/x"; expect dir-not-empty 1 check_new_dir "$tmp/full"
  expect dir-is-file 1 check_new_dir "$tmp/ok.bin"

  [[ $fail -eq 0 ]] && echo "self-test: ok"
  return "$fail"
}

if [[ "${1:-}" == "--self-test" ]]; then
  rc=0
  self_test || rc=$?
  exit "$rc"
fi

if [[ "${1:-}" == "--get" ]]; then
  [[ $# -eq 3 ]] || { echo "usage: fetch-tool.sh --get <name> <version|url|sha256|size|signer|file>" >&2; exit 2; }
  rc=0
  parse_lock "$lock_file" "$2" || rc=$?
  [[ "$rc" -eq 0 ]] || exit "$rc"
  case "$3" in
    version) printf '%s\n' "$L_VERSION" ;;
    url)     printf '%s\n' "$L_URL" ;;
    sha256)  printf '%s\n' "$L_SHA" ;;
    size)    printf '%s\n' "$L_SIZE" ;;
    signer)  printf '%s\n' "$L_SIGNER" ;;
    file)    printf '%s\n' "$L_FILE" ;;
    *) echo "fetch-tool: unknown field '$3'" >&2; exit 2 ;;
  esac
  exit "$rc"
fi

if [[ $# -ne 2 ]]; then
  echo "usage: fetch-tool.sh <name> <new-empty-dir> | --get <name> <field> | --self-test" >&2
  exit 2
fi
name="$1"; dir="$2"
rc=0
parse_lock "$lock_file" "$name" || rc=$?
[[ "$rc" -eq 0 ]] || exit "$rc"
check_new_dir "$dir" || exit 1
mkdir -p -- "$dir"
dest="$dir/$L_FILE"

# https only, also after redirects; TLS 1.2+; no .curlrc (-q must be the first argument); bounded in size and time.
curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --max-redirs 5 \
  --connect-timeout 30 --max-time 900 --max-filesize "$L_SIZE" -o "$dest" -- "$L_URL" || {
  echo "fetch-tool: download failed: $L_URL" >&2
  rm -f -- "$dest"
  exit 1
}
# Size and SHA-256 BEFORE anything else; on a mismatch the file is deleted and we stop here.
verify_file "$dest" "$L_SHA" "$L_SIZE" || exit 1
echo "tool=$name"
echo "version=$L_VERSION"
echo "file=$dest"
echo "sha256=$L_SHA"
echo "size=$L_SIZE"
echo "signer=$L_SIGNER"
echo "fetch-tool: verified (size and sha256 match packaging/tools.lock); NOT executed, no execute bit"
