#!/usr/bin/env bash
# Shared helpers for scripts/release/*.sh (sourced, not executed).

# hash_field LINE -> the hash of a `sha256sum`/`shasum` output line: the first field, without the leading
# backslash that GNU sha256sum puts in front of the line when the FILE NAME holds a backslash or a newline
# (Git Bash on Windows: `D:\a\_temp\x` gives `\<hash>  D:\\a\\_temp\\x`).
hash_field() {
  local out="$1"
  out="${out#\\}"
  printf '%s\n' "${out%% *}"
}

# sha256_of FILE -> 64 lowercase hex on stdout (sha256sum on Linux/Git Bash, shasum on macOS). The file is read from
# stdin, so its name never appears in the output (no escaping, review 19e A1); the hash field is cut by hash_field.
sha256_of() {
  local out
  if command -v sha256sum >/dev/null 2>&1; then
    out="$(sha256sum < "$1")"
  else
    out="$(shasum -a 256 < "$1")"
  fi
  hash_field "$out"
}

# size_of FILE -> size in bytes.
size_of() {
  wc -c < "$1" | tr -d '[:space:]'
}

# native_path PATH -> Windows form under Git Bash (cygpath), unchanged elsewhere.
native_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s\n' "$1"
  fi
}

# summary LINE... -> appends to $GITHUB_STEP_SUMMARY when running in Actions, else to stdout.
summary() {
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '%s\n' "$@" >> "$GITHUB_STEP_SUMMARY"
  fi
  printf '%s\n' "$@"
}

# gui_ext LABEL -> extension of the GUI release file of that target (stage 19g, Q5 b):
# ".exe" Windows, ".zip" macOS (Chervotochina.app inside), "" Linux. Unknown label: returns 1.
gui_ext() {
  case "$1" in
    linux-x86_64)               printf '\n' ;;
    macos-aarch64|macos-x86_64) printf '.zip\n' ;;
    windows-x86_64)             printf '.exe\n' ;;
    *) return 1 ;;
  esac
}
