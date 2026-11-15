#!/usr/bin/env bash
# Stage 19e-3 (SPEC 19e 3.3, 5.3 item 4; guard rule 8): the Inno Setup script is checked BY TEXT before ISCC runs.
#   bash scripts/release/check-iss.sh <iss>
#   bash scripts/release/check-iss.sh --self-test
# What must hold (the script is a closed form; anything else fails):
#   - starts with a UTF-8 BOM (SPEC 3.3; Inno also reads it without, Dopolnenie 1 p.3, we keep it);
#   - only the sections [Setup] [Languages] [Files] [Icons] [Run], each once; so no [Code], [Registry], [Dirs], [INI],
#     [InstallDelete], [UninstallDelete], [UninstallRun], [Tasks], [Types], [Components];
#   - every non-comment line of each section is one of the EXPECTED lines and every expected line is there (so:
#     PrivilegesRequired=lowest, no PrivilegesRequiredOverridesAllowed, DefaultDirName={autopf}\Chervotochina,
#     exactly 2 lines in [Files], 1 in [Icons], 1 in [Run]);
#   - AppId equals packaging/windows/APPID (never changes: updates in place depend on it);
#   - preprocessor lines: only `#ifndef <Define>`, `#endif`, `#error ...` for the four /D parameters; no #include;
#   - constants in braces only {app} {autopf} {autoprograms} {#AppVersion} {#SrcDir} {#TouchDate} {#TouchTime}
#     (so no {userappdata}, {localappdata}, {commonappdata}, {pf}, ...); no `http` except the two project URLs.
# Exit 0 = ok, 1 = a rule is broken (all are printed), 2 = usage.
set -euo pipefail
export LC_ALL=C

root="$(cd "$(dirname "$0")/../.." && pwd)"
HOMEPAGE=https://github.com/rekc2004/chervotochina

# expected_setup GUID -> the exact lines of [Setup] (one per line)
expected_setup() {
  cat <<EOF
AppId={{$1}
AppName=Червоточина
AppVersion={#AppVersion}
AppVerName=Червоточина {#AppVersion}
AppPublisher=Chervotochina
AppPublisherURL=$HOMEPAGE
AppSupportURL=$HOMEPAGE
DefaultDirName={autopf}\\Chervotochina
DisableDirPage=yes
DisableProgramGroupPage=yes
UsePreviousAppDir=yes
PrivilegesRequired=lowest
OutputBaseFilename=chervotochina-{#AppVersion}-windows-x86_64-setup
SetupIconFile={#SrcDir}\\chervotochina.ico
UninstallDisplayIcon={app}\\chervotochina.ico
UninstallDisplayName=Червоточина
Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
WizardStyle=modern
ShowLanguageDialog=no
SetupLogging=yes
CloseApplications=yes
RestartApplications=no
TimeStampsInUTC=yes
TouchDate={#TouchDate}
TouchTime={#TouchTime}
VersionInfoVersion={#AppVersion}.0
EOF
}

expected_languages() {
  printf '%s\n' 'Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"'
}
expected_files() {
  printf '%s\n' \
    'Source: "{#SrcDir}\chervotochina.exe"; DestDir: "{app}"; Flags: ignoreversion' \
    'Source: "{#SrcDir}\chervotochina.ico"; DestDir: "{app}"; Flags: ignoreversion'
}
expected_icons() {
  printf '%s\n' 'Name: "{autoprograms}\Червоточина"; Filename: "{app}\chervotochina.exe"; IconFilename: "{app}\chervotochina.ico"; WorkingDir: "{app}"'
}
expected_run() {
  printf '%s\n' 'Filename: "{app}\chervotochina.exe"; Description: "Запустить Червоточину"; Flags: nowait postinstall skipifsilent'
}

# check_iss FILE -> 0 / 1 (prints every problem)
check_iss() {
  local f="$1" bad=0 line t n=0 sect="" guid sec lineno=0
  local -A seen=() lines=()
  local sections_ok=" Setup Languages Files Icons Run "
  [[ -f "$f" ]] || { echo "check-iss: no such file: $f" >&2; return 1; }
  if [[ "$(head -c 3 "$f" | od -An -tx1 | tr -d ' \n')" != efbbbf ]]; then
    echo "check-iss: the file does not start with a UTF-8 BOM" >&2; bad=1
  fi
  guid="$(tr -d '\r\n' < "$root/packaging/windows/APPID" 2>/dev/null || true)"
  if ! [[ "$guid" =~ ^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$ ]]; then
    echo "check-iss: packaging/windows/APPID is missing or is not an upper-case GUID" >&2; return 1
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    line="${line%$'\r'}"
    [[ $lineno -eq 1 ]] && line="${line#$'\xEF\xBB\xBF'}"
    t="${line#"${line%%[![:space:]]*}"}"
    t="${t%"${t##*[![:space:]]}"}"
    if [[ "$t" == \;* ]]; then
      # a comment line runs nothing in Inno, but ISPP expands inline `{#...}` in it too: no inline constructs
      # (review 19e B5, Low).
      if [[ "$t" == *'{#'* ]]; then
        echo "check-iss: line $lineno: ISPP inline construct {# in a comment: $t" >&2; bad=1
      fi
      continue
    fi
    [[ -z "$t" ]] && continue
    if [[ "$t" == '#'* ]]; then
      case "$t" in
        '#ifndef AppVersion'|'#ifndef SrcDir'|'#ifndef TouchDate'|'#ifndef TouchTime'|'#endif') ;;
        '#error '*) [[ "$t" != *'{'* ]] || { echo "check-iss: line $lineno: braces in #error" >&2; bad=1; } ;;
        *) echo "check-iss: line $lineno: preprocessor directive not allowed: $t" >&2; bad=1 ;;
      esac
      continue
    fi
    # global rules on every effective line
    local stripped="${t//\{\{/}"
    local tok
    while [[ "$stripped" =~ \{([^{}]*)\} ]]; do
      tok="{${BASH_REMATCH[1]}}"
      case "$tok" in
        '{app}'|'{autopf}'|'{autoprograms}'|'{#AppVersion}'|'{#SrcDir}'|'{#TouchDate}'|'{#TouchTime}') ;;
        *) echo "check-iss: line $lineno: constant $tok is not allowed" >&2; bad=1 ;;
      esac
      stripped="${stripped/"$tok"/}"
    done
    if [[ "${t//$HOMEPAGE/}" == *[Hh][Tt][Tt][Pp]* ]]; then
      echo "check-iss: line $lineno: 'http' only as the project address $HOMEPAGE: $t" >&2; bad=1
    fi
    case "$t" in
      *'#include'*|*[Ll]ocalappdata*|*[Uu]serappdata*|*PrivilegesRequiredOverridesAllowed*)
        echo "check-iss: line $lineno: forbidden text: $t" >&2; bad=1 ;;
    esac
    if [[ "$t" =~ ^\[([A-Za-z]+)\]$ ]]; then
      sect="${BASH_REMATCH[1]}"
      if [[ "$sections_ok" != *" $sect "* ]]; then
        echo "check-iss: line $lineno: section [$sect] is not allowed" >&2; bad=1
      elif [[ -n "${seen[$sect]:-}" ]]; then
        echo "check-iss: line $lineno: section [$sect] twice" >&2; bad=1
      fi
      seen[$sect]=1
      continue
    fi
    if [[ -z "$sect" ]]; then
      echo "check-iss: line $lineno: text before the first section: $t" >&2; bad=1; continue
    fi
    lines[$sect]+="$t"$'\n'
    n=$((n + 1))
  done < "$f"
  for sec in Setup Languages Files Icons Run; do
    [[ -n "${seen[$sec]:-}" ]] || { echo "check-iss: section [$sec] is missing" >&2; bad=1; }
    local want got
    case "$sec" in
      Setup) want="$(expected_setup "$guid")" ;;
      Languages) want="$(expected_languages)" ;;
      Files) want="$(expected_files)" ;;
      Icons) want="$(expected_icons)" ;;
      Run) want="$(expected_run)" ;;
    esac
    got="${lines[$sec]:-}"
    got="${got%$'\n'}"
    if [[ "$(LC_ALL=C sort <<<"$got")" != "$(LC_ALL=C sort <<<"$want")" ]]; then
      echo "check-iss: [$sec] differs from the expected form of SPEC 19e 3.3. Lines that are not expected or are missing:" >&2
      diff <(LC_ALL=C sort <<<"$got") <(LC_ALL=C sort <<<"$want") | sed 's/^/    /' >&2 || true
      bad=1
    fi
  done
  return "$bad"
}

self_test() {
  local tmp iss fail=0 f
  iss="$root/packaging/windows/chervotochina.iss"
  [[ -f "$iss" ]] || { echo "self-test: FAILED (no $iss)" >&2; return 1; }
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  expect() { # name want-rc file
    local rc=0
    check_iss "$3" >/dev/null 2>&1 || rc=$?
    [[ "$rc" == "$2" ]] || { echo "self-test: FAILED ($1: rc=$rc, expected $2)" >&2; fail=1; }
  }
  expect real-file 0 "$iss"
  # review 19e A3: the file on disk is CRLF (.gitattributes `*.iss eol=crlf`) on one OS and LF on another. The sed
  # mutations below work on an LF copy that KEEPS the BOM, so they behave the same everywhere; the checker itself
  # is tested on both LF and CRLF forms.
  tr -d '\r' < "$iss" > "$tmp/base.iss"
  [[ "$(head -c 3 "$tmp/base.iss" | od -An -tx1 | tr -d ' \n')" == efbbbf ]] || { echo "self-test: FAILED (the LF copy lost the BOM)" >&2; fail=1; }
  iss="$tmp/base.iss"
  expect lf-ok 0 "$iss"
  # CRLF line endings are fine (git checks the file out with CRLF on Windows)
  sed 's/$/\r/' "$iss" > "$tmp/crlf.iss"; expect crlf-ok 0 "$tmp/crlf.iss"
  # mutate NAME SED-EXPRESSION: a copy of the real file with one change must be rejected
  mutate() {
    sed "$2" "$iss" > "$tmp/m.iss"
    if cmp -s "$iss" "$tmp/m.iss"; then echo "self-test: FAILED ($1: the mutation changed nothing)" >&2; fail=1; return; fi
    expect "$1" 1 "$tmp/m.iss"
  }
  append() { { cat "$iss"; printf '%s\n' "${@:2}"; } > "$tmp/a.iss"; expect "$1" 1 "$tmp/a.iss"; }
  append comment-inline-ispp '; {#emit "x"}'
  mutate comment-inline-ispp-first-line '2s/^;/; {#SrcDir}/'
  append section-code '' '[Code]' 'function InitializeSetup(): Boolean;'
  append section-uninstalldelete '' '[UninstallDelete]' 'Type: filesandordirs; Name: "{app}"'
  append section-registry '' '[Registry]' 'Root: HKCU; Subkey: "Software\X"'
  append section-installdelete '' '[InstallDelete]' 'Type: files; Name: "{app}\x"'
  append section-tasks '' '[Tasks]' 'Name: "desktopicon"; Description: "x"'
  append section-dirs '' '[Dirs]' 'Name: "{app}\x"'
  append section-twice '' '[Run]' 'Filename: "{app}\chervotochina.exe"; Description: "Запустить Червоточину"; Flags: nowait postinstall skipifsilent'
  mutate privileges-admin 's/^PrivilegesRequired=lowest$/PrivilegesRequired=admin/'
  mutate privileges-poweruser 's/^PrivilegesRequired=lowest$/PrivilegesRequired=poweruser/'
  mutate privileges-missing '/^PrivilegesRequired=lowest$/d'
  mutate overrides-dialog 's/^PrivilegesRequired=lowest$/PrivilegesRequired=lowest\nPrivilegesRequiredOverridesAllowed=dialog/'
  mutate other-appid 's/^AppId={{[0-9A-F-]*}/AppId={{00000000-0000-0000-0000-000000000000}/'
  mutate appid-no-escape 's/^AppId={{/AppId={/'
  mutate dir-localappdata 's/^DefaultDirName=.*/DefaultDirName={localappdata}\\Chervotochina/'
  mutate dir-programfiles 's/^DefaultDirName=.*/DefaultDirName={pf}\\Chervotochina/'
  mutate dir-userappdata 's/^DefaultDirName=.*/DefaultDirName={userappdata}\\Chervotochina/'
  mutate dir-prompt 's/^DisableDirPage=yes$/DisableDirPage=no/'
  mutate include '1,/^\[Setup\]$/s/^#ifndef AppVersion$/#include "other.iss"/'
  mutate define '1,/^\[Setup\]$/s/^#ifndef AppVersion$/#define AppVersion "9.9.9"/'
  mutate third-files-line '/chervotochina.ico"; DestDir/a Source: "{#SrcDir}\\extra.dll"; DestDir: "{app}"; Flags: ignoreversion'
  mutate files-line-removed '/chervotochina.ico"; DestDir/d'
  mutate icons-desktop-added '/^Name: "{autoprograms}/a Name: "{autodesktop}\\Червоточина"; Filename: "{app}\\chervotochina.exe"'
  mutate run-http 's#^Filename: "{app}\\chervotochina.exe"; Description: "Запустить Червоточину"#Filename: "https://example.invalid/x.exe"; Description: "Запустить Червоточину"#'
  mutate http-in-url 's#^AppSupportURL=.*#AppSupportURL=http://example.invalid/#'
  mutate other-https-url 's#^AppPublisherURL=.*#AppPublisherURL=https://example.invalid/#'
  mutate run-flags-no-skipifsilent 's/ skipifsilent//'
  mutate extra-setup-directive 's/^SetupLogging=yes$/SetupLogging=yes\nUninstallable=no/'
  mutate language-added 's/^Name: "ru"; MessagesFile: "compiler:Languages\\Russian.isl"$/&\nName: "en"; MessagesFile: "compiler:Default.isl"/'
  mutate tasks-flag 's/Flags: ignoreversion/Flags: ignoreversion restartreplace/'
  mutate unknown-constant 's/^UninstallDisplayIcon={app}/UninstallDisplayIcon={sys}/'
  # no BOM
  tail -c +4 "$iss" > "$tmp/nobom.iss"; expect no-bom 1 "$tmp/nobom.iss"
  # a missing file
  expect no-file 1 "$tmp/nosuch.iss"
  [[ $fail -eq 0 ]] && echo "self-test: ok"
  return "$fail"
}

if [[ "${1:-}" == "--self-test" ]]; then
  rc=0
  self_test || rc=$?
  exit "$rc"
fi
if [[ $# -ne 1 ]]; then
  echo "usage: check-iss.sh <iss> | --self-test" >&2
  exit 2
fi
if check_iss "$1"; then
  echo "check-iss: ok ($1)"
else
  echo "check-iss: FAILED ($1)" >&2
  exit 1
fi
