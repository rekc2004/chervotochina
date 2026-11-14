#!/usr/bin/env bash
# Stage 19e-3 (SPEC 19e 5.3 item 8): smoke test of the .deb (the built file, not a rebuild). Ubuntu runner only (sudo, apt).
#   bash scripts/release/smoke-deb.sh <release-dir>
# FIRST step: the SHA-256 of the .deb must equal the manifest line of its target (linux-x86_64), otherwise it is NOT
# installed. Then: apt installs the CI set for the window and desktop-file-utils (CI only), a snapshot of the packages
# (before), `apt-get install ./deb` with the DEFAULT settings (Recommends included: the package has none), a snapshot
# (after): exactly one package added, `chervotochina`; the installed /usr/bin files equal the manifest lines of the
# single files; desktop-file-validate; `chervo --version`; `--render-check` under xvfb; a sentinel in the user data
# directory; `apt-get remove` and `dpkg --purge`; everything gone, the package list equals the first snapshot, the
# sentinel is in place byte for byte. Needs passwordless sudo (as on GitHub runners). Not for the machines of the owner.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: smoke-deb.sh <release-dir>" >&2
  exit 2
fi
rel="$1"
root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=lib.sh
. "$root/scripts/release/lib.sh"
APP_ID=io.github.rekc2004.chervotochina

fail=0
bad() { summary "- FAIL: $*"; fail=1; }
good() { summary "- ok: $*"; }
finish() { summary ""; exit "$fail"; }

manifest="$rel/chervo-release.txt"
[[ -f "$manifest" ]] || { echo "no manifest: $manifest" >&2; exit 1; }
ver="$(awk '$1 == "version" { print $2; exit }' "$manifest" | tr -d '\r')"
[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "bad version in the manifest: $ver" >&2; exit 1; }
deb_name="chervotochina-$ver-linux-x86_64.deb"
deb="$rel/$deb_name"
[[ -f "$deb" && ! -L "$deb" ]] || { echo "no release file: $deb" >&2; exit 1; }

# manifest_sha NAME -> the SHA-256 of the line of target linux-x86_64 with this file name
manifest_sha() {
  awk -v n="$1" '$1 == "artifact" && $2 == "linux-x86_64" && $5 == n { print $3 }' "$manifest" | tr -d '\r'
}

summary "### smoke-deb: $(. /etc/os-release && echo "$PRETTY_NAME") (file \`$deb_name\`)"
want="$(manifest_sha "$deb_name")"
have="$(sha256_of "$deb")"
summary "- manifest sha256: \`${want:-<none>}\`" "- file sha256:     \`$have\`"
if [[ -z "$want" || "$want" != "$have" ]]; then
  bad "SHA-256 of the .deb differs from the manifest line (or the line is missing); the package is NOT installed"
  finish
fi
good "SHA-256 of the .deb equals the manifest line"
want_gui="$(manifest_sha "chervotochina-$ver-linux-x86_64")"
want_cli="$(manifest_sha "chervo-$ver-linux-x86_64")"
[[ -n "$want_gui" && -n "$want_cli" ]] || { bad "the manifest lacks the lines of the single files"; finish; }

# 1. CI set for the window and desktop-file-utils (CI only; the package does not need them)
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends xvfb mesa-vulkan-drivers libgl1-mesa-dri libegl1 libvulkan1 libx11-6 libxcursor1 libxrandr2 libxi6 libxkbcommon-x11-0 desktop-file-utils >/dev/null

# 2. snapshot before; apt settings that matter
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
dpkg-query -W -f='${Package}\n' | LC_ALL=C sort > "$work/before"
summary "- apt install settings (apt-config dump | grep -i Install-):" '```' "$(apt-config dump | grep -i 'Install-' || true)" '```'
summary "- packages before: $(grep -c . "$work/before")"
test ! -e /usr/bin/chervotochina && test ! -e /usr/bin/chervo || { bad "files of the package exist before the installation"; finish; }

# 3. install with the DEFAULT settings
sudo apt-get install -y "./$deb" > "$work/install.log" 2>&1 || { tail -n 40 "$work/install.log"; bad "apt-get install failed"; finish; }
summary "- apt-get install log (tail):" '```' "$(tail -n 25 "$work/install.log")" '```'

# 4. snapshot after: exactly one package added
dpkg-query -W -f='${Package}\n' | LC_ALL=C sort > "$work/after"
added="$(comm -13 "$work/before" "$work/after" | tr '\n' ' ')"
removed="$(comm -23 "$work/before" "$work/after" | tr '\n' ' ')"
summary "- packages after: $(grep -c . "$work/after"); added: ${added:-none}; removed: ${removed:-none}"
if [[ "$added" == 'chervotochina ' && -z "$removed" ]]; then good "exactly one package was added: chervotochina"; else bad "expected exactly 'chervotochina' to be added (added: $added, removed: $removed)"; fi

# 5. the installed files equal the manifest lines of the single files
g="$(sha256_of /usr/bin/chervotochina)"; c="$(sha256_of /usr/bin/chervo)"
summary "- /usr/bin/chervotochina: \`$g\` (manifest \`$want_gui\`)" "- /usr/bin/chervo: \`$c\` (manifest \`$want_cli\`)"
if [[ "$g" == "$want_gui" ]]; then good "/usr/bin/chervotochina equals the single file of the manifest"; else bad "/usr/bin/chervotochina differs from the manifest line"; fi
if [[ "$c" == "$want_cli" ]]; then good "/usr/bin/chervo equals the single file of the manifest"; else bad "/usr/bin/chervo differs from the manifest line"; fi

# 6. .desktop, --version, --render-check
if desktop-file-validate "/usr/share/applications/$APP_ID.desktop"; then good "desktop-file-validate"; else bad "desktop-file-validate failed"; fi
out="$(/usr/bin/chervo --version 2>&1 || true)"
summary "- chervo --version: \`$out\`"
if [[ "$out" == *"$ver"* ]]; then good "chervo --version contains $ver"; else bad "chervo --version does not contain $ver"; fi
RC=0
timeout 120 xvfb-run -a /usr/bin/chervotochina --render-check || RC=$?
summary "- \`--render-check\` rc=$RC"
if [[ $RC -eq 0 ]]; then good "--render-check: rc 0"; else bad "--render-check: expected rc 0"; fi

# 7. a sentinel in the user data directory
data="${XDG_DATA_HOME:-$HOME/.local/share}/chervotochina"
mkdir -p "$data"
head -c 64 /dev/urandom > "$data/sentinel-19e"
sentinel_sha="$(sha256_of "$data/sentinel-19e")"

# 8. remove, then purge
sudo apt-get remove -y chervotochina > "$work/remove.log" 2>&1 || { tail -n 40 "$work/remove.log"; bad "apt-get remove failed"; }
sudo dpkg --purge chervotochina > "$work/purge.log" 2>&1 || { tail -n 40 "$work/purge.log"; bad "dpkg --purge failed"; }
summary "- remove and purge log (tail):" '```' "$(tail -n 8 "$work/remove.log") $(tail -n 4 "$work/purge.log")" '```'

# 9. everything is gone, the user data is not
for f in /usr/bin/chervotochina /usr/bin/chervo "/usr/share/applications/$APP_ID.desktop" /usr/share/doc/chervotochina; do
  if [[ -e "$f" ]]; then bad "$f is still there after the removal"; fi
done
icons="$(find /usr/share/icons -name "$APP_ID.png" 2>/dev/null | head -n 3)"
if [[ -n "$icons" ]]; then bad "icons are still there: $icons"; else good "no binaries, .desktop file or icons after the removal"; fi
if dpkg -s chervotochina >/dev/null 2>&1; then bad "dpkg -s still finds the package"; else good "dpkg -s: the package is not installed"; fi
dpkg-query -W -f='${Package}\n' | LC_ALL=C sort > "$work/final"
if cmp -s "$work/before" "$work/final"; then good "the package list equals the first snapshot"; else bad "the package list differs from the first snapshot: $(diff "$work/before" "$work/final" | head -n 10 | tr '\n' ' ')"; fi
if [[ -f "$data/sentinel-19e" && "$(sha256_of "$data/sentinel-19e")" == "$sentinel_sha" ]]; then good "the user data sentinel is in place, same bytes"; else bad "the user data sentinel is gone or changed"; fi
rm -f "$data/sentinel-19e"
finish
