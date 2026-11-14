#!/usr/bin/env bash
# Stage 19e-3 (SPEC 19e 3.4, 5.3 item 6): checks a built .dmg by what is IN it. macOS only (hdiutil, ditto, codesign).
#   bash scripts/release/check-dmg.sh <dmg> <zip>
# Mounts the image read-only (-nobrowse -noautoopen, own mount point), ALWAYS detaches (trap). Nothing from the image
# is run. Checks: the visible root is exactly `Chervotochina.app` and `Applications`; `Applications` is a symbolic link
# with the target exactly /Applications; hidden service items made by the system (.fseventsd, .Trashes, ...) are
# allowed and printed; no symbolic link inside the .app; the file list and every file of the .app equal the .app from
# the .zip of the same target (`ditto -x -k` into a new empty directory), byte for byte (cmp); `codesign --verify --strict`
# on the mounted .app. Exit 0 = ok, 1 = something is wrong (all problems printed), 2 = usage.
# Written for bash 3.2 (macOS). [not verified on a macOS runner: attach/detach flags are from the man page]
set -euo pipefail
export LC_ALL=C

root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=lib.sh
. "$root/scripts/release/lib.sh"

if [[ $# -ne 2 ]]; then
  echo "usage: check-dmg.sh <dmg> <zip>" >&2
  exit 2
fi
dmg="$1"; zip="$2"
[[ -f "$dmg" && ! -L "$dmg" ]] || { echo "check-dmg: no such file: $dmg" >&2; exit 1; }
[[ -f "$zip" && ! -L "$zip" ]] || { echo "check-dmg: no such file: $zip" >&2; exit 1; }
for tool in hdiutil ditto codesign cmp find; do
  command -v "$tool" >/dev/null 2>&1 || { echo "check-dmg: '$tool' is not available (macOS only)" >&2; exit 1; }
done

bad=0
err() { echo "check-dmg: $*" >&2; bad=1; }

tmp="$(mktemp -d)"
mnt="$tmp/mnt"
attached=no
cleanup() {
  if [[ "$attached" == yes ]]; then
    hdiutil detach "$mnt" >/dev/null 2>&1 || hdiutil detach -force "$mnt" >/dev/null 2>&1 || echo "check-dmg: could not detach $mnt" >&2
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

mkdir "$mnt" "$tmp/ref"
ditto -x -k "$zip" "$tmp/ref"
[[ "$(ls -A "$tmp/ref")" == Chervotochina.app ]] || { echo "check-dmg: the zip must hold exactly Chervotochina.app" >&2; exit 1; }

hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$mnt" "$dmg" > "$tmp/attach.log" 2>&1 || { cat "$tmp/attach.log" >&2; echo "check-dmg: hdiutil attach failed" >&2; exit 1; }
attached=yes

# root: visible items exactly Applications and Chervotochina.app; hidden service items are printed
visible="$(ls "$mnt" | LC_ALL=C sort | tr '\n' ' ')"
[[ "$visible" == 'Applications Chervotochina.app ' ]] || err "the visible root is '$visible', expected 'Applications Chervotochina.app '"
hidden="$(ls -A "$mnt" | grep '^\.' | tr '\n' ' ' || true)"
echo "check-dmg: hidden service items (allowed): ${hidden:-none}"
if [[ -L "$mnt/Applications" ]]; then
  [[ "$(readlink "$mnt/Applications")" == /Applications ]] || err "Applications points to '$(readlink "$mnt/Applications")', expected exactly /Applications"
else
  err "Applications is not a symbolic link"
fi
[[ -d "$mnt/Chervotochina.app" && ! -L "$mnt/Chervotochina.app" ]] || err "Chervotochina.app is not a real directory"

app="$mnt/Chervotochina.app"
ref="$tmp/ref/Chervotochina.app"
if [[ -d "$app" ]]; then
  links="$(find "$app" -type l | head -n 5)"
  [[ -z "$links" ]] || err "symbolic links inside the .app: $links"
  # anything that is not a plain file or directory (links, sockets, devices) is a problem too
  odd="$(find "$app" ! -type f ! -type d | head -n 5)"
  [[ -z "$odd" ]] || err "special files inside the .app: $odd"
  (cd "$app" && find . -type f | LC_ALL=C sort) > "$tmp/files.dmg"
  (cd "$ref" && find . -type f | LC_ALL=C sort) > "$tmp/files.zip"
  if ! cmp -s "$tmp/files.dmg" "$tmp/files.zip"; then
    err "the file list of the .app in the image differs from the .zip"
    diff "$tmp/files.dmg" "$tmp/files.zip" | head -n 20 >&2 || true
  fi
  (cd "$app" && find . -type d | LC_ALL=C sort) > "$tmp/dirs.dmg"
  (cd "$ref" && find . -type d | LC_ALL=C sort) > "$tmp/dirs.zip"
  cmp -s "$tmp/dirs.dmg" "$tmp/dirs.zip" || err "the directory list of the .app in the image differs from the .zip"
  nfiles=0
  while IFS= read -r f; do
    nfiles=$((nfiles + 1))
    cmp -s -- "$app/$f" "$ref/$f" || err "differs from the .zip: $f"
  done < "$tmp/files.zip"
  echo "check-dmg: compared $nfiles files of the .app with the .zip"
  codesign --verify --strict --verbose=2 "$app" || err "codesign --verify --strict failed on the mounted .app"
fi

if [[ $bad -eq 0 ]]; then
  echo "check-dmg: ok ($dmg)"
  exit 0
fi
echo "check-dmg: FAILED ($dmg)" >&2
exit 1
