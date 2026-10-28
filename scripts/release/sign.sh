#!/usr/bin/env bash
# Stage 19b (spec 19, section 5 item 4). RUN BY THE OWNER ON HIS OWN MACHINE (Linux or Git Bash).
# The signing key never leaves the owner (Q1 = a); CI has no key.
#
#   bash scripts/release/sign.sh <tag> <path-to-primary-secret-key>
#
# Needs: minisign, gh (logged in), git, bash, sha256sum or shasum. The secret key must lie OUTSIDE
# this repository. The script does NOT publish the release; publishing is done by hand.
#
# Steps: download the DRAFT into a new empty temp directory -> compare size and SHA-256 of every file with
# the manifest (before any signature) -> check the manifest `commit` against the tag in THIS clone and
# compare every file with the artifact `release-files` of the finished push run of release.yml on that
# commit (the draft alone is not trusted: whoever holds a write token can replace draft and manifest
# together) -> find the checker of this OS (Linux: the released chervo; Windows, macOS: the CI verifier of
# that same run, which is not in the release, Q5 b) -> sign the manifest and every file -> verify with minisign
# and the checker (files of this target and "any") -> show the list and ask before uploading the signatures.
# No checker for this OS = nothing is signed (stage 19g: the old "WARNING ... was NOT run" is gone).
# Run it from a clone of the repository that has the tag (`git fetch --tags` first); gh needs read access
# to Actions artifacts. Residual risk: spec 19 section 8, T19.
# [not verified: minisign flags -S -m -s -t -V -p were written from the minisign manual, and this script
# was not run end to end; first run only with a throw-away key and a throw-away draft]
set -euo pipefail

usage() {
  echo "usage: bash scripts/release/sign.sh <tag> <path-to-primary-secret-key>" >&2
  exit 2
}
[[ $# -eq 2 ]] || usage
tag="$1"
key="$2"
repo="${CHERVO_REPO:-rekc2004/chervotochina}"

root="$(cd "$(dirname "$0")/../.." && pwd -P)"
# shellcheck source=lib.sh
. "$root/scripts/release/lib.sh"

die() { echo "sign.sh: $*" >&2; exit 1; }

[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "bad tag '$tag' (expected v<MAJOR>.<MINOR>.<PATCH>)"
for tool in minisign gh git; do
  command -v "$tool" >/dev/null 2>&1 || die "'$tool' is not installed"
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  die "neither sha256sum nor shasum is available"
fi

# The secret key must exist and must not be inside the repository.
[[ -f "$key" ]] || die "no such key file: $key"
keyabs="$(cd "$(dirname "$key")" && pwd -P)/$(basename "$key")"
case "$keyabs" in
  "$root"/*) die "the secret key is inside the repository ($keyabs); move it out" ;;
esac

pub="$root/crates/chervo-update/keys/primary.pub"
[[ -s "$pub" ]] || die "the embedded primary public key is empty ($pub): embed the owner keys first"

# The release must be a draft.
is_draft="$(gh release list --repo "$repo" --limit 100 --json tagName,isDraft \
  --jq ".[] | select(.tagName == \"$tag\") | .isDraft")"
[[ "$is_draft" == "true" ]] || die "release $tag was not found among drafts of $repo (isDraft='$is_draft')"

# The commit of the tag in this clone (a clone is required).
git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  || die "this script must run from a clone of the repository (no git work tree at $root)"
commit="$(git -C "$root" rev-parse --verify --quiet "refs/tags/$tag^{commit}")" \
  || die "tag $tag is not in this clone: run 'git fetch --tags' first"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "unexpected commit id for $tag: '$commit'"

work="$(mktemp -d)"
ci="$(mktemp -d)"
vdir="$(mktemp -d)"
trap 'rm -rf "$work" "$ci" "$vdir"' EXIT
gh release download "$tag" --repo "$repo" --dir "$work"
# Hidden files count too (the "no extra files" loop below); files that match nothing give an empty list.
shopt -s dotglob nullglob
cd "$work"

[[ -f chervo-release.txt ]] || die "chervo-release.txt is not in the draft"
if compgen -G '*.minisig' >/dev/null; then
  die "the draft already has .minisig files; refusing to sign twice"
fi
ver="$(awk '$1 == "version" { print $2; exit }' chervo-release.txt | tr -d '\r')"
[[ "$tag" == "v$ver" ]] || die "tag $tag does not match manifest version $ver"
mcommit="$(awk '$1 == "commit" { print $2; exit }' chervo-release.txt | tr -d '\r')"
[[ "$mcommit" == "$commit" ]] || die "manifest commit '$mcommit' differs from the commit of tag $tag in this clone ($commit)"
echo "manifest commit = commit of tag $tag: $commit"

# 1. Every file against the manifest (size and SHA-256), before anything is signed.
listed=( chervo-release.txt )
while read -r kw target sha size name; do
  [[ "$kw" == "artifact" ]] || continue
  name="${name%$'\r'}"
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "unsafe file name in the manifest: '$name'"
  [[ -f "$name" && ! -L "$name" ]] || die "file from the manifest is missing (or is a link): $name"
  [[ "$(size_of "$name")" == "$size" ]] || die "size differs from the manifest: $name"
  [[ "$(sha256_of "$name")" == "$sha" ]] || die "SHA-256 differs from the manifest: $name"
  listed+=( "$name" )
  echo "manifest ok: $target $name $sha"
done < chervo-release.txt
[[ ${#listed[@]} -gt 1 ]] || die "no artifacts in the manifest"
# No extra files in the draft.
for f in *; do
  found=no
  for l in "${listed[@]}"; do [[ "$f" == "$l" ]] && found=yes; done
  [[ "$found" == yes ]] || die "file in the draft is not in the manifest: $f"
done
artifacts=( "${listed[@]:1}" )

# 1а. The draft against the build artifact `release-files` of a finished, successful PUSH run of
# release.yml whose head_sha is the commit of the tag. No such run, or any difference = failure.
run_ids="$(gh run list --repo "$repo" --workflow release.yml --event push --status success --limit 200 \
  --json databaseId,headSha,event,status,conclusion \
  --jq ".[] | select(.headSha == \"$commit\" and .event == \"push\" and .status == \"completed\" and .conclusion == \"success\") | .databaseId")"
[[ -n "$run_ids" ]] || die "no finished successful push run of release.yml on commit $commit; wait for CI or do not sign"
matched=""
for id in $run_ids; do
  [[ "$id" =~ ^[0-9]+$ ]] || die "unexpected run id from gh: '$id'"
  rm -rf "$ci"; mkdir "$ci"
  if ! gh run download "$id" --repo "$repo" -n release-files -D "$ci" >/dev/null; then
    echo "run $id: artifact release-files is not available (expired?), trying the next run" >&2
    continue
  fi
  same=yes
  for f in *; do
    if [[ ! -f "$ci/$f" || "$(sha256_of "$f")" != "$(sha256_of "$ci/$f")" ]]; then
      echo "run $id: '$f' differs from the CI artifact or is absent there" >&2; same=no
    fi
  done
  for f in "$ci"/*; do
    [[ -e "./${f##*/}" ]] || { echo "run $id: '${f##*/}' is in the CI artifact but not in the draft" >&2; same=no; }
  done
  if [[ "$same" == yes ]]; then matched="$id"; break; fi
done
[[ -n "$matched" ]] || die "the draft does NOT match the artifact release-files of any successful push run on $commit; do not sign"
echo "draft = artifact release-files of run $matched (commit $commit): $(printf '%s ' "${listed[@]}")"

# 1б. The checker of this OS, BEFORE anything is signed (stage 19g, Q5 b, R19g-11). The CLI is released for
# Linux only. Windows and macOS: the checker is `chervo-verifier-<ver>-<label><ext>` from the artifact
# verifier-<label> of the SAME run $matched whose release-files equal the draft; it is not in the draft,
# not in the manifest and not signed. It is run only after the draft was compared with that run.
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  label=linux-x86_64;   ext='' ;;
  Darwin-arm64)  label=macos-aarch64;  ext='' ;;
  Darwin-x86_64) label=macos-x86_64;   ext='' ;;
  MINGW*-x86_64|MSYS*-x86_64|CYGWIN*-x86_64) label=windows-x86_64; ext='.exe' ;;
  *) die "sign.sh runs on Linux x86_64, Windows x86_64 (Git Bash) or macOS; nothing was signed" ;;
esac
gext="$(gui_ext "$label")"
if [[ "$label" == linux-x86_64 ]]; then
  verifier="./chervo-$ver-$label"
  [[ -f "$verifier" && ! -L "$verifier" ]] || die "chervo-$ver-$label is not in the draft; nothing was signed"
  chmod +x "$verifier"
else
  gh run download "$matched" --repo "$repo" -n "verifier-$label" -D "$vdir" >/dev/null \
    || die "artifact verifier-$label of run $matched is not available (14 days?); nothing was signed"
  vfiles=( "$vdir"/* )
  vname="chervo-verifier-$ver-$label$ext"
  [[ ${#vfiles[@]} -eq 1 && -f "${vfiles[0]}" && ! -L "${vfiles[0]}" && "${vfiles[0]##*/}" == "$vname" ]] \
    || die "the artifact verifier-$label must hold exactly one regular file $vname; nothing was signed"
  verifier="${vfiles[0]}"
  chmod +x "$verifier"
  echo "verifier from run $matched, commit $commit, not published, not signed: $(sha256_of "$verifier")  $vname"
fi
# Files of this target and of target "any" (the checker is given only these: files of other targets
# would give WrongTarget).
own=()
while read -r kw target sha size name; do
  [[ "$kw" == "artifact" ]] || continue
  name="${name%$'\r'}"
  if [[ "$target" == "$label" || "$target" == "any" ]]; then own+=( "$name" ); fi
done < chervo-release.txt
have_gui=no
for f in "${own[@]}"; do [[ "$f" == "chervotochina-$ver-$label$gext" ]] && have_gui=yes; done
[[ "$have_gui" == yes ]] || die "the manifest has no chervotochina-$ver-$label$gext for target $label; nothing was signed"

# 2. Sign: the manifest (trusted comment with the version) and each file (password is typed by the owner).
minisign -Sm chervo-release.txt -s "$key" -t "chervo-release $ver"
for f in "${artifacts[@]}"; do
  minisign -Sm "$f" -s "$key"
done

# 3. Verify with minisign (the manifest and ALL files), then with the checker of this OS (step 1б):
#    only files of this target and of target "any" are given to it.
minisign -Vm chervo-release.txt -p "$pub"
for f in "${artifacts[@]}"; do
  minisign -Vm "$f" -p "$pub"
done
vout="$("$verifier" verify-release chervo-release.txt chervo-release.txt.minisig "${own[@]}" | tr -d '\r')" \
  || die "verify-release failed on the signed files of $label and any"
echo "$vout"
ver_re="${ver//./[.]}"
nok="$(grep -cE "^OK [A-Za-z0-9._-]+ $ver_re same$" <<<"$vout" || true)"
nlines="$(grep -c . <<<"$vout" || true)"
[[ "$nok" == "${#own[@]}" && "$nlines" == "${#own[@]}" ]] \
  || die "verify-release: expected exactly ${#own[@]} lines 'OK <name> $ver same', got $nok of $nlines; nothing was uploaded"

# 4. Ask before changing the draft.
echo
echo "Signatures to upload to the draft $tag of $repo:"
upload=( chervo-release.txt.minisig )
for f in "${artifacts[@]}"; do upload+=( "$f.minisig" ); done
printf '  %s\n' "${upload[@]}"
read -r -p "загрузить подписи в черновик? (да/нет) " answer
if [[ "$answer" == "да" ]]; then
  gh release upload "$tag" --repo "$repo" "${upload[@]}"
  echo "Uploaded. The release is still a DRAFT; publish it by hand after the checklist."
else
  echo "Nothing uploaded."
fi

cat <<EOF

CHECKLIST before publishing $tag (the script publishes nothing):
  [ ] docs/SECURITY_REVIEW.md: no open High/Critical on the code of the tag; security reviews of stages 18 and 19 exist
  [ ] CI of the tag is green; job 'smoke' is green on all OS
  [ ] workflow release-smoke.yml for $tag is green on all OS (run it after the upload above)
  [ ] by hand, with the RELEASE files:
      Windows (owner's PC, real Credential Manager): run chervotochina-*.exe from the draft; the first screen
        shows 'хранилище доступно'; on the screen 'Обновления' the downloaded manifest, signature and .exe give
        'подходит, та же версия'; the keys on that screen match the README;
      Linux machine of the owner: 'chervo doctor' per docs/HEADLESS_LINUX.md, 'chervo release-keys' matches the README;
      macOS: no machine, write 'not verified on macOS' in the release notes
  [ ] optional, owner decides: file transfer between two machines with release files, SHA-256 match
  [ ] after publishing: Linux: 'chervo check-update' with the binary of the previous version (or a 0.0.0 build) shows
      the new version, with the release binary it says the latest version is installed;
      Windows: in the window with the update check switched on, 'Проверить сейчас' says 'Установлена последняя версия'
  [ ] key_id of the keys ('chervo release-keys' on Linux, the screen 'Обновления' on Windows) match the README and the owner's second channel
EOF
