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
# together) -> sign the manifest and every file -> verify with minisign and the embedded keys -> show the
# list and ask before uploading the signatures to the draft.
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
trap 'rm -rf "$work" "$ci"' EXIT
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

# 2. Sign: the manifest (trusted comment with the version) and each file (password is typed by the owner).
minisign -Sm chervo-release.txt -s "$key" -t "chervo-release $ver"
for f in "${artifacts[@]}"; do
  minisign -Sm "$f" -s "$key"
done

# 3. Verify with minisign and the embedded public key, then with our own program of this OS.
minisign -Vm chervo-release.txt -p "$pub"
for f in "${artifacts[@]}"; do
  minisign -Vm "$f" -p "$pub"
done
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  label=linux-x86_64;   ext='' ;;
  Darwin-arm64)  label=macos-aarch64;  ext='' ;;
  Darwin-x86_64) label=macos-x86_64;   ext='' ;;
  MINGW*-x86_64|MSYS*-x86_64|CYGWIN*-x86_64) label=windows-x86_64; ext='.exe' ;;
  *) label=''; ext='' ;;
esac
bin="chervo-$ver-$label$ext"
if [[ -n "$label" && -f "$bin" ]]; then
  chmod +x "$bin"
  "./$bin" verify-release chervo-release.txt chervo-release.txt.minisig "${artifacts[@]}" \
    || die "chervo verify-release failed on the signed files"
else
  echo "WARNING: no binary for this OS in the release; 'chervo verify-release' was NOT run" >&2
fi

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
  [ ] by hand, with the RELEASE binary: Windows (owner's PC, real Credential Manager) 'chervo doctor' -> available;
      Linux machine of the owner: 'chervo doctor' per docs/HEADLESS_LINUX.md; macOS: no machine,
      write 'not verified on macOS' in the release notes
  [ ] optional, owner decides: file transfer between two machines with release binaries, SHA-256 match
  [ ] after publishing: 'chervo check-update' with the binary of the previous version (or a 0.0.0 build) shows
      the new version; with the release binary it says the latest version is installed
  [ ] key_id of the keys ('chervo release-keys') match the README and the owner's second channel
EOF
