#!/usr/bin/env bash
# Stage 19b: collects the release directory and builds the unsigned manifest.
#   bash scripts/release/assemble.sh <dist-dir> <release-dir>
# <dist-dir> holds the binaries of all targets (artifacts of `build`); this script
#   1. makes the SBOM (cargo-cyclonedx 0.5.9, must be installed) for chervo-cli,
#   2. checks the white list (exactly the expected names; any extra file fails),
#   3. writes <release-dir>/chervo-release.txt with chervo-make-manifest,
#   4. checks the manifest format (test manifest_file).
# The owner signs afterwards (scripts/release/sign.sh); there is no key in CI.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: assemble.sh <dist-dir> <release-dir>" >&2
  exit 2
fi
dist="$1"
release="$2"
root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=lib.sh
. "$root/scripts/release/lib.sh"
cd "$root"

ver="$(bash scripts/release/version.sh)"
commit="$(git rev-parse HEAD)"

# 1. SBOM. One SBOM for chervo-cli (no per-target choice is used; [not verified] whether 0.5.9 offers it).
cargo cyclonedx --format json --override-filename sbom
[[ -f crates/chervo-cli/sbom.json ]] || { echo "SBOM was not created: crates/chervo-cli/sbom.json" >&2; exit 1; }
cp crates/chervo-cli/sbom.json "$dist/chervo-$ver-sbom.cdx.json"

# 2. White list.
bash scripts/release/check-whitelist.sh "$dist" "$ver"

# 3. Manifest.
[[ ! -e "$release" ]] || { echo "release directory already exists: $release" >&2; exit 1; }
mkdir -p "$release"
cp -- "$dist"/* "$release"/
cargo run --locked -p chervo-update --bin chervo-make-manifest -- \
  --version "$ver" --commit "$commit" --out "$release/chervo-release.txt" \
  --artifact linux-x86_64 "$release/chervo-$ver-linux-x86_64" \
  --artifact macos-aarch64 "$release/chervo-$ver-macos-aarch64" \
  --artifact macos-x86_64 "$release/chervo-$ver-macos-x86_64" \
  --artifact windows-x86_64 "$release/chervo-$ver-windows-x86_64.exe" \
  --artifact any "$release/chervo-$ver-sbom.cdx.json"

# 4. Format check of the manifest file.
CHERVO_MANIFEST="$(cd "$release" && pwd)/chervo-release.txt" \
  cargo test -p chervo-update --locked --test manifest_file -- --include-ignored

summary "### Release files (unsigned)" "commit \`$commit\`, version \`$ver\`" '```'
(cd "$release" && for f in *; do printf '%s  %s  %s bytes\n' "$(sha256_of "$f")" "$f" "$(size_of "$f")"; done) | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
summary '```' "Manifest:" '```'
tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}" < "$release/chervo-release.txt"
summary '```'
