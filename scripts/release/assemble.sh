#!/usr/bin/env bash
# Stage 19b: collects the release directory and builds the unsigned manifest.
#   bash scripts/release/assemble.sh <dist-dir> <release-dir>
# <dist-dir> holds the binaries of all targets (artifacts of `build`); this script
#   1. makes the SBOMs (cargo-cyclonedx 0.5.9, must be installed) for chervo-cli and chervo-gui,
#      and the third-party licence file (cargo-about =0.9.2, must be installed),
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

# 1. SBOM of both packages (no per-target choice is used). Stage 19g: the GUI gets its own file.
#    [not verified] that cargo-cyclonedx 0.5.9 writes sbom.json for EVERY workspace member; a missing file stops here.
cargo cyclonedx --format json --override-filename sbom
[[ -f crates/chervo-cli/sbom.json ]] || { echo "SBOM was not created: crates/chervo-cli/sbom.json" >&2; exit 1; }
[[ -f crates/chervo-gui/sbom.json ]] || { echo "SBOM was not created: crates/chervo-gui/sbom.json" >&2; exit 1; }
cp crates/chervo-cli/sbom.json "$dist/chervo-$ver-sbom.cdx.json"
cp crates/chervo-gui/sbom.json "$dist/chervotochina-$ver-sbom.cdx.json"

# 1b. Third-party licences (stage 19g-4, Q6 = a): cargo-about (pinned in release.yml) over the window and the
#     CLI packages separately (no --workspace: guard rule 1). The file is `any` in the manifest.
lic="$dist/chervo-$ver-third-party-licenses.txt"
lic_tpl=packaging/licenses/third-party-licenses.hbs
lic_cfg=packaging/licenses/about.toml
lic_part1="$(mktemp)"
lic_part2="$(mktemp)"
trap 'rm -f "$lic_part1" "$lic_part2"' EXIT
cargo about generate -c "$lic_cfg" -m crates/chervo-gui/Cargo.toml --locked --fail -o "$lic_part1" "$lic_tpl"
cargo about generate -c "$lic_cfg" -m crates/chervo-cli/Cargo.toml --locked --fail -o "$lic_part2" "$lic_tpl"
{
  echo "Third-party licenses of Chervotochina $ver (commit $commit)"
  echo
  echo "Part 1: chervotochina (window, all 4 targets)"
  echo
  cat "$lic_part1"
  echo
  echo "Part 2: chervo (console, Linux)"
  echo
  cat "$lic_part2"
} > "$lic"
lic_size="$(size_of "$lic")"
if [[ "$lic_size" -le 0 || "$lic_size" -ge 8388608 ]]; then
  echo "licence file has a bad size: $lic_size" >&2; exit 1
fi
for needle in epaint_default_fonts clipboard-win error-code webpki-roots OFL-1.1 Ubuntu-font-1.0 BSL-1.0 CDLA-Permissive-2.0 MIT Apache-2.0; do
  grep -qF -- "$needle" "$lic" || { echo "licence file lacks '$needle'" >&2; exit 1; }
done
for ent in '&lt;' '&gt;' '&amp;' '&quot;' '&#'; do
  if grep -qF -- "$ent" "$lic"; then echo "licence file has an HTML entity: $ent" >&2; exit 1; fi
done
if grep -q '^{{' "$lic"; then echo "licence file has a line starting with '{{'" >&2; exit 1; fi
lic_sections="$(grep -c '^=\{16,\}$' "$lic" || true)"
lic_stubs=0
for stub in '<copyright holders>' '<year>' '<Copyright Holder>'; do
  n="$(grep -oF -- "$stub" "$lic" | wc -l | tr -d '[:space:]')"
  lic_stubs=$((lic_stubs + n))
done
# Apache-2.0 requires NOTICE files to travel along: only recorded here (crate sources), the owner decides.
lic_notices="$(find "${CARGO_HOME:-$HOME/.cargo}/registry/src" -maxdepth 2 -name 'NOTICE*' 2>/dev/null | LC_ALL=C sort || true)"
summary "### Third-party licences" "sections: $lic_sections, placeholder stubs: $lic_stubs, size: $lic_size bytes" "NOTICE files in crate sources:" '```' "${lic_notices:-none}" '```'

# 2. White list.
bash scripts/release/check-whitelist.sh "$dist" "$ver"

# 3. Manifest.
[[ ! -e "$release" ]] || { echo "release directory already exists: $release" >&2; exit 1; }
mkdir -p "$release"
cp -- "$dist"/* "$release"/
cargo run --locked -p chervo-update --bin chervo-make-manifest -- \
  --version "$ver" --commit "$commit" --out "$release/chervo-release.txt" \
  --artifact linux-x86_64 "$release/chervo-$ver-linux-x86_64" \
  --artifact linux-x86_64 "$release/chervotochina-$ver-linux-x86_64" \
  --artifact macos-aarch64 "$release/chervotochina-$ver-macos-aarch64.zip" \
  --artifact macos-x86_64 "$release/chervotochina-$ver-macos-x86_64.zip" \
  --artifact windows-x86_64 "$release/chervotochina-$ver-windows-x86_64.exe" \
  --artifact any "$release/chervo-$ver-sbom.cdx.json" \
  --artifact any "$release/chervotochina-$ver-sbom.cdx.json" \
  --artifact any "$release/chervo-$ver-third-party-licenses.txt"

# 4. Format check of the manifest file.
CHERVO_MANIFEST="$(cd "$release" && pwd)/chervo-release.txt" \
  cargo test -p chervo-update --locked --test manifest_file -- --include-ignored

summary "### Release files (unsigned)" "commit \`$commit\`, version \`$ver\`" '```'
(cd "$release" && for f in *; do printf '%s  %s  %s bytes\n' "$(sha256_of "$f")" "$f" "$(size_of "$f")"; done) | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
summary '```' "Manifest:" '```'
tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}" < "$release/chervo-release.txt"
summary '```'
