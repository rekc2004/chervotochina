#!/usr/bin/env bash
# Stage 19b: builds ONLY the release binary `chervo` of package chervo-cli for one target.
#   bash scripts/release/build-release.sh <rust-target-triple> <out-dir>
# Output: <out-dir>/chervo-<version>-<label>[.exe], SHA-256 is printed.
#
# Test hooks (feature `test-store` of chervo-core, stage 18a) must not reach the release:
# the build is by package only (-p chervo-cli --bin chervo), never --workspace, --all-targets,
# --all-features, --examples (resolver 3 would unify dev-features). scripts/check-release-guards.sh
# checks the form of the command below; this script additionally checks the resolved feature set.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: build-release.sh <rust-target-triple> <out-dir>" >&2
  exit 2
fi
triple="$1"
outdir="$2"

root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=lib.sh
. "$root/scripts/release/lib.sh"
cd "$root"

case "$triple" in
  x86_64-unknown-linux-gnu)  label=linux-x86_64;   ext='' ;;
  aarch64-apple-darwin)      label=macos-aarch64;  ext='' ;;
  x86_64-apple-darwin)       label=macos-x86_64;   ext='' ;;
  x86_64-pc-windows-msvc)    label=windows-x86_64; ext='.exe' ;;
  *) echo "unsupported target: $triple" >&2; exit 2 ;;
esac

ver="$(bash scripts/release/version.sh)"
rustup target add "$triple"

ws="$(native_path "$root")"
cargo_home="$(native_path "${CARGO_HOME:-$HOME/.cargo}")"
flags="--remap-path-prefix=$ws=/build --remap-path-prefix=$cargo_home=/cargo"
if [[ "$triple" == *-windows-msvc ]]; then
  flags="$flags -C target-feature=+crt-static"
fi
export RUSTFLAGS="$flags"
export CARGO_PROFILE_RELEASE_STRIP=symbols
export CARGO_PROFILE_RELEASE_DEBUG=0

# Guard 5a, resolved features of the released package must not contain the test hooks.
tree="$(cargo tree --locked -e no-dev,features -p chervo-cli --target "$triple")"
if grep -qF 'feature "test-store"' <<<"$tree"; then
  echo "build-release: feature test-store is enabled for chervo-cli; refusing to build" >&2
  exit 1
fi

cargo build --release --locked -p chervo-cli --bin chervo --target "$triple"

mkdir -p "$outdir"
name="chervo-$ver-$label$ext"
cp "target/$triple/release/chervo$ext" "$outdir/$name"
sum="$(sha256_of "$outdir/$name")"
echo "built $name sha256=$sum size=$(size_of "$outdir/$name")"
