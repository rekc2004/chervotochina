#!/usr/bin/env bash
# Stage 19b/19g: builds the release binaries for one target, each with its OWN cargo call:
# `chervo` of package chervo-cli and `chervotochina` of package chervo-gui.
#   bash scripts/release/build-release.sh <rust-target-triple> <out-dir> <verifier-dir>
# Output (SHA-256 of each file is printed, with a "published" / "verifier, not published" mark):
#   <out-dir>/chervo-<ver>-linux-x86_64                      CLI, Linux only (Q5 b)
#   <out-dir>/chervotochina-<ver>-linux-x86_64               window
#   <out-dir>/chervotochina-<ver>-windows-x86_64.exe         window
#   <out-dir>/chervotochina-<ver>-macos-<arch>.zip           window (Chervotochina.app, package-macos.sh)
#   <verifier-dir>/chervo-verifier-<ver>-<label>[.exe]       CLI of Windows/macOS: NEVER published (R19g-11)
#
# Test hooks (feature `test-store` of chervo-core, stage 18a) must not reach the release:
# the build is by package only (-p <one package> --bin <one bin>), never --workspace, --all-targets,
# --all-features, --examples, and never two -p in one call (resolver 3 would unify the features of both
# packages). scripts/check-release-guards.sh checks the form of the commands below; this script
# additionally checks the resolved feature set of each package.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: build-release.sh <rust-target-triple> <out-dir> <verifier-dir>" >&2
  exit 2
fi
triple="$1"
outdir="$2"
vdir="$3"

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

# Guard 5a, resolved features of each released package must not contain the test hooks.
check_tree() { # package
  local tree
  tree="$(cargo tree --locked -e no-dev,features -p "$1" --target "$triple")"
  if grep -qF 'feature "test-store"' <<<"$tree"; then
    echo "build-release: feature test-store is enabled for $1; refusing to build" >&2
    return 1
  fi
}

mark() { # file published|verifier
  local note="published"
  [[ "$2" == published ]] || note="verifier, not published"
  echo "built $(basename "$1") sha256=$(sha256_of "$1") size=$(size_of "$1") [$note]"
}

# 1. CLI. Linux: released. Other targets: only the verifier build (R19g-11), outside <out-dir>.
check_tree chervo-cli
cargo build --release --locked -p chervo-cli --bin chervo --target "$triple"
if [[ "$label" == linux-x86_64 ]]; then
  mkdir -p "$outdir"
  cli="$outdir/chervo-$ver-$label$ext"
  cp "target/$triple/release/chervo$ext" "$cli"
  mark "$cli" published
else
  mkdir -p "$vdir"
  cli="$vdir/chervo-verifier-$ver-$label$ext"
  cp "target/$triple/release/chervo$ext" "$cli"
  mark "$cli" verifier
fi

# 2. GUI (window), a separate call and a separate feature check.
check_tree chervo-gui
if [[ "$label" == linux-x86_64 ]]; then
  bash scripts/check-gui-linux-tree.sh
fi
cargo build --release --locked -p chervo-gui --bin chervotochina --target "$triple"
mkdir -p "$outdir"
case "$label" in
  linux-x86_64|windows-x86_64)
    gui="$outdir/chervotochina-$ver-$label$ext"
    cp "target/$triple/release/chervotochina$ext" "$gui"
    ;;
  *)
    bash scripts/release/package-macos.sh "target/$triple/release/chervotochina" "$ver" "$label" "$outdir"
    gui="$outdir/chervotochina-$ver-$label.zip"
    ;;
esac
mark "$gui" published
