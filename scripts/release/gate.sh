#!/usr/bin/env bash
# Stage 19b: release gate (runs in release.yml, job `gate`, with full git history).
#   bash scripts/release/gate.sh
# Environment: GITHUB_REF_TYPE, GITHUB_REF_NAME, GITHUB_OUTPUT (Actions), SKIP_KEYS_INPUT
# ("true" only for workflow_dispatch trial runs without a tag).
# Tag: name matches v<MAJOR>.<MINOR>.<PATCH>; equals v + workspace version; its commit is an
# ancestor of origin/main; the owner keys are embedded (test embedded_keys).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=lib.sh
. "$root/scripts/release/lib.sh"
cd "$root"

ref_type="${GITHUB_REF_TYPE:-}"
ref_name="${GITHUB_REF_NAME:-}"
skip=false

if [[ "${SKIP_KEYS_INPUT:-}" == "true" ]]; then
  if [[ "$ref_type" == "tag" ]]; then
    echo "gate: skip_keys_check is not allowed for a tag" >&2
    exit 1
  fi
  skip=true
fi

if [[ "$ref_type" == "tag" ]]; then
  if ! [[ "$ref_name" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "gate: tag '$ref_name' does not match v<MAJOR>.<MINOR>.<PATCH>" >&2
    exit 1
  fi
  ver="$(bash scripts/release/version.sh)"
  if [[ "v$ver" != "$ref_name" ]]; then
    echo "gate: tag $ref_name does not equal v + workspace version ($ver)" >&2
    exit 1
  fi
  git rev-parse --verify --quiet origin/main >/dev/null || { echo "gate: origin/main is not fetched" >&2; exit 1; }
  if ! git merge-base --is-ancestor HEAD origin/main; then
    echo "gate: the commit of the tag is not an ancestor of origin/main" >&2
    exit 1
  fi
  summary "gate: tag $ref_name = workspace version, commit $(git rev-parse HEAD) is on main"
else
  summary "gate: trial run (no tag); the draft job will not run"
fi

if [[ "$skip" == "true" ]]; then
  summary "gate: WARNING embedded_keys NOT checked (skip_keys_check = true, trial run only)"
else
  cargo test -p chervo-update --locked --test embedded_keys -- --include-ignored
  summary "gate: owner keys are embedded (embedded_keys passed)"
fi

echo "skip_keys=$skip" >> "${GITHUB_OUTPUT:-/dev/null}"
