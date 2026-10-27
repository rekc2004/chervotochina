#!/usr/bin/env bash
# Stage 19b (C31): every `uses:` in .github/workflows is pinned by a 40-hex commit SHA with a
# `# vX.Y.Z` comment; only actions/checkout, actions/upload-artifact, actions/download-artifact
# (and local ./.github/workflows/* reusable workflows) are allowed.
#   bash scripts/check-actions-pinned.sh [dir-with-workflows]
#   bash scripts/check-actions-pinned.sh --self-test
set -euo pipefail

allowed_re='^actions/(checkout|upload-artifact|download-artifact)$'
sha_re='^[0-9a-f]{40}$'
comment_re='^# v[0-9]+\.[0-9]+\.[0-9]+([[:space:]].*)?$'

# Prints a message per bad line; returns 1 if any (or if there are no workflow files at all).
check_dir() {
  local dir="$1" f line n bad=0 rest spec comment name ref found=0
  for f in "$dir"/*.yml "$dir"/*.yaml; do
    [[ -e "$f" ]] || continue
    found=1
    n=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      n=$((n + 1))
      line="${line%$'\r'}"
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      if ! [[ "$line" =~ ^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*(.*)$ ]]; then
        # `uses` in any other form (flow mapping `- {uses: x@y}`, quoted key, space before the colon)
        # is not parsed here, so it is forbidden rather than skipped.
        if [[ "$line" =~ (^|[^A-Za-z0-9_-])[\"\']?uses[\"\']?[[:space:]]*: ]]; then
          echo "$f:$n: 'uses' in an unsupported form (use a plain '- uses: x@sha # vX.Y.Z' line): $line" >&2; bad=1
        fi
        continue
      fi
      rest="${BASH_REMATCH[2]}"
      if [[ "$rest" == *" #"* ]]; then
        spec="${rest%% \#*}"
        comment="#${rest#*\#}"
      else
        spec="$rest"
        comment=""
      fi
      spec="${spec%"${spec##*[![:space:]]}"}"
      if [[ "$spec" == ./.github/workflows/* ]]; then
        continue
      fi
      if [[ "$spec" != *@* ]]; then
        echo "$f:$n: no @ref in uses: $spec" >&2; bad=1; continue
      fi
      name="${spec%@*}"
      ref="${spec##*@}"
      if [[ ! "$name" =~ $allowed_re ]]; then
        echo "$f:$n: action not in allow-list: $name" >&2; bad=1; continue
      fi
      if [[ ! "$ref" =~ $sha_re ]]; then
        echo "$f:$n: not a 40-hex lowercase commit SHA: $ref" >&2; bad=1; continue
      fi
      if [[ ! "$comment" =~ $comment_re ]]; then
        echo "$f:$n: missing '# vX.Y.Z' comment" >&2; bad=1; continue
      fi
    done < "$f"
  done
  if [[ $found -eq 0 ]]; then
    echo "no workflow files in $dir" >&2
    return 1
  fi
  return "$bad"
}

self_test() {
  local tmp rc fail=0 i=0 body
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  local sha=0123456789abcdef0123456789abcdef01234567
  mkdir "$tmp/ok"
  cat > "$tmp/ok/a.yml" <<YML
jobs:
  x:
    steps:
      # - uses: evil/thing@main   (comment lines are ignored)
      - uses: actions/checkout@$sha # v4.4.0
      - uses: actions/upload-artifact@$sha # v4.6.2
        with: {name: a}
      - uses: actions/download-artifact@$sha # v4.3.0
  y:
    uses: ./.github/workflows/ci.yml
YML
  rc=0; check_dir "$tmp/ok" 2>/dev/null || rc=$?
  if [[ $rc -ne 0 ]]; then echo "self-test: FAILED (good file rejected)" >&2; fail=1; fi
  local bads=(
    "actions/checkout@v4"
    "actions/checkout@${sha:0:39} # v4.4.0"
    "actions/checkout@${sha}0 # v4.4.0"
    "actions/checkout@${sha^^} # v4.4.0"
    "actions/checkout@$sha"
    "actions/checkout@$sha # v4"
    "actions/checkout@$sha # latest"
    "actions/checkout@main"
    "someone/else@$sha # v1.0.0"
    "actions/cache@$sha # v4.0.0"
    "docker://alpine:3.20"
    "actions/checkout"
  )
  for body in "${bads[@]}"; do
    i=$((i + 1))
    mkdir "$tmp/bad$i"
    printf 'jobs:\n  x:\n    steps:\n      - uses: %s\n' "$body" > "$tmp/bad$i/b.yml"
    rc=0; check_dir "$tmp/bad$i" 2>/dev/null || rc=$?
    if [[ $rc -eq 0 ]]; then echo "self-test: FAILED (accepted: $body)" >&2; fail=1; fi
  done
  # Other spellings of `uses` must be rejected even when the action is pinned and allowed.
  local raws=(
    "      - {uses: actions/checkout@$sha # v4.4.0}"
    "      - { name: x, uses: actions/checkout@$sha }"
    "      - {name: x, uses: actions/checkout@main}"
    "      - \"uses\": actions/checkout@$sha # v4.4.0"
    "      - 'uses': actions/checkout@$sha # v4.4.0"
    "      - uses : actions/checkout@$sha # v4.4.0"
    "    steps: [{uses: evil/thing@main}]"
  )
  for body in "${raws[@]}"; do
    i=$((i + 1))
    mkdir "$tmp/bad$i"
    printf 'jobs:\n  x:\n    steps:\n%s\n' "$body" > "$tmp/bad$i/b.yml"
    rc=0; check_dir "$tmp/bad$i" 2>/dev/null || rc=$?
    if [[ $rc -eq 0 ]]; then echo "self-test: FAILED (accepted: $body)" >&2; fail=1; fi
  done
  mkdir "$tmp/empty"
  rc=0; check_dir "$tmp/empty" 2>/dev/null || rc=$?
  if [[ $rc -eq 0 ]]; then echo "self-test: FAILED (empty dir accepted)" >&2; fail=1; fi
  if [[ $fail -eq 0 ]]; then
    echo "self-test: ok ($(( ${#bads[@]} + ${#raws[@]} )) bad forms rejected, good file accepted)"
    return 0
  fi
  return 1
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit $?
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
dir="${1:-$root/.github/workflows}"
if check_dir "$dir"; then
  echo "actions-pinned: ok"
else
  echo "actions-pinned: FAILED" >&2
  exit 1
fi
