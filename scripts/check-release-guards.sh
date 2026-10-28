#!/usr/bin/env bash
# Stage 19b guards for the release pipeline (each rule has a negative case in --self-test).
#   bash scripts/check-release-guards.sh [repo-root]
#   bash scripts/check-release-guards.sh --self-test
#
# 1. build form (5a): no cargo command in release.yml / scripts/release/*.sh uses --workspace,
#    --all-targets, --all-features, --examples (test hooks and examples must not reach the release);
#    build-release.sh contains BOTH exact package-only build lines (chervo-cli and chervo-gui, one
#    cargo call each), and no cargo line has two `-p` (stage 19g: resolver 3 would merge the features).
# 2. release-smoke.yml (3a): no `gh release create|upload|edit|delete`, no `gh api`, `gh run` only as
#    `gh run list` or `gh run download` (stage 19g); the `tag` input only reaches the job through
#    `env:`, and is checked against the strict pattern.
# 3. workflows: no pull_request_target, no cache action, no secrets in the release workflows
#    (`secrets.`, `secrets[`, `secrets:`, `toJSON(secrets)`), persist-credentials: false after every
#    checkout, permissions: {} on top of the release workflows, any `<scope>: write` / `write-all`
#    only in the allowed job.
# 4. release-smoke.yml (review 19b, M1): the job `fetch` (the only one with write access) must not
#    run anything it downloaded; the job `check` (runs the downloaded binary) has `permissions: {}`.
#    The text check of `fetch` is BEST EFFORT (a regex over the lines, not a shell parser).
#    Stage 19g: the downloaded CI verifiers (`verifier-files/`) count as downloaded files too.
# 6. release.yml (stage 19g, R19g-11): the jobs `assemble` and `draft` never mention `verifier`: the CLI
#    builds for Windows/macOS must not reach the release files, the manifest or the draft.
set -euo pipefail

# Joins lines continued with a trailing backslash and drops comment-only lines.
logical_lines() {
  sed -e ':a' -e '/\\$/{N;s/\\\n/ /;ba' -e '}' -- "$1" | sed -e 's/\r$//' | grep -vE '^[[:space:]]*#' || true
}

# --- 1 ---
# Two package selectors in one line: `-p a ... -p b` or `--package a ... -p b`.
p_pair_re='(^|[[:space:]])(-p|--package)[[:space:]=].*[[:space:]](-p|--package)[[:space:]=]'

guard_build_form() { # files...
  local f bad=0 line
  for f in "$@"; do
    [[ -f "$f" ]] || { echo "missing file: $f" >&2; bad=1; continue; }
    while IFS= read -r line; do
      if [[ "$line" =~ (^|[^A-Za-z0-9_-])cargo[[:space:]] ]] &&
         [[ "$line" =~ (--workspace|--all-targets|--all-features|--examples|--example[[:space:]=]|--benches|--exclude) ]]; then
        echo "$f: forbidden cargo flag in: ${line#"${line%%[![:space:]]*}"}" >&2
        bad=1
      fi
      # Stage 19g: one package per cargo call.
      if [[ "$line" =~ (^|[^A-Za-z0-9_-])cargo[[:space:]] ]] && [[ "$line" =~ $p_pair_re ]]; then
        echo "$f: two -p in one cargo call: ${line#"${line%%[![:space:]]*}"}" >&2
        bad=1
      fi
    done < <(logical_lines "$f")
  done
  return "$bad"
}

guard_build_line() { # build-release.sh: BOTH package-only build lines (CLI and window)
  local f="$1" bad=0 want
  for want in 'cargo build --release --locked -p chervo-cli --bin chervo --target' \
              'cargo build --release --locked -p chervo-gui --bin chervotochina --target'; do
    if ! logical_lines "$f" | grep -qF "$want"; then
      echo "$f: package-only release build line not found: $want" >&2
      bad=1
    fi
  done
  return "$bad"
}

# --- 2 ---
guard_smoke_yml() { # release-smoke.yml
  local f="$1" bad=0 line rest sub matched
  [[ -f "$f" ]] || { echo "missing file: $f" >&2; return 1; }
  while IFS= read -r line; do
    if [[ "$line" =~ gh[[:space:]]+release[[:space:]]+(create|upload|edit|delete|delete-asset) ]] ||
       [[ "$line" =~ gh[[:space:]]+api([[:space:]]|$) ]] ||
       [[ "$line" =~ gh[[:space:]]+(workflow|secret|variable|repo)[[:space:]] ]]; then
      echo "$f: forbidden gh command: ${line#"${line%%[![:space:]]*}"}" >&2; bad=1
    fi
    # Stage 19g: `gh run` only as `list` and `download` (read-only); every occurrence on the line is checked.
    rest="$line"
    while [[ "$rest" =~ gh[[:space:]]+run([[:space:]]+([A-Za-z-]+))? ]]; do
      sub="${BASH_REMATCH[2]:-}"
      matched="${BASH_REMATCH[0]}"
      if [[ "$sub" != list && "$sub" != download ]]; then
        echo "$f: forbidden gh run command (only list and download): ${line#"${line%%[![:space:]]*}"}" >&2; bad=1
      fi
      rest="${rest#*"$matched"}"
    done
    if [[ "$line" == *'${{'*inputs* ]] &&
       ! [[ "$line" =~ ^[[:space:]]+[A-Z_]+:[[:space:]]+\$\{\{[[:space:]]*(github\.event\.)?inputs\.tag[[:space:]]*\}\}[[:space:]]*$ ]]; then
      echo "$f: input used outside an env: line: ${line#"${line%%[![:space:]]*}"}" >&2; bad=1
    fi
  done < <(logical_lines "$f")
  if ! grep -qF '^v[0-9]+\.[0-9]+\.[0-9]+$' "$f"; then
    echo "$f: strict tag pattern ^v[0-9]+\\.[0-9]+\\.[0-9]+\$ not found" >&2; bad=1
  fi
  return "$bad"
}

# --- 3 ---
guard_common() { # workflow files...
  local f bad=0 checkouts persists
  for f in "$@"; do
    [[ -f "$f" ]] || { echo "missing file: $f" >&2; bad=1; continue; }
    if logical_lines "$f" | grep -qE 'pull_request_target'; then
      echo "$f: pull_request_target is forbidden" >&2; bad=1
    fi
    if logical_lines "$f" | grep -qE 'actions/cache|restore-keys|^[[:space:]]+cache:'; then
      echo "$f: caches are forbidden" >&2; bad=1
    fi
    checkouts="$(logical_lines "$f" | grep -cE 'uses:[[:space:]]*actions/checkout@' || true)"
    persists="$(logical_lines "$f" | grep -cE 'persist-credentials:[[:space:]]*false[[:space:]]*$' || true)"
    if [[ "$checkouts" != "$persists" ]]; then
      echo "$f: $checkouts checkout(s) but $persists 'persist-credentials: false'" >&2; bad=1
    fi
  done
  return "$bad"
}

guard_no_secrets() { # workflow
  # Expression functions and context names are case-insensitive: -i.
  if logical_lines "$1" | grep -qiE 'secrets[[:space:]]*(\.|\[|:)|tojson\([[:space:]]*secrets'; then
    echo "$1: secrets are forbidden (Q1 = a: the key never leaves the owner)" >&2
    return 1
  fi
}

guard_release_yml() { # release.yml: strict
  local f="$1" bad=0
  [[ -f "$f" ]] || { echo "missing file: $f" >&2; return 1; }
  if logical_lines "$f" | grep -qE 'pull_request'; then
    echo "$f: pull_request* triggers are forbidden" >&2; bad=1
  fi
  guard_no_secrets "$f" || bad=1
  if ! logical_lines "$f" | grep -qE '^permissions:[[:space:]]*\{\}[[:space:]]*$'; then
    echo "$f: top-level 'permissions: {}' not found" >&2; bad=1
  fi
  guard_write_only_in "$f" draft || bad=1
  if ! logical_lines "$f" | grep -qF "github.event_name == 'push'"; then
    echo "$f: the draft job must be restricted to push events" >&2; bad=1
  fi
  return "$bad"
}

guard_smoke_perms() { # release-smoke.yml: top-level permissions
  local f="$1"
  if ! logical_lines "$f" | grep -qE '^permissions:[[:space:]]*\{\}[[:space:]]*$'; then
    echo "$f: top-level 'permissions: {}' not found" >&2
    return 1
  fi
}

# Any `<scope>: write` (contents, id-token, packages, ... also in flow form `{contents: write}`)
# and `write-all` are allowed only inside job $2; at the top level (before `jobs:`) never.
guard_write_only_in() {
  logical_lines "$1" | awk -v allowed="$2" -v file="$1" '
    /^jobs:/ { injobs = 1; next }
    injobs && /^  [A-Za-z0-9_-]+:[ \t]*$/ { job = $1; sub(":", "", job) }
    /(^|[ \t{,])[A-Za-z-]+:[ \t]*["'"'"']?write(-all)?(["'"'"' \t,}]|$)/ {
      if (job != allowed) { print file ": write permission outside job " allowed " (job=" job "): " $0 > "/dev/stderr"; bad = 1 }
    }
    END { exit bad }'
}

# Lines of job $2 (the part under `jobs:` with the 2-space job key $2), comments already dropped.
job_block() { # file job
  logical_lines "$1" | awk -v want="$2" '
    /^jobs:/ { injobs = 1; next }
    injobs && /^  [A-Za-z0-9_-]+:[ \t]*$/ { job = $1; sub(":", "", job); next }
    job == want { print }'
}

# The job $2 must exist, have `permissions: {}` and no other permissions key or contents: line.
guard_job_no_perms() { # file job
  local f="$1" j="$2" block line ok=0 bad=0
  block="$(job_block "$f" "$j")"
  [[ -n "$block" ]] || { echo "$f: job $j not found" >&2; return 1; }
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]{4}permissions:[[:space:]]*\{\}[[:space:]]*$ ]]; then
      ok=1
    elif [[ "$line" =~ permissions: ]] || [[ "$line" =~ (^|[^A-Za-z-])contents: ]]; then
      echo "$f: job $j must have exactly 'permissions: {}': ${line#"${line%%[![:space:]]*}"}" >&2; bad=1
    fi
  done <<<"$block"
  [[ $ok -eq 1 ]] || { echo "$f: job $j has no 'permissions: {}'" >&2; bad=1; }
  return "$bad"
}

# The job that holds write access must not run anything it downloaded. BEST EFFORT, by text:
# no chmod/eval/exec/source, no interpreter or build tool, no `./` command, no path under the
# download directory (`draft-files/...`) outside an artifact `path:` line.
guard_fetch_no_exec() { # file job
  local f="$1" j="$2" line bad=0
  local cmd_re='(^|[;&|(`{[:space:]])(chmod|eval|exec|source|bash|sh|zsh|dash|python3?|perl|ruby|node|pwsh|powershell|cargo|rustc|make|java|wine|xargs)([[:space:]]|$)'
  local dot_re='(^|[;&|(`{[:space:]"'"'"'])\.{1,2}/|(^|[;&|(`{[:space:]])\.[[:space:]]'
  local dir_re='(draft-files|verifier-files)["'"'"']?/'
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*shell: ]] && continue
    [[ "$line" =~ ^[[:space:]]*(-[[:space:]]+)?path: ]] && continue
    if [[ "$line" =~ $cmd_re ]] || [[ "$line" =~ $dot_re ]] || [[ "$line" =~ $dir_re ]]; then
      echo "$f: job $j seems to run or touch downloaded files: ${line#"${line%%[![:space:]]*}"}" >&2; bad=1
    fi
  done < <(job_block "$f" "$j")
  return "$bad"
}

# --- 6 --- (stage 19g, R19g-11) the jobs assemble and draft of release.yml never mention `verifier`.
guard_no_verifier_in_release() { # release.yml
  local f="$1" j block bad=0
  [[ -f "$f" ]] || { echo "missing file: $f" >&2; return 1; }
  for j in assemble draft; do
    block="$(job_block "$f" "$j")"
    if [[ -z "$block" ]]; then
      echo "$f: job $j not found" >&2; bad=1; continue
    fi
    if grep -qi 'verifier' <<<"$block"; then
      echo "$f: job $j mentions 'verifier' (the CI verifier must not reach the release)" >&2; bad=1
    fi
  done
  return "$bad"
}

run_all() {
  local root="$1" bad=0 wf="$1/.github/workflows"
  guard_build_form "$wf/release.yml" "$root"/scripts/release/*.sh || bad=1
  guard_build_line "$root/scripts/release/build-release.sh" || bad=1
  guard_smoke_yml "$wf/release-smoke.yml" || bad=1
  guard_smoke_perms "$wf/release-smoke.yml" || bad=1
  guard_common "$wf"/*.yml || bad=1
  guard_release_yml "$wf/release.yml" || bad=1
  guard_no_verifier_in_release "$wf/release.yml" || bad=1
  guard_no_secrets "$wf/release-smoke.yml" || bad=1
  # release-smoke may hold write access (draft visibility) in `fetch` only; `fetch` runs nothing
  # downloaded; `check` (runs the downloaded binary) has no permissions at all.
  guard_write_only_in "$wf/release-smoke.yml" fetch || bad=1
  guard_fetch_no_exec "$wf/release-smoke.yml" fetch || bad=1
  guard_job_no_perms "$wf/release-smoke.yml" check || bad=1
  return "$bad"
}

expect() { # name expected-rc command...
  local name="$1" want="$2" rc=0
  shift 2
  "$@" >/dev/null 2>&1 || rc=$?
  if [[ "$rc" != "$want" ]]; then
    echo "self-test: FAILED ($name: rc=$rc, expected $want)" >&2
    SELF_FAIL=1
  fi
}

# subst TEXT PATTERN REPLACEMENT -> TEXT with the first literal PATTERN replaced (stdout, no newline added).
subst() {
  printf '%s' "${1/"$2"/"$3"}"
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  SELF_FAIL=0
  local f

  # 1. build form
  local cli_line='cargo build --release --locked -p chervo-cli --bin chervo --target x'
  local gui_line='cargo build --release --locked -p chervo-gui --bin chervotochina --target x'
  f="$tmp/ok.sh";   printf '#!/bin/bash\n# never cargo build --workspace\n%s\n%s\ncargo tree --locked -e no-dev,features -p chervo-cli\ncargo tree --locked -e no-dev,features -p chervo-gui\n' "$cli_line" "$gui_line" > "$f"
  expect build-ok 0 guard_build_form "$f"
  expect build-line-ok 0 guard_build_line "$f"
  f="$tmp/b6.sh";   printf '%s\n' "$cli_line" > "$f"
  expect build-line-gui-missing 1 guard_build_line "$f"
  f="$tmp/b6b.sh";  printf '%s\n' "$gui_line" > "$f"
  expect build-line-cli-missing 1 guard_build_line "$f"
  f="$tmp/b7.sh";   printf 'cargo build --release --locked -p chervo-cli -p chervo-gui --target x\n' > "$f"
  expect build-two-packages 1 guard_build_form "$f"
  f="$tmp/b8.sh";   printf '      - run: cargo test -p chervo-cli \\\n          -p chervo-gui\n' > "$f"
  expect build-two-packages-continued 1 guard_build_form "$f"
  f="$tmp/b9.sh";   printf 'cargo build --package chervo-cli -p chervo-gui\n' > "$f"
  expect build-two-packages-long-form 1 guard_build_form "$f"
  f="$tmp/b1.sh";   printf 'cargo build --release --workspace\n' > "$f"
  expect build-workspace 1 guard_build_form "$f"
  f="$tmp/b2.sh";   printf 'cargo build --release \\\n  --all-targets\n' > "$f"
  expect build-continued-all-targets 1 guard_build_form "$f"
  f="$tmp/b3.sh";   printf '      - run: cargo test --all-features\n' > "$f"
  expect build-all-features 1 guard_build_form "$f"
  f="$tmp/b4.sh";   printf 'cargo build -p chervo-cli --examples\n' > "$f"
  expect build-examples 1 guard_build_form "$f"
  f="$tmp/b5.sh";   printf 'cargo build --release -p chervo-cli\n' > "$f"
  expect build-line-missing 1 guard_build_line "$f"

  # 2. release-smoke.yml
  local good='on:
  workflow_dispatch:
    inputs:
      tag: {required: true}
permissions: {}
jobs:
  fetch:
    permissions:
      contents: write
    steps:
      - run: |
          [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
          gh release download "$TAG" --dir draft-files
          ls -l draft-files
          gh run list --repo x --workflow release.yml --json databaseId
          gh run download 1 --repo x -n verifier-macos-aarch64 -D verifier-files
        env:
          TAG: ${{ inputs.tag }}
        shell: bash
      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567 # v4.6.2
        with:
          path: draft-files/*
  check:
    needs: [fetch]
    permissions: {}
    steps:
      - run: bash tools/scripts/release/release-smoke.sh draft-files linux-x86_64 ""
'
  f="$tmp/s0.yml"; printf '%s' "$good" > "$f"
  expect smoke-ok 0 guard_smoke_yml "$f"
  expect smoke-perms-ok 0 guard_smoke_perms "$f"
  expect smoke-write-job-ok 0 guard_write_only_in "$f" fetch
  expect smoke-fetch-no-exec-ok 0 guard_fetch_no_exec "$f" fetch
  expect smoke-check-no-perms-ok 0 guard_job_no_perms "$f" check
  expect smoke-no-secrets-ok 0 guard_no_secrets "$f"
  # M1: the job with write access runs nothing it downloaded.
  local marker='          gh release download "$TAG" --dir draft-files' bad
  for bad in 'chmod +x draft-files/chervo-0.1.0-linux-x86_64' 'draft-files/chervo-0.1.0-linux-x86_64 --version' \
             'chmod +x verifier-files/x' 'verifier-files/chervo-verifier-0.1.0-windows-x86_64.exe --version' './verifier-files/x' \
             './draft-files/x' 'bash draft-files/x.sh' 'python3 -I draft-files/x.py' 'source draft-files/env' \
             'eval "$(cat draft-files/x)"' '. draft-files/x' 'cargo run' 'xargs -0 sh' '(cd draft-files && ../tool)'; do
    f="$tmp/m1.yml"; subst "$good" "$marker" "$marker"$'\n'"          $bad" > "$f"
    expect "smoke-fetch-exec[$bad]" 1 guard_fetch_no_exec "$f" fetch
  done
  # M1: write access only in `fetch`; `check` has exactly `permissions: {}`.
  local chk=$'    needs: [fetch]\n    permissions: {}'
  f="$tmp/m2.yml"; subst "$good" "$chk" $'    needs: [fetch]\n    permissions:\n      contents: write' > "$f"
  expect smoke-check-write 1 guard_write_only_in "$f" fetch
  expect smoke-check-write-perms 1 guard_job_no_perms "$f" check
  f="$tmp/m3.yml"; subst "$good" "$chk" '    needs: [fetch]' > "$f"
  expect smoke-check-no-perms 1 guard_job_no_perms "$f" check
  f="$tmp/m4.yml"; subst "$good" '    permissions: {}' $'    permissions:\n      contents: read' > "$f"
  expect smoke-check-read 1 guard_job_no_perms "$f" check
  expect smoke-check-job-missing 1 guard_job_no_perms "$f" nosuchjob
  # L7: every kind of write permission outside the allowed job, and the secrets forms.
  local w
  for w in 'permissions: write-all' 'permissions: {contents: write}' 'id-token: write' 'packages: write' 'actions: "write"'; do
    f="$tmp/l7.yml"; subst "$good" "$chk" $'    needs: [fetch]\n    '"$w" > "$f"
    expect "write-outside[$w]" 1 guard_write_only_in "$f" fetch
  done
  f="$tmp/l7top.yml"; subst "$good" $'permissions: {}\njobs:' $'permissions: write-all\njobs:' > "$f"
  expect write-all-top-level 1 guard_write_only_in "$f" fetch
  for w in '${{ secrets.KEY }}' "\${{ secrets['KEY'] }}" '${{ toJSON(secrets) }}' '${{ ToJson( Secrets ) }}' '${{ SECRETS.KEY }}' 'secrets: inherit'; do
    f="$tmp/l7s.yml"; { printf '%s' "$good"; printf '      - run: echo %s\n' "$w"; } > "$f"
    expect "secrets-form[$w]" 1 guard_no_secrets "$f"
  done
  local cmd
  for cmd in 'gh release upload "$TAG" x' 'gh release create "$TAG"' 'gh release edit "$TAG"' 'gh release delete "$TAG"' 'gh api repos/x/y' 'gh workflow run x' \
             'gh run rerun 1' 'gh run cancel 1' 'gh run delete 1' 'gh run watch 1' 'gh run view 1' 'gh run' \
             'gh run list --repo x; gh run rerun 1'; do
    f="$tmp/s1.yml"; { printf '%s' "$good"; printf '      - run: %s\n' "$cmd"; } > "$f"
    expect "smoke-bad[$cmd]" 1 guard_smoke_yml "$f"
  done
  f="$tmp/s2.yml"; { printf '%s' "$good"; printf '      - run: echo ${{ inputs.tag }}\n'; } > "$f"
  expect smoke-input-in-run 1 guard_smoke_yml "$f"
  f="$tmp/s3.yml"; printf '%s' "${good//'^v[0-9]+\.[0-9]+\.[0-9]+$'/x}" > "$f"
  expect smoke-no-tag-pattern 1 guard_smoke_yml "$f"
  f="$tmp/s4.yml"; printf '%s' "${good/permissions: \{\}/}" > "$f"
  expect smoke-no-top-perms 1 guard_smoke_perms "$f"

  # 6. the verifier must not reach assemble / draft (R19g-11)
  local asm='jobs:
  build:
    steps:
      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567 # v4.6.2
        with:
          name: verifier-linux-x86_64
  assemble:
    steps:
      - uses: actions/download-artifact@0123456789abcdef0123456789abcdef01234567 # v4.3.0
        with:
          pattern: bin-*
  draft:
    steps:
      - run: bash scripts/release/draft.sh release
'
  f="$tmp/v0.yml"; printf '%s' "$asm" > "$f"
  expect verifier-rule-ok 0 guard_no_verifier_in_release "$f"
  f="$tmp/v1.yml"; subst "$asm" 'pattern: bin-*' 'name: verifier-linux-x86_64' > "$f"
  expect verifier-in-assemble 1 guard_no_verifier_in_release "$f"
  f="$tmp/v2.yml"; subst "$asm" 'draft.sh release' 'draft.sh release verifier' > "$f"
  expect verifier-in-draft 1 guard_no_verifier_in_release "$f"
  f="$tmp/v3.yml"; subst "$asm" 'pattern: bin-*' 'pattern: Verifier-*' > "$f"
  expect verifier-in-assemble-mixed-case 1 guard_no_verifier_in_release "$f"
  f="$tmp/v4.yml"; subst "$asm" '  assemble:' '  assemble2:' > "$f"
  expect verifier-rule-job-missing 1 guard_no_verifier_in_release "$f"

  # 3. common and release.yml
  local rel='on:
  push:
    tags: ["v[0-9]+.[0-9]+.[0-9]+"]
permissions: {}
jobs:
  build:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v4.4.0
        with:
          persist-credentials: false
  draft:
    if: github.event_name == '"'push'"'
    permissions:
      contents: write
    steps:
      - run: echo
'
  f="$tmp/r0.yml"; printf '%s' "$rel" > "$f"
  expect release-ok 0 guard_release_yml "$f"
  expect common-ok 0 guard_common "$f"
  f="$tmp/r1.yml"; printf '%s' "${rel/push:/pull_request_target:}" > "$f"
  expect common-pr-target 1 guard_common "$f"
  f="$tmp/r2.yml"; printf '%s' "${rel/persist-credentials: false/persist-credentials: true}" > "$f"
  expect common-persist-credentials 1 guard_common "$f"
  f="$tmp/r3.yml"; { printf '%s' "$rel"; printf '      - uses: actions/cache@0123456789abcdef0123456789abcdef01234567 # v4.0.0\n'; } > "$f"
  expect common-cache 1 guard_common "$f"
  f="$tmp/r4.yml"; printf '%s' "${rel/contents: read/contents: write}" > "$f"
  expect release-write-outside-draft 1 guard_release_yml "$f"
  f="$tmp/r5.yml"; printf '%s' "${rel/permissions: \{\}/}" > "$f"
  expect release-no-top-perms 1 guard_release_yml "$f"
  f="$tmp/r6.yml"; { printf '%s' "$rel"; printf '      - run: echo ${{ secrets.KEY }}\n'; } > "$f"
  expect release-secrets 1 guard_release_yml "$f"
  f="$tmp/r7.yml"; printf '%s' "${rel/push:/pull_request:}" > "$f"
  expect release-pull-request 1 guard_release_yml "$f"
  f="$tmp/r8.yml"; printf '%s' "${rel/github.event_name == \'push\'/true}" > "$f"
  expect release-draft-not-push-only 1 guard_release_yml "$f"
  f="$tmp/r9.yml"; subst "$rel" 'contents: read' 'id-token: write' > "$f"
  expect release-other-write-outside-draft 1 guard_release_yml "$f"
  f="$tmp/r10.yml"; subst "$rel" 'contents: read' 'permissions: write-all' > "$f"
  expect release-write-all-outside-draft 1 guard_release_yml "$f"
  f="$tmp/r11.yml"; { printf '%s' "$rel"; printf "      - run: echo \${{ secrets['KEY'] }}\n"; } > "$f"
  expect release-secrets-bracket 1 guard_release_yml "$f"
  f="$tmp/r12.yml"; { printf '%s' "$rel"; printf '      - run: echo ${{ toJSON(secrets) }}\n'; } > "$f"
  expect release-secrets-tojson 1 guard_release_yml "$f"

  if [[ $SELF_FAIL -eq 0 ]]; then
    echo "self-test: ok"
    return 0
  fi
  return 1
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit $?
fi

root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
if run_all "$root"; then
  echo "release-guards: ok"
else
  echo "release-guards: FAILED" >&2
  exit 1
fi
