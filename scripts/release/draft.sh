#!/usr/bin/env bash
# Stage 19b: creates a DRAFT release with the files of `assemble` (unsigned). Never publishes.
#   TAG=v1.2.3 GH_TOKEN=... GITHUB_REPOSITORY=owner/repo bash scripts/release/draft.sh <release-dir>
# The owner then runs scripts/release/sign.sh and publishes by hand.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: draft.sh <release-dir>" >&2
  exit 2
fi
rel="$1"
tag="${TAG:?TAG is not set}"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"

if ! [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "draft: bad tag '$tag'" >&2
  exit 1
fi
[[ -f "$rel/chervo-release.txt" ]] || { echo "draft: no manifest in $rel" >&2; exit 1; }

notes="$(mktemp)"
trap 'rm -f "$notes"' EXIT
{
  echo "Черновик выпуска $tag. Собран в GitHub Actions из тега, файлы НЕ ПОДПИСАНЫ."
  echo
  echo "Состав: chervo (CLI) для linux-x86_64, macos-aarch64, macos-x86_64, windows-x86_64, SBOM (CycloneDX)"
  echo "и манифест chervo-release.txt (версия, коммит, SHA-256 и размеры файлов)."
  echo
  echo "- Подпись добавляет владелец вручную (scripts/release/sign.sh): chervo-release.txt.minisig и <файл>.minisig."
  echo "- Не публиковать до подписи, до прогона release-smoke.yml и до ручного чек-листа sign.sh."
  echo "- Linux: собрано на образе ubuntu-22.04; минимальная glibc равна версии на этом образе (см. сводку задания build)."
  echo "- macOS: на macOS не проверено; программа не подписана Apple, запуск по docs/INSTALL.md."
  echo "- SBOM один для chervo-cli, без выбора платформы."
  echo "- Побитовая воспроизводимость не заявляется (результат сравнения двух сборок Linux в сводке задания repro)."
} > "$notes"

files=( "$rel"/* )
gh release create "$tag" --repo "$repo" --draft --verify-tag --title "$tag" --notes-file "$notes" "${files[@]}"
echo "draft release $tag created (not published)"
