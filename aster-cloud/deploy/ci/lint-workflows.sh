#!/usr/bin/env bash
# Shared local/CI entry: actionlint must not silently omit shell diagnostics.
set -euo pipefail
[[ $# == 0 ]] || { echo 'WORKFLOW_LINT_ARGUMENTS_REFUSED' >&2; exit 1; }
command -v shellcheck >/dev/null || { echo 'WORKFLOW_LINT_REQUIRES_SHELLCHECK' >&2; exit 1; }
command -v go >/dev/null || { echo 'WORKFLOW_LINT_REQUIRES_GO' >&2; exit 1; }
shellcheck --version
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
cd "$repo"
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 .github/workflows/ci.yml .github/workflows/install-download-check.yml
