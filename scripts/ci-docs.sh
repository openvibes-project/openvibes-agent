#!/usr/bin/env bash
# Is this change docs only? Changed files on stdin; prints docs=true when every
# file is Markdown (*.md), else docs=false. No files listed (a diff that could
# not be made) is not docs: everything runs. The "Choose test tiers" job in
# ci.yml uses it; cases are in scripts/test-ci-docs.sh.
set -euo pipefail
changed=$(cat)
if [[ -n $changed ]] && ! grep -qvE '\.md$' <<<"$changed"; then
    echo docs=true
else
    echo docs=false
fi
