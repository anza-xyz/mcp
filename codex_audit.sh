#!/usr/bin/env bash
set -euo pipefail

interval="${CODEX_AUDIT_INTERVAL:-60}"
upstream_branch=$(git remote show upstream | sed -n '/HEAD branch/s/.*: //p')
if [ -z "$upstream_branch" ]; then
  upstream_branch=main
fi

while true; do
  git fetch --all --prune

  last=$(rg -o --no-line-number "<!-- CODEX_LAST_AUDITED: ([0-9a-f]+) -->" -r '$1' codex.md 2>/dev/null | tail -n 1)
  if [ -n "$last" ] && git merge-base --is-ancestor "$last" HEAD; then
    new_commits=$(git rev-list --reverse "${last}..HEAD")
  else
    new_commits=$(git rev-list --reverse "upstream/${upstream_branch}..HEAD")
  fi

  if [ -n "$new_commits" ]; then
    echo "New commits detected since $last:"
    echo "$new_commits"
    exit 0
  fi

  sleep "$interval"
done
