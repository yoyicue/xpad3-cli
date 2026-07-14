#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LOCK="$ROOT/sources.lock.json"

for command in curl git jq; do
  command -v "$command" >/dev/null || {
    printf 'required command not found: %s\n' "$command" >&2
    exit 1
  }
done

jq -e '
  .schema == 1 and
  (.sources | length > 0) and
  all(.sources[];
    (.component | type == "string" and length > 0) and
    (.repository | test("^https://github\\.com/[^/]+/[^/]+$")) and
    (.tag | type == "string" and length > 0) and
    (.commit | test("^[0-9a-f]{40}$")) and
    (.license | type == "string" and length > 0)
  )
' "$LOCK" >/dev/null || {
  printf 'invalid source lock: every component needs a canonical GitHub URL, tag, commit and license\n' >&2
  exit 1
}

verified=0
while IFS=$'\t' read -r repository tag expected; do
  slug=${repository#https://github.com/}
  canonical=$(curl --fail --silent --show-error --location \
    -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/$slug" | jq -r '.html_url')
  [[ "$canonical" == "$repository" ]] || {
    printf 'non-canonical or renamed repository: locked=%s canonical=%s\n' \
      "$repository" "$canonical" >&2
    exit 1
  }

  refs=$(git ls-remote --tags "$repository" \
    "refs/tags/$tag" "refs/tags/$tag^{}")
  resolved=$(printf '%s\n' "$refs" |
    awk -v ref="refs/tags/$tag^{}" '$2 == ref { print $1; exit }')
  if [[ -z "$resolved" ]]; then
    resolved=$(printf '%s\n' "$refs" |
      awk -v ref="refs/tags/$tag" '$2 == ref { print $1; exit }')
  fi
  [[ -n "$resolved" ]] || {
    printf 'source tag not found: %s %s\n' "$repository" "$tag" >&2
    exit 1
  }
  [[ "$resolved" == "$expected" ]] || {
    printf 'source identity mismatch: %s %s expected=%s actual=%s\n' \
      "$repository" "$tag" "$expected" "$resolved" >&2
    exit 1
  }

  printf 'SOURCE_OK repository=%s tag=%s commit=%s\n' \
    "$repository" "$tag" "$resolved"
  verified=$((verified + 1))
done < <(jq -r '.sources[] | [.repository, .tag, .commit] | @tsv' "$LOCK" | sort -u)

printf 'XPAD2_SOURCES_VERIFY_OK entries=%s\n' "$verified"
