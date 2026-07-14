#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=$(awk -F '"' '/^version = / {print $2; exit}' "$ROOT/Cargo.toml")
DIST="$ROOT/dist"
tmp_dir=$(mktemp -d /tmp/xpad2-release-verify.XXXXXX)
trap 'rm -rf "$tmp_dir"' EXIT

(
  cd "$DIST"
  shasum -a 256 -c SHA256SUMS
)
unzip -q "$DIST/xpad2-cache-v$VERSION.zip" -d "$tmp_dir"
openssl dgst -sha256 -verify "$ROOT/keys/catalog-release-public.pem" \
  -signature "$tmp_dir/xpad2-cache/catalog.sig" \
  "$tmp_dir/xpad2-cache/catalog.json" >/dev/null

while IFS=$'\t' read -r id sha size; do
  blob="$tmp_dir/xpad2-cache/blobs/$sha"
  [[ -f "$blob" ]] || {
    printf 'cache blob missing: %s\n' "$id" >&2
    exit 1
  }
  [[ "$(wc -c < "$blob" | tr -d ' ')" == "$size" ]] || {
    printf 'cache blob size mismatch: %s\n' "$id" >&2
    exit 1
  }
  [[ "$(shasum -a 256 "$blob" | awk '{print $1}')" == "$sha" ]] || {
    printf 'cache blob SHA-256 mismatch: %s\n' "$id" >&2
    exit 1
  }
done < <(jq -r '.artifacts[] | select(.embedded == true) | [.id,.sha256,(.size|tostring)] | @tsv' "$tmp_dir/xpad2-cache/catalog.json")

file "$DIST/xpad2-v$VERSION-android-arm64" | grep -q 'ARM aarch64'
printf 'XPAD2_RELEASE_VERIFY_OK version=%s\n' "$VERSION"
