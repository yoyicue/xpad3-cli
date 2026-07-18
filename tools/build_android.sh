#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

command -v cargo >/dev/null || {
  printf 'cargo is required\n' >&2
  exit 1
}
cargo ndk --help >/dev/null 2>&1 || {
  printf 'cargo-ndk is required: cargo install cargo-ndk\n' >&2
  exit 1
}

cargo test --all
cargo ndk -t arm64-v8a -P 33 build --release

binary="$ROOT/target/aarch64-linux-android/release/xpad3"
[[ -x "$binary" ]] || {
  printf 'Android binary missing: %s\n' "$binary" >&2
  exit 1
}
file "$binary" | grep -q 'ARM aarch64' || {
  printf 'refusing non-AArch64 output: %s\n' "$binary" >&2
  exit 1
}

printf 'XPAD3_ANDROID_BUILD_OK path=%s sha256=%s\n' \
  "$binary" "$(shasum -a 256 "$binary" | awk '{print $1}')"
