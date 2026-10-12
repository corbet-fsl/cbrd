#!/usr/bin/env bash
# Run the native owner gates; browser and coverage stay in verify.
set -euo pipefail
exec 2>&1
rustc --version
cargo metadata --locked --format-version 1 > dependency-metadata.json
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
