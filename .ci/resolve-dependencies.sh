#!/usr/bin/env bash
# Resolve explicit upstream changes; this job does not claim validation.
set -euo pipefail
exec 2>&1
: "${ARTIFACT_ROOT:?Missing retained artifact destination}"
cargo update
cp Cargo.lock "$ARTIFACT_ROOT/resolve-dependencies-Cargo.lock"
sha256sum Cargo.lock
echo '---LOCK-BEGIN---'
cat Cargo.lock
echo '---LOCK-END---'
echo 'Resolved dependency locks only; retain them in a commit and run verify.'
