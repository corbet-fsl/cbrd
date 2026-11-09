#!/usr/bin/env bash
# .ci/verify.sh for cbrd — ports ALL Linux verification gates from
# .github/workflows/ci.yml (resolve selftest, dependency-policy, check,
# coverage incl. native + wasm browser coverage) in full ordering,
# environment, and flags.
set -euo pipefail
exec 2>&1
CBRD_LAST_GATE="init"
trap 'rc=$?; echo "CBRD-DIAG last_gate=$CBRD_LAST_GATE exit=$rc" >&2; exit $rc' EXIT
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_OUTPUT="${GITHUB_OUTPUT:-$RUNNER_TEMP/github_output.txt}"
touch "$GITHUB_OUTPUT"

# A C compiler covers lock-evidenced cc edges (blake3 in native tests);
# the Ubuntu image supplies gcc, the job supplies pinned clang (cc wrapper).
command -v cc >/dev/null || { echo 'missing cc for lock-evidenced cc edges' >&2; exit 2; }
# Wasm target on stable is guaranteed by run-cached.sh (helper readiness +
# exclusive provisioning); no toolchain mutation here under the shared lock.

# --- resolve pure selftest + dependency-policy (no deny gate in CI) ---
CBRD_LAST_GATE="resolve-first-party"
python3 .ci/check-first-party.py

# --- check job (stable) in exact CI order ---
CBRD_LAST_GATE="fmt"
bash .ci/update-our-crates.sh
cargo fmt --all
CBRD_LAST_GATE="fmt-gate"
git diff -- src tests examples > formatting.patch
test ! -s formatting.patch
CBRD_LAST_GATE="clippy"
cargo clippy --locked --all-targets -- -D warnings
CBRD_LAST_GATE="native-tests"
cargo test --locked --all-targets
command -v wasm-pack >/dev/null || { echo 'missing wasm-pack' >&2; exit 2; }
# CI consumes the runner-image chromedriver; the job runtime supplies the
# paired pinned nix chromium+chromedriver via CHROMEDRIVER/CHROME_BIN.
export CHROMEDRIVER="${CHROMEDRIVER:-$(command -v chromedriver)}"
export CHROME_BIN="${CHROME_BIN:-$(command -v chromium)}"
test -x "$CHROMEDRIVER" || { echo "missing chromedriver at $CHROMEDRIVER" >&2; exit 2; }
test -x "$CHROME_BIN" || { echo "missing chromium at $CHROME_BIN" >&2; exit 2; }
# Stock runners discover a google-chrome binary; link the pinned chromium
# under that name job-locally so discovery is deterministic.
mkdir -p "$RUNNER_TEMP/bin"
ln -sf "$CHROME_BIN" "$RUNNER_TEMP/bin/google-chrome"
export PATH="$RUNNER_TEMP/bin:$PATH"
CBRD_LAST_GATE="wasm-pack"
# minicov's build script hardcodes `clang` (CC env is ignored) and the default
# nix `clang` is a multi-target wrapper injecting host glibc includes, which
# breaks its wasm32 C build. Resolve `clang` to the pinned unwrapped compiler
# for this leg only: the subshell keeps native builds and nightly coverage on
# the provisioned wrapper toolchain.
: "${CBRD_WASM_CLANG_BIN:?Missing unwrapped wasm clang from run-cached.sh}"
(
export PATH="$CBRD_WASM_CLANG_BIN:$PATH"
wasm-pack test --headless --chrome -- --locked
)

# --- coverage job, native (nightly only) ---
CBRD_LAST_GATE="nightly-select"
# Select nightly exactly as CI's nightly job does; every bare cargo/rustc
# below resolves nightly via RUSTC/CARGO/PATH/RUSTUP_TOOLCHAIN.
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
CBRD_LAST_GATE="native-coverage"
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --branch --all-targets --json --output-path coverage.json --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --lcov --output-path coverage.lcov --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --text --output-path coverage.txt --ignore-filename-regex '/tests/'
CBRD_LAST_GATE="native-coverage-check"
python3 .ci/test-source-coverage.py
python3 .ci/check-source-coverage.py coverage.lcov coverage.json coverage.txt

# --- coverage job, browser wasm (nightly only) ---
CBRD_LAST_GATE="wasm-nightly-select"
# Re-select nightly in this scope so bare rustc/cargo below resolve nightly
# exactly as in CI's nightly coverage job.
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
# Wasm target on nightly is guaranteed by run-cached.sh (helper readiness +
# exclusive provisioning); no toolchain mutation here under the shared lock.
CBRD_LAST_GATE="wasm-coverage-env"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="-Zno-profiler-runtime -Clink-args=--no-gc-sections --cfg=owned_browser_coverage"
export WASM_BINDGEN_TEST_ONLY_WEB="1"
export WASM_BINDGEN_SPLIT_LINKED_MODULES="1"
export CC_wasm32_unknown_unknown="$CBRD_WASM_CLANG"
rustc --version --verbose
"$NIGHTLY_CARGO" llvm-cov --version
clang --version
command -v clang >/dev/null || { echo 'missing clang' >&2; exit 2; }
test -x "$CHROMEDRIVER" || { echo "missing chromedriver at $CHROMEDRIVER" >&2; exit 2; }
# Binding version from the committed lock (adapts CI's GITHUB_OUTPUT step);
# install the matching prebuilt runner job-locally, as CI's install-action
# does, with checksum verification.
CBRD_LAST_GATE="wasm-runner-provision"
python3 - <<'PYCODE'
import os, tomllib
packages = tomllib.load(open('Cargo.lock', 'rb'))['package']
version = next(p['version'] for p in packages if p['name'] == 'wasm-bindgen')
with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
    f.write('version=' + version + '\n')
PYCODE
binding_version=$(sed -n 's/^version=//p' "$GITHUB_OUTPUT" | tail -n 1)
test -n "$binding_version" || { echo 'could not resolve wasm-bindgen version from Cargo.lock' >&2; exit 2; }
echo "$binding_version" > binding-version.txt
archive="wasm-bindgen-${binding_version}-x86_64-unknown-linux-musl.tar.gz"
base="${WASM_BINDGEN_DOWNLOAD_BASE:-https://github.com/wasm-bindgen/wasm-bindgen/releases/download}/${binding_version}"
mkdir -p "$RUNNER_TEMP/wasm-runner"
cd "$RUNNER_TEMP/wasm-runner"
CBRD_LAST_GATE="wasm-runner-fetch"
curl --fail --location --retry 3 --remote-name "$base/$archive"
curl --fail --location --retry 3 --remote-name "$base/$archive.sha256sum"
checksum=$(cut -d ' ' -f1 "$archive.sha256sum")
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check
tar -xzf "$archive" --strip-components=1
export PATH="$PWD:$PATH"
cd - > /dev/null
wasm-bindgen --version | grep -q "$binding_version" || { echo 'wasm runner version mismatch' >&2; exit 2; }
# Python environment: requirements.txt pins exactly `selenium>=4`; the runner
# supplies it through a pinned python3.withPackages environment, so the
# import below succeeds without network. The pip install stays as the CI
# fallback.
python3 -c 'import selenium; print(selenium.__version__)' || python3 -m pip install -r .ci/requirements.txt
# browser-coverage-runner.py hardcodes Service("/usr/bin/chromedriver") and
# sets no binary_location. Adapt exactly those two narrowly-checked facts in
# a job-temp copy: driver service path -> $CHROMEDRIVER, and binary_location
# -> $CHROME_BIN (resolved pinned chromium executable). Any other source
# drift fails the gate; Chrome options and all tests are preserved byte for
# byte (diff audit: exactly one removed line, two added lines).
: "${CHROME_BIN:?Missing resolved chromium executable from run-cached.sh}"
test -x "$CHROME_BIN" || { echo "chromium not executable at $CHROME_BIN" >&2; exit 2; }
CBRD_LAST_GATE="wasm-runner-adapt"
runner_src=.ci/browser-coverage-runner.py
runner_copy="$RUNNER_TEMP/browser-coverage-runner.py"
anchor_hits=$(grep -cF 'driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=options)' "$runner_src" || true)
test "$anchor_hits" -eq 1
existing_binary_location=$(grep -cF 'binary_location' "$runner_src" || true)
test "$existing_binary_location" -eq 0
python3 - "$runner_src" "$runner_copy" "$CHROMEDRIVER" "$CHROME_BIN" <<'PYEOF'
import sys
src, dst, driver, chrome = sys.argv[1:5]
text = open(src).read()
anchor = 'driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=options)'
assert text.count(anchor) == 1, 'runner driver-construction text drifted'
replacement = 'options.binary_location = "' + chrome + '"\n        driver = webdriver.Chrome(service=Service("' + driver + '"), options=options)'
open(dst, 'w').write(text.replace(anchor, replacement))
PYEOF
drift_removed=$(diff "$runner_src" "$runner_copy" | grep -c '^<' || true)
drift_added=$(diff "$runner_src" "$runner_copy" | grep -c '^>' || true)
test "$drift_removed" -eq 1
test "$drift_added" -eq 2
grep -F "$CHROMEDRIVER" "$runner_copy"
grep -F "$CHROME_BIN" "$runner_copy"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="python3 $runner_copy"
CBRD_LAST_GATE="wasm-coverage"
: "${CBRD_WASM_CLANG_BIN:?Missing unwrapped wasm clang from run-cached.sh}"
(
export PATH="$CBRD_WASM_CLANG_BIN:$PATH"
"$NIGHTLY_CARGO" llvm-cov test --locked --branch --coverage-target-only --target wasm32-unknown-unknown --test board --json --output-path wasm-coverage.json --ignore-filename-regex '/tests/'
)
CBRD_LAST_GATE="wasm-coverage-report"
"$NIGHTLY_CARGO" llvm-cov report --target wasm32-unknown-unknown --lcov --output-path wasm-coverage.lcov --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --target wasm32-unknown-unknown --text --output-path wasm-coverage.txt --ignore-filename-regex '/tests/'
)
CBRD_LAST_GATE="wasm-coverage-check"
python3 .ci/check-source-coverage.py wasm-coverage.lcov wasm-coverage.json wasm-coverage.txt wasm
