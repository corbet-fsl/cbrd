#!/usr/bin/env bash
# Execute the manifest's selected checks with content-keyed result reuse.
set -euo pipefail
exec 2>&1
: "${CCID_BIN:?Missing verified ccid job runtime}"
: "${CI_COMMIT_SHA:?Missing verified source revision}"
: "${CI_REPOSITORY_URL:?Missing canonical repository identity}"
: "${CHECKS:?Missing declared check selection}"
if [ "$CHECKS" != "verify" ]; then
  echo "CHECKS must be exactly 'verify', got: $CHECKS" >&2
  exit 2
fi
cache_root=${CI_CACHE_ROOT:-${CARGO_HOME:-}}
[[ $cache_root = /* ]] || { echo 'An absolute persistent CI_CACHE_ROOT or CARGO_HOME is required' >&2; exit 2; }
namespace=$(printf '%s' "$CI_REPOSITORY_URL" | sha256sum | cut -c1-24)
state="$cache_root/ccid-cached/$namespace"
toolchains=${CI_TOOLCHAIN_ROOT:-$cache_root/ccid-cached/toolchains}
[[ $toolchains = /* ]] || { echo 'CI_TOOLCHAIN_ROOT must be absolute' >&2; exit 2; }
mkdir -p "$state" "$toolchains"
exec 9>"$state/lock"
flock -w "${CI_TIMEOUT:-2700}" 9
mkdir -p "$state/moon-cache/hashes" "$state/moon-cache/outputs" "$state/moon-home"
mkdir -p .moon/cache
# Tool installation is an explicit part of this job, in persistent CI storage.
# No Node: CI runs no node steps. curl fetches the lock-matched prebuilt wasm
# runner (see verify.sh); requirements.txt pins exactly `selenium>=4`.
tool_source=github:NixOS/nixpkgs/b7c2ada94fe99c15b0dbcf4d11fd7850b957a436?narHash=sha256-IItrdb7Puk05RqOBWZYFC5X6Wl1sJmCfh5MWVHw5iMM=
tool_paths=$(nix build --no-link --print-out-paths "$tool_source#moon" "$tool_source#proto" "$tool_source#python3" "$tool_source#cargo-llvm-cov" "$tool_source#wasm-pack" "$tool_source#clang" "$tool_source#curl" "$tool_source#chromedriver" "$tool_source#chromium")
for path in $tool_paths; do PATH="$path/bin:$PATH"; done
# minicov's build script hardcodes `clang`, so the wasm32 C build uses whatever
# `clang` resolves on PATH. Resolve the pinned unwrapped compiler here (actual
# closure path from Nix at runtime, never a hardcoded store path) and export
# it for the cache fingerprint + the wasm-pack leg in verify.sh. It stays off
# the global PATH so native builds and nightly coverage keep the wrapper.
CBRD_WASM_CLANG_BIN=""
for out in $(nix build --no-link --print-out-paths "$tool_source#llvmPackages.clang-unwrapped"); do
  if [ -x "$out/bin/clang" ]; then CBRD_WASM_CLANG_BIN="$out/bin"; fi
done
test -n "$CBRD_WASM_CLANG_BIN" || { echo 'pinned unwrapped clang provides no bin/clang' >&2; exit 2; }
export CBRD_WASM_CLANG_BIN
export CBRD_WASM_CLANG="$CBRD_WASM_CLANG_BIN/clang"
"$CBRD_WASM_CLANG" --version
# requirements.txt pins exactly `selenium>=4`; build a pinned
# python3.withPackages environment carrying selenium as a transitive input,
# so the gate needs no PyPI round trip and no hand-rolled PYTHONPATH.
# Same nixpkgs revision as tool_source (tarball form of the pinned flake).
selenium_python=$(nix build --no-link --print-out-paths --impure --expr "let pkgs = import (builtins.fetchTarball { url = \"https://github.com/NixOS/nixpkgs/archive/b7c2ada94fe99c15b0dbcf4d11fd7850b957a436.tar.gz\"; sha256 = \"sha256-IItrdb7Puk05RqOBWZYFC5X6Wl1sJmCfh5MWVHw5iMM=\"; }) {}; in (pkgs.python3.withPackages (ps: [ ps.selenium ps.pip ]))")
PATH="$selenium_python/bin:$PATH"
export PROTO_HOME="$toolchains/proto"
export MOON_HOME="$state/moon-home"
export PROTO_AUTO_CLEAN=false PROTO_TELEMETRY=false PROTO_YES=true
export RUSTUP_INIT_SKIP_PATH_CHECK=yes RUSTUP_TOOLCHAIN=stable
export PATH="$(dirname "$CCID_BIN"):$PROTO_HOME/shims:$PROTO_HOME/bin:$PATH"
export CI_JOBS="${CI_JOBS:-2}" CARGO_BUILD_JOBS="${CI_JOBS:-2}"
export RUST_TEST_THREADS="${CI_TEST_THREADS:-2}"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
# Append to any git config the verified runtime already supplies through the environment.
git_config_base=${GIT_CONFIG_COUNT:-0}
export GIT_CONFIG_COUNT=$((git_config_base + 2))
export "GIT_CONFIG_KEY_$((git_config_base + 0))=url.https://git.corbet.ch/corbet-libs/.insteadOf"
export "GIT_CONFIG_VALUE_$((git_config_base + 0))=https://github.com/corbet-libs/"
export "GIT_CONFIG_KEY_$((git_config_base + 1))=url.https://git.corbet.ch/corbet-foss/.insteadOf"
export "GIT_CONFIG_VALUE_$((git_config_base + 1))=https://github.com/corbet-foss/"
# Shared-first toolchain lock: jobs share a provisioned toolchain and take
# exclusive only to provision missing pieces. Same lock file, so old
# whole-job-exclusive runners interoperate (they just serialize).
# Both wasm32 targets are covered by TOOLCHAIN_WASM_TARGETS (provisioned
# under exclusive when missing); the unconditional `rustup target add`
# lines in verify.sh are removed, so no toolchain mutation executes here
# or downstream under the shared lock.
TOOLCHAIN_LOCK_FILE="$toolchains/install.lock"
TOOLCHAIN_LOCK_TIMEOUT="${CI_TIMEOUT:-2700}"
TOOLCHAIN_WANT_NIGHTLY=1
TOOLCHAIN_WASM_TARGETS="stable:wasm32-unknown-unknown nightly:wasm32-unknown-unknown"
# shellcheck source=toolchain-lock.sh
source "$(dirname "${BASH_SOURCE[0]}")/toolchain-lock.sh"
toolchain_ensure
cargo_bin=$(rustup which --toolchain stable cargo)
test -x "$cargo_bin"
export PATH="$(dirname "$cargo_bin"):$PATH"
export CCID_SOURCE_REVISION="$CI_COMMIT_SHA"
"$CCID_BIN" render --repo "$PWD" --check
proto --version
moon --version
rustc -vV
cargo --version
python3 --version
python3 -c 'import selenium; print(selenium.__version__)'
wasm-pack --version
clang --version
command -v cc
curl --version
export CHROMEDRIVER="${CHROMEDRIVER:-$(command -v chromedriver)}"
export CHROME_BIN="${CHROME_BIN:-$(command -v chromium)}"
test -x "$CHROMEDRIVER" || { echo "nix chromedriver not executable at $CHROMEDRIVER" >&2; exit 2; }
test -x "$CHROME_BIN" || { echo "nix chromium not executable at $CHROME_BIN" >&2; exit 2; }
chromedriver --version
chromium --version
rustup run nightly rustc -vV
rustup run nightly cargo llvm-cov --version
"$CCID_BIN" cached --repo "$PWD" --check verify
test -s ".ccid/results/verify.jsonl"
