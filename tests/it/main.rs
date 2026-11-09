//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`). `board` runs on native and wasm (the repo CI drives this binary by
//! name under llvm-cov on wasm32: `.ci/verify.sh:183`, `.github/workflows/ci.yml:137`);
//! the other modules are native only, as before (their inner `#![cfg]`).
mod board;
mod exchange;
mod forum_runtime;
mod groups;
mod rooms;
mod vouched;
