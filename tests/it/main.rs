//! The crate's native integration tests in one binary.
//!
//! Every former `tests/<name>.rs` that the host runs is a module here, so a warm edit loop links
//! one test executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`). `board` stays separate: the repo CI drives it by name
//! (`.ci/verify.sh:183`, `.github/workflows/ci.yml:137` `--test board` under llvm-cov on wasm32).
mod exchange;
mod forum_runtime;
mod groups;
mod rooms;
mod vouched;
