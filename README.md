# tc_key_wrap

A Rust workspace for key wrapping over block ciphers. It holds `tc_key_wrap`,
the shared `KeyWrap` and `KeyWrapInit` contracts together with the RFC 3394,
RFC 5649 and RFC 3211 wrappers, which run over any engine that implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits, and
`tc_des_wrap` and `tc_rc2_wrap`, the CMS Triple-DES and RC2 key wraps built on
those contracts.
Each crate is published separately and keeps its own README, changelog, and
validation commands.

[![CI](https://github.com/TomiCheng/tc_key_wrap/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_key_wrap/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_key_wrap`](tc_key_wrap) | [![crates.io](https://img.shields.io/crates/v/tc_key_wrap.svg)](https://crates.io/crates/tc_key_wrap) [![docs.rs](https://docs.rs/tc_key_wrap/badge.svg)](https://docs.rs/tc_key_wrap) | RFC 3394, RFC 5649 and RFC 3211 key wrapping over any `tc_block_cipher` engine, and the `KeyWrap` and `KeyWrapInit` contracts that algorithm-specific wrappers implement. `no_std`, no `unsafe`; the default build carries only the traits, parameter containers and errors and depends on `tc_block_cipher` and `tc_zeroize`. Default-off `rfc3394`, `rfc5649` and `rfc3211` features add the wrappers, and a default-off `alloc` feature adds parameter types that own and wipe their bytes. |
| [`tc_des_wrap`](tc_des_wrap) | [![crates.io](https://img.shields.io/crates/v/tc_des_wrap.svg)](https://crates.io/crates/tc_des_wrap) [![docs.rs](https://docs.rs/tc_des_wrap/badge.svg)](https://docs.rs/tc_des_wrap) | CMS Triple-DES key wrapping (RFC 3217) with a SHA-1 checksum, for legacy interoperability, over the Triple DES engine of `tc_des`. Variable time. `no_std`, no `unsafe`, no features; needs an allocator and a caller-supplied `rand_core` generator in every build. |
| [`tc_rc2_wrap`](tc_rc2_wrap) | [![crates.io](https://img.shields.io/crates/v/tc_rc2_wrap.svg)](https://crates.io/crates/tc_rc2_wrap) [![docs.rs](https://docs.rs/tc_rc2_wrap/badge.svg)](https://docs.rs/tc_rc2_wrap) | CMS RC2 key wrapping (RFC 3217) with a SHA-1 checksum, for legacy interoperability, over the RC2 engine of `tc_rc_cipher`. Variable time. `no_std`, no `unsafe`, no features; needs an allocator and a caller-supplied `rand_core` generator in every build. |

The workspace also holds `tc_dstu7624_wrap`, which is not released yet.

## Requirements

Rust 1.85 or later, edition 2024. Every crate builds without `std`.
`tc_key_wrap` reaches the heap only through its default-off `alloc` feature,
which `rfc3211` enables; `tc_des_wrap` and `tc_rc2_wrap` always need one.

Rust 1.85 is the earliest compiler for edition 2024, and it is guaranteed for
every build that uses only this workspace's crates and their `tc_*`
dependencies. The `rfc3211` feature of `tc_key_wrap` and every build of
`tc_des_wrap` and `tc_rc2_wrap` depend on `rand_core` and follow that crate's
minimum Rust version instead, which is 1.85 for `rand_core` 0.10.1;
dev-dependencies used only by tests are exempt. The workspace lock tracks the
latest dependency releases, so CI on stable tests what a user on a current
toolchain resolves.

## Workspace checks

```text
cargo test --locked
cargo test --locked --all-features
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo doc --locked --no-deps --all-features
```

CI additionally runs these on Linux x64, i686 and ARM64, macOS ARM64, and
Windows x64, runs Clippy on each `tc_key_wrap` feature alone, checks the
`wasm32-unknown-unknown` and `aarch64-unknown-none` targets and each released
crate's dependency set, checks the build that Rust 1.85.0 covers, and verifies
the package archives. See
[.github/workflows/ci.yml](.github/workflows/ci.yml).

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
