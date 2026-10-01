# tc_des_wrap

[![crates.io](https://img.shields.io/crates/v/tc_des_wrap.svg)](https://crates.io/crates/tc_des_wrap)
[![docs.rs](https://docs.rs/tc_des_wrap/badge.svg)](https://docs.rs/tc_des_wrap)
[![CI](https://github.com/TomiCheng/tc_key_wrap/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_key_wrap/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

CMS Triple-DES key wrapping as specified by RFC 3217, with a SHA-1 checksum,
over the Triple DES engine of [`tc_des`](https://crates.io/crates/tc_des). The
wrapper implements the `KeyWrap` and `KeyWrapInit` contracts of
[`tc_key_wrap`](https://crates.io/crates/tc_key_wrap). Triple DES is provided
for interoperability with existing formats and is not suitable for new
designs. Ported from Bouncy Castle C#.

The crate is `no_std` and contains no `unsafe` code. It needs an allocator,
because unwrapping copies its input, and a caller-supplied `rand_core`
generator for the IV. It has no features and depends on `tc_des`,
`tc_key_wrap`, `tc_block_cipher`, `tc_sha`, `tc_digest`, `tc_constant_time`,
`tc_zeroize` and `rand_core`.

Requires Rust 1.85 or later (edition 2024). Every build depends on
`rand_core` and so follows its minimum Rust version, which is 1.85 for
`rand_core` 0.10.1.

## Types

- `DesEdeWrapEngine` — the RFC 3217 Triple-DES key wrapper over a generator
  `R`.
- `DesEdeWrapError`, `DesEdeWrapInitError` — the `tc_key_wrap` processing and
  initialization errors over the Triple DES engine's.

`DesEdeWrapEngine` wraps a key whose length is a multiple of 8 bytes, normally
a 24-byte Triple DES key, followed by the first 8 bytes of its SHA-1 hash. It
encrypts that with CBC under the IV, reverses the result together with the IV,
and encrypts again under the fixed RFC 3217 IV, so the output is 16 bytes
longer than the key. It unwraps 16 bytes or more, in multiples of 8. The
key-encryption key is 16 or 24 bytes.

The parameters implement `KeyParams` and `IvOptParams`, as the
`KeyWithIvOptRef`, `KeyWithIvOptFixed` and `KeyWithIvOptOwned` containers of
`tc_key_wrap` do. Wrapping takes an 8-byte IV from the parameters or, given
`None`, draws one from the generator. Either way the IV is fixed at `init`, as
in Bouncy Castle, and every wrap until the next `init` uses it. Unwrapping
takes no IV and returns `IvNotAllowedForUnwrap` for one. `Display` writes
`"DESede"`.

Like Bouncy Castle, the wrapper does not set the odd parity bits of the key it
wraps, which RFC 3217 asks for first; set them before wrapping if the
recipient checks them.

## Usage

```toml
[dependencies]
tc_des_wrap = "0.1.0"
tc_key_wrap = "0.1.0"
rand = "0.10"
```

```rust
use tc_des_wrap::DesEdeWrapEngine;
use tc_key_wrap::{KeyWithIvOptRef, KeyWrap, KeyWrapInit, WrapDirection};

let (kek, key) = ([0x42; 24], [0x11; 24]);
let mut wrapper = DesEdeWrapEngine::new(rand::rng());
wrapper.init(WrapDirection::Wrap, &KeyWithIvOptRef::new(&kek, None)).expect("valid Triple DES KEK");
let mut wrapped = [0; 40];
wrapper.wrap_into(&key, &mut wrapped).expect("initialized, key of whole blocks");
```

The type documentation carries an executable example.

## Security

Triple DES is a legacy cipher; use this crate only to read or produce existing
CMS data. The wrap authenticates the key with a 64-bit truncated SHA-1
checksum.

Initialize the wrapper again before each wrap, so that every wrapped key gets
a fresh IV; a generator seeded from the operating system, such as
`rand::rng()`, supplies it.

`DesEdeWrapEngine` is variable time: the Triple DES engine looks up S-boxes
with secret data during key setup and block processing. The checksum is
compared in constant time, but the surrounding decryption is not.

A failed wrap wipes the output, and a failed unwrap leaves it untouched; the
unwrap's working copy is wiped on drop. The Triple DES engine wipes its own key
schedule, and the `tc_key_wrap` parameter containers that own their bytes wipe
them on drop. Wiping does not reach the caller's buffers, copies left in
registers and on the stack, or a value that is leaked or forgotten.

## Validation

`DesEdeWrapEngine` is tested against Bouncy Castle's three-key vector, with
both the given IV and an IV drawn from the generator, and round-trips a key
under a two-key key-encryption key through a trait object. Contract tests
cover tampering, an IV supplied for unwrapping and a rejected
re-initialization. A test requires every public API to document whether it is
constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_des_wrap --locked
cargo clippy -p tc_des_wrap --all-targets --locked -- -D warnings
cargo fmt -p tc_des_wrap --check
cargo doc -p tc_des_wrap --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_des_wrap --list --locked
cargo publish -p tc_des_wrap --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
