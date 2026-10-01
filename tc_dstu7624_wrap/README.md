# tc_dstu7624_wrap

[![crates.io](https://img.shields.io/crates/v/tc_dstu7624_wrap.svg)](https://crates.io/crates/tc_dstu7624_wrap)
[![docs.rs](https://docs.rs/tc_dstu7624_wrap/badge.svg)](https://docs.rs/tc_dstu7624_wrap)
[![CI](https://github.com/TomiCheng/tc_key_wrap/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_key_wrap/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

DSTU 7624:2014 (Kalyna) key wrapping over the engines of
[`tc_dstu7624`](https://crates.io/crates/tc_dstu7624). The wrapper implements
the `KeyWrap` and `KeyWrapInit` contracts of
[`tc_key_wrap`](https://crates.io/crates/tc_key_wrap). Ported from Bouncy
Castle C#.

The crate is `no_std`, needs no allocator and no random generator, and
contains no `unsafe` code. It has no features and depends on `tc_dstu7624`,
`tc_key_wrap`, `tc_block_cipher` and `tc_zeroize`.

Requires Rust 1.85 or later (edition 2024).

## Types

- `Dstu7624WrapEngine128`, `Dstu7624WrapEngine256`, `Dstu7624WrapEngine512` —
  the DSTU 7624 key wrapper over the 128-, 256- and 512-bit Kalyna engines.
- `Dstu7624WrapEngine` — the wrapper they alias, whose const parameter counts
  64-bit block words.
- `Dstu7624WrapError`, `Dstu7624WrapInitError` — the `tc_key_wrap` processing
  and initialization errors over the Kalyna engine's.

The wrapper appends an all-zero integrity block to the key and applies the
DSTU 7624 wrapping transformation over half-block registers: `6 * (n - 1)`
encryptions for `n` half blocks, each followed by a round counter. The
standard defines no padding, so the key to wrap is a whole number of cipher
blocks, possibly none, and the output is one block longer. It unwraps one
block or more, in whole blocks.

The parameters are any `KeyParams`, such as `tc_block_cipher::KeyRef`. The
key-encryption key is 16 or 32 bytes for 128-bit blocks, 32 or 64 bytes for
256-bit blocks, and 64 bytes for 512-bit blocks. There is no IV. `Display`
writes `"DSTU7624Wrap"`, and every width has `const fn new` and `Default`.

## Usage

```toml
[dependencies]
tc_dstu7624_wrap = "0.1.0"
tc_key_wrap = "0.1.0"
tc_block_cipher = "0.1.0"
```

```rust
use tc_block_cipher::KeyRef;
use tc_dstu7624_wrap::Dstu7624WrapEngine128;
use tc_key_wrap::{KeyWrap, KeyWrapInit, WrapDirection};

let (kek, key) = ([0x42; 16], [0x11; 32]);
let mut wrapper = Dstu7624WrapEngine128::new();
wrapper.init(WrapDirection::Wrap, &KeyRef::new(&kek)).expect("valid Kalyna-128 key");
let mut wrapped = [0; 48];
wrapper.wrap_into(&key, &mut wrapped).expect("initialized, whole blocks");
```

The type documentation carries an executable example.

## Security

The wrap is deterministic: with no IV, the same key-encryption key and key
always give the same output. It authenticates the key with an all-zero block
of the cipher's width, which suits key material but not general messages.

`Dstu7624WrapEngine` is variable time: the Kalyna engine looks up S-boxes with
secret data during key setup and block processing.

A failed wrap or unwrap, including an integrity block that is not zero, wipes
the output it was writing; bytes past the wrapped or unwrapped length are left
untouched. The working registers are wiped when each call returns, and the
Kalyna engine wipes its own key schedule. Wiping does not reach the caller's buffers, copies left in
registers and on the stack, or a value that is leaked or forgotten.

## Validation

`Dstu7624WrapEngine` is tested against Bouncy Castle's vectors for every block
width: two for 128-bit and 256-bit blocks and one for 512-bit blocks, in both
directions. Contract tests cover the sizing rules, an empty key through a
trait object, tampering and a rejected re-initialization. A test requires
every public API to document whether it is constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_dstu7624_wrap --locked
cargo clippy -p tc_dstu7624_wrap --all-targets --locked -- -D warnings
cargo fmt -p tc_dstu7624_wrap --check
cargo doc -p tc_dstu7624_wrap --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_dstu7624_wrap --list --locked
cargo publish -p tc_dstu7624_wrap --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
