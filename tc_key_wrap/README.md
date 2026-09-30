# tc_key_wrap

[![crates.io](https://img.shields.io/crates/v/tc_key_wrap.svg)](https://crates.io/crates/tc_key_wrap)
[![docs.rs](https://docs.rs/tc_key_wrap/badge.svg)](https://docs.rs/tc_key_wrap)
[![CI](https://github.com/TomiCheng/tc_key_wrap/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_key_wrap/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Key wrapping for block ciphers: RFC 3394 (AES key wrap), RFC 5649 (AES key
wrap with padding) and the RFC 3211 key wrap for password-based recipients.
Every wrapper runs over an engine that implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits, such as
[`tc_aes`](https://crates.io/crates/tc_aes). The crate also defines the
`KeyWrap` and `KeyWrapInit` contracts that algorithm-specific wrappers
implement. Ported from Bouncy Castle C#.

The crate is `no_std`, needs no allocator by default and contains no `unsafe`
code. The default build depends on `tc_block_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize) and provides the traits,
parameter types and errors; each algorithm is behind its own feature.

Requires Rust 1.85 or later (edition 2024) for the default build and the
`rfc3394`, `rfc5649` and `alloc` features. The `rfc3211` feature follows the
minimum Rust version of the `rand_core` crate instead, which is 1.85 for
`rand_core` 0.10.1.

## Types

- `Rfc3394WrapEngine` (`rfc3394`) — RFC 3394 key wrap over a cipher with
  16-byte blocks.
- `Rfc5649WrapEngine` (`rfc5649`) — RFC 5649 key wrap with padding, for keys
  of any length.
- `Rfc3211WrapEngine` (`rfc3211`) — RFC 3211 key wrap over a cipher with
  blocks of 4 bytes or more.
- `KeyWithIvRef`, `KeyWithIvFixed`, `KeyWithIvOwned` (`alloc`) — a key and a
  required IV that borrow, or own and wipe, their bytes.
- `KeyWithIvOptRef`, `KeyWithIvOptFixed`, `KeyWithIvOptOwned` (`alloc`) — a
  key and an optional IV; `None` selects the wrapper's standard IV.
- `WrapDirection` — wrapping or unwrapping, chosen at `init`.
- `KeyWrapError`, `KeyWrapInitError` — processing and initialization errors
  that wrap the cipher's.

RFC 3394 wraps a key of 8 bytes or more, in multiples of 8, and adds 8 bytes.
Its IV defaults to `A6A6A6A6A6A6A6A6`; a custom IV is 8 bytes.
`Rfc3394WrapEngine::with_reverse_direction` wraps with the cipher's decryption
direction, as Bouncy Castle's `useReverseDirection` does. RFC 5649 wraps from 1
byte up to `2^32 - 1` bytes and outputs the key rounded up to a multiple of 8,
plus 8. Its alternative-IV prefix defaults to `A65959A6`; a custom prefix is 4
bytes. Bouncy Castle's `AesWrapEngine`, `AriaWrapEngine` and the matching
`*WrapPadEngine` classes are these two wrappers over the named cipher.

RFC 3211 wraps a key of up to 255 bytes under an IV of one block. It pads with
random bytes from a `rand_core::CryptoRng` passed to `new`, so an instance
used only for unwrapping also takes a generator.

`wrapped_len` returns the exact output size and `max_unwrapped_len` a
sufficient capacity; `unwrap_into` returns how many key bytes it recovered.
Every call before `init`, or in the other direction, returns an error without
touching the output. `Display` writes the cipher's name and the algorithm, such
as `"AES/RFC3394Wrap"`.

## Traits

- `KeyWrap` — sizing, `wrap_into` and `unwrap_into` over caller-provided
  buffers; usable as `dyn KeyWrap<Error = E>`.
- `KeyWrapInit` — initializes a wrapper for a direction from parameters of
  type `P`.
- `IvParams` — the IV a parameter type provides alongside the cipher's
  `KeyParams`.
- `IvOptParams` — an IV that may be absent; every `IvParams` type implements
  it.

## Features

- `rfc3394` (off by default) — adds `Rfc3394WrapEngine` and the
  `tc_constant_time` dependency.
- `rfc5649` (off by default) — adds `Rfc5649WrapEngine`; enables `rfc3394`.
- `rfc3211` (off by default) — adds `Rfc3211WrapEngine`; enables `alloc` and
  the `rand_core` dependency.
- `alloc` (off by default) — adds the owned parameter types; does not require
  the standard library.

## Usage

```toml
[dependencies]
tc_key_wrap = { version = "0.1.0", features = ["rfc3394"] }
tc_aes = "0.1.0"
```

```rust
use tc_aes::AesEngine;
use tc_key_wrap::{KeyWithIvOptRef, KeyWrap, KeyWrapInit, Rfc3394WrapEngine, WrapDirection};

let (kek, key) = ([0x42; 16], [0x11; 16]);
let mut wrapper = Rfc3394WrapEngine::new(AesEngine::new());
wrapper.init(WrapDirection::Wrap, &KeyWithIvOptRef::new(&kek, None)).expect("valid KEK");
let mut wrapped = [0; 24];
wrapper.wrap_into(&key, &mut wrapped).expect("initialized, valid key length");
```

The type documentation carries an executable example for every wrapper.

## Security

RFC 3394 and RFC 5649 are deterministic: the same key-encryption key and key
always give the same output. They authenticate the key with a 64-bit check,
which suits key material but not general messages.

RFC 3211 checks only a length byte and 3 check bytes. They catch a wrong
key-encryption key but are no strong integrity check: a forged blob passes with
a probability near `2^-24`. Give every wrap a fresh random IV. The engine takes a
key-encryption key, not a password; derive the key from the password first,
for example with PBKDF2.

`Rfc3394WrapEngine` is constant time exactly when its cipher is.
`Rfc5649WrapEngine` is too, except that the padding check follows the
recovered length, which a successful unwrap reveals. `Rfc3211WrapEngine` is
constant time exactly when its cipher is, apart from the key length and whether
the check passed; wrapping adds the generator's own time.
`tc_aes::AesEngine`, for example, is constant time with AES-NI or its
`rustcrypto` feature and variable time otherwise.

A failed wrap wipes the output. A failed RFC 3394 or RFC 5649 unwrap wipes the
output, and a failed RFC 3211 unwrap leaves it untouched. The fixed and owned
parameter types wipe their bytes on drop, every parameter type's `Debug`
redacts the key and IV, and the cipher wipes its own key schedule. Wiping does
not reach the caller's buffers, copies left in registers and on the stack, or a
value that is leaked or forgotten.

## Validation

`Rfc3394WrapEngine` is tested against the six RFC 3394 vectors and
`Rfc5649WrapEngine` against the two RFC 5649 vectors, plus three independent
ARIA vectors. `Rfc3211WrapEngine` is tested against Bouncy Castle's DES,
Triple-DES, AES and ARIA vectors and a round trip with a seeded `StdRng`.
Contract tests cover custom IVs, trait objects, tampering, direction and
sizing errors, short outputs and IV validation. A test requires every public
API to document whether it is constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_key_wrap --locked
cargo test -p tc_key_wrap --locked --all-features
cargo clippy -p tc_key_wrap --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_key_wrap --check
cargo doc -p tc_key_wrap --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_key_wrap --list --locked
cargo publish -p tc_key_wrap --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
