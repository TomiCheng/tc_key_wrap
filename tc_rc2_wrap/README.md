# tc_rc2_wrap

[![crates.io](https://img.shields.io/crates/v/tc_rc2_wrap.svg)](https://crates.io/crates/tc_rc2_wrap)
[![docs.rs](https://docs.rs/tc_rc2_wrap/badge.svg)](https://docs.rs/tc_rc2_wrap)
[![CI](https://github.com/TomiCheng/tc_key_wrap/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_key_wrap/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

CMS RC2 key wrapping as specified by RFC 3217, with a SHA-1 checksum and
random padding, over the RC2 engine of
[`tc_rc_cipher`](https://crates.io/crates/tc_rc_cipher). The wrapper
implements the `KeyWrap` and `KeyWrapInit` contracts of
[`tc_key_wrap`](https://crates.io/crates/tc_key_wrap). RC2 is provided for
interoperability with existing formats and is not suitable for new designs.
Ported from Bouncy Castle C#.

The crate is `no_std` and contains no `unsafe` code. It needs an allocator,
because unwrapping copies its input, and a caller-supplied `rand_core`
generator for the IV and the padding. It has no features and depends on
`tc_rc_cipher`, `tc_key_wrap`, `tc_block_cipher`, `tc_sha`, `tc_digest`,
`tc_constant_time`, `tc_zeroize` and `rand_core`.

Requires Rust 1.85 or later (edition 2024). Every build depends on
`rand_core` and so follows its minimum Rust version, which is 1.85 for
`rand_core` 0.10.1.

## Types

- `Rc2WrapEngine` — the RFC 3217 RC2 key wrapper over a generator `R`.
- `Rc2WrapParamsRef` — a borrowed key-encryption key, effective key size and
  optional IV.
- `Rc2WrapParamsOwned` — the owning form, which wipes the key and IV on drop.
- `Rc2WrapError`, `Rc2WrapInitError` — the `tc_key_wrap` processing and
  initialization errors over the RC2 engine's.

`Rc2WrapEngine` wraps a key of up to 255 bytes: a length byte and the key,
padded to whole 8-byte blocks with random bytes, followed by the first 8 bytes
of its SHA-1 hash. It encrypts that with CBC under the IV, reverses the result
together with the IV, and encrypts again under the fixed RFC 3217 IV, so the
output is 16 bytes longer than the padded key. It unwraps 24 to 272 bytes, in
multiples of 8. The key-encryption key is 1 to 128 bytes with an effective
size of 1 to 1024 bits; the parameter types default the effective size to the
key's full length.

Wrapping takes an 8-byte IV from the parameters or, given `None`, draws one
from the generator. Either way the IV is fixed at `init`, as in Bouncy Castle,
and every wrap until the next `init` uses it. Unwrapping takes no IV and
returns `IvNotAllowedForUnwrap` for one. `Display` writes `"RC2"`.

Any type that implements `KeyParams`, `Rc2Params` and `IvOptParams` can serve
as the parameters; the two parameter types exist because none of the
containers in `tc_rc_cipher` or `tc_key_wrap` implements all three.

## Usage

```toml
[dependencies]
tc_rc2_wrap = "0.1.0"
tc_key_wrap = "0.1.0"
rand = "0.10"
```

```rust
use tc_key_wrap::{KeyWrap, KeyWrapInit, WrapDirection};
use tc_rc2_wrap::{Rc2WrapEngine, Rc2WrapParamsRef};

let (kek, key) = ([0x42; 16], [0x11; 16]);
let mut wrapper = Rc2WrapEngine::new(rand::rng());
wrapper.init(WrapDirection::Wrap, &Rc2WrapParamsRef::new(&kek, None)).expect("valid RC2 KEK");
let mut wrapped = vec![0; wrapper.wrapped_len(key.len()).expect("key of at most 255 bytes")];
wrapper.wrap_into(&key, &mut wrapped).expect("initialized");
```

The type documentation carries executable examples for the wrapper and both
parameter types.

## Security

RC2 is a legacy cipher; use this crate only to read or produce existing CMS
data. The wrap authenticates the key with a 64-bit truncated SHA-1 checksum.

Initialize the wrapper again before each wrap, so that every wrapped key gets
a fresh IV; a generator seeded from the operating system, such as
`rand::rng()`, supplies the IV and the padding.

`Rc2WrapEngine` is variable time: the RC2 engine indexes tables with secret
data during key setup and block processing. The checksum is compared in
constant time, but the surrounding decryption is not.

A failed wrap wipes the output, and a failed unwrap leaves it untouched; the
unwrap's working copy is wiped on drop. `Rc2WrapParamsOwned` wipes its key and
IV on drop, both parameter types' `Debug` prints only lengths and the
effective size, and the RC2 engine wipes its own key schedule. Wiping does not
reach the caller's buffers, copies left in registers and on the stack, or a
value that is leaked or forgotten.

## Validation

`Rc2WrapEngine` is tested against the RFC 3217 vector, with both the given IV
and an IV drawn from the generator, and round-trips keys of 0, 1, 7, 8, 15,
16, 31 and 255 bytes through a trait object. Contract tests cover tampering, an IV supplied for
unwrapping and a rejected re-initialization. A test requires every public API
to document whether it is constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_rc2_wrap --locked
cargo clippy -p tc_rc2_wrap --all-targets --locked -- -D warnings
cargo fmt -p tc_rc2_wrap --check
cargo doc -p tc_rc2_wrap --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_rc2_wrap --list --locked
cargo publish -p tc_rc2_wrap --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
