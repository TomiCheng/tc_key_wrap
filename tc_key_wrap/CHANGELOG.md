# Changelog

All notable changes to `tc_key_wrap` are documented in this file.

## 0.1.0 - 2026-09-30

Initial release.

### Added

- The `KeyWrap` contract, which sizes, wraps and unwraps into caller-provided
  buffers and can be used as `dyn KeyWrap<Error = E>`, and the separate
  `KeyWrapInit` contract, which initializes a wrapper for a `WrapDirection`
  from parameters of type `P`.
- `IvParams` for a required IV and `IvOptParams` for an IV that may be absent,
  implemented by every `IvParams` type.
- `Rfc3394WrapEngine` behind the default-off `rfc3394` feature: RFC 3394 key
  wrap over a cipher with 16-byte blocks, with the standard or an 8-byte custom
  IV, and `with_reverse_direction` for Bouncy Castle's `useReverseDirection`.
- `Rfc5649WrapEngine` behind the default-off `rfc5649` feature, which enables
  `rfc3394`: RFC 5649 key wrap with padding for keys from 1 byte up to
  `2^32 - 1` bytes, with the standard or a 4-byte custom alternative-IV prefix.
- `Rfc3211WrapEngine` behind the default-off `rfc3211` feature, which enables
  `alloc` and the `rand_core` dependency: RFC 3211 key wrap of up to 255 bytes
  over a cipher with blocks of 4 bytes or more, under a one-block IV, with
  random padding from a caller-supplied `rand_core::CryptoRng`.
- A failed `init` leaves every wrapper uninitialized. Wrapping and unwrapping
  return an error before `init` or in the other direction, and
  `OutputTooShort` for a short output, without touching the output. A failed
  wrap wipes the output; a failed RFC 3394 or RFC 5649 unwrap wipes it, and a
  failed RFC 3211 unwrap leaves it untouched.
- `KeyWithIvRef`, `KeyWithIvFixed`, `KeyWithIvOptRef`, `KeyWithIvOptFixed`
  and, with the default-off `alloc` feature, `KeyWithIvOwned` and
  `KeyWithIvOptOwned` parameter containers. The fixed and owned forms wipe the
  key and the IV on drop, and `Debug` writes only the lengths.
- `KeyWrapError` and `KeyWrapInitError`, which wrap the cipher's errors.
- `Display` for every wrapper, writing the cipher's name followed by
  `/RFC3394Wrap`, `/RFC5649Wrap` or `/RFC3211Wrap`. `Rfc3394WrapEngine` and
  `Rfc5649WrapEngine` implement `Default` and have `const fn new`.
- Tests against the RFC 3394 vectors, the RFC 5649 vectors and independent
  ARIA vectors for RFC 5649, and Bouncy Castle's DES, Triple-DES, AES and ARIA
  vectors for RFC 3211; contract tests of custom IVs, trait objects,
  tampering, direction and sizing errors, short outputs and IV validation; a
  test that every public API documents whether it is constant or variable
  time; and doctests for every wrapper.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024. The `rfc3211`
  feature follows the minimum Rust version of `rand_core`, which is 1.85 for
  0.10.1.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1; `rfc3394` adds
  `tc_constant_time` 0.1 and `rfc3211` adds `rand_core` 0.10.
- RFC 3394 is constant time exactly when the cipher is. RFC 5649 is too, except
  that its padding check follows the recovered length. RFC 3211 is constant
  time exactly when the cipher is, apart from the key length and whether its
  check passed.
- RFC 3211 checks only a length byte and 3 check bytes, and its engine takes a
  key-encryption key, not a password.
- Wiping does not reach the caller's buffers or copies left in registers and on
  the stack.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
