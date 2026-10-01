# Changelog

All notable changes to `tc_des_wrap` are documented in this file.

## 0.1.0 - 2026-10-01

Initial release.

### Added

- `DesEdeWrapEngine`, CMS Triple-DES key wrapping as specified by RFC 3217
  over the Triple DES engine of `tc_des`, implementing the `KeyWrap` and
  `KeyWrapInit` contracts of `tc_key_wrap`. It wraps a key whose length is a
  multiple of 8 bytes with the first 8 bytes of its SHA-1 checksum, under a 16-
  or 24-byte key-encryption key, and unwraps 16 bytes or more in multiples of
  8.
- Wrapping takes an 8-byte IV from the parameters or draws one from the
  caller-supplied `rand_core::CryptoRng`; the IV is fixed at `init` and serves
  every wrap until the next `init`. Unwrapping rejects a supplied IV with
  `IvNotAllowedForUnwrap`. Any parameters that implement `KeyParams` and
  `IvOptParams`, such as the `KeyWithIvOpt*` containers of `tc_key_wrap`, are
  accepted.
- A failed `init` leaves the wrapper uninitialized. Wrapping and unwrapping
  return an error before `init` or in the other direction, and
  `OutputTooShort` for a short output, without touching the output. A failed
  wrap wipes the output, and a failed unwrap, including a checksum mismatch,
  leaves it untouched.
- `DesEdeWrapError` and `DesEdeWrapInitError`, aliases of the `tc_key_wrap`
  errors over the Triple DES engine's errors.
- `Display` for the wrapper, writing `"DESede"`, and `Default` when the
  generator implements `Default`.
- Tests against Bouncy Castle's three-key vector with a given and a generated
  IV; a round trip under a two-key key-encryption key through a trait object;
  contract tests of tampering, an IV supplied for unwrapping and a rejected
  re-initialization; a test that every public API documents whether it is
  constant or variable time; and a doctest for the wrapper.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024. Every build depends
  on `rand_core` and follows its minimum Rust version, which is 1.85 for
  0.10.1.
- Depends on `tc_des` 0.1, `tc_key_wrap` 0.1, `tc_block_cipher` 0.1, `tc_sha`
  0.1, `tc_digest` 0.1, `tc_constant_time` 0.1, `tc_zeroize` 0.1 (with
  `alloc`) and `rand_core` 0.10, and needs an allocator.
- The wrapper is variable time: the Triple DES engine looks up S-boxes with
  secret data.
- Like Bouncy Castle, the wrapper does not set the parity bits of the key it
  wraps.
- Triple DES is provided for interoperability with existing formats and is not
  suitable for new designs.
- Wiping does not reach the caller's buffers or copies left in registers and on
  the stack.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
