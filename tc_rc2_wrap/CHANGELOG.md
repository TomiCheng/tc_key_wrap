# Changelog

All notable changes to `tc_rc2_wrap` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `Rc2WrapEngine`, CMS RC2 key wrapping as specified by RFC 3217 over the RC2
  engine of `tc_rc_cipher`, implementing the `KeyWrap` and `KeyWrapInit`
  contracts of `tc_key_wrap`. It wraps a key of up to 255 bytes with a length
  byte, random padding to whole blocks and the first 8 bytes of a SHA-1
  checksum, under a key-encryption key of 1 to 128 bytes with an effective size
  of 1 to 1024 bits, and unwraps 24 to 272 bytes in multiples of 8.
- Wrapping takes an 8-byte IV from the parameters or draws one from the
  caller-supplied `rand_core::CryptoRng`; the IV is fixed at `init` and serves
  every wrap until the next `init`. Unwrapping rejects a supplied IV with
  `IvNotAllowedForUnwrap`.
- A failed `init` leaves the wrapper uninitialized. Wrapping and unwrapping
  return an error before `init` or in the other direction, and
  `OutputTooShort` for a short output, without touching the output. A failed
  wrap wipes the output, and a failed unwrap, including a checksum, length or
  padding mismatch, leaves it untouched.
- `Rc2WrapParamsRef` and `Rc2WrapParamsOwned`, which carry the key, the
  effective key size and an optional IV and implement `KeyParams`,
  `Rc2Params` and `IvOptParams`. The owned form wipes the key and the IV on
  drop, and `Debug` writes only the lengths and the effective size.
- `Rc2WrapError` and `Rc2WrapInitError`, aliases of the `tc_key_wrap` errors
  over the RC2 engine's errors.
- `Display` for the wrapper, writing `"RC2"`, and `Default` when the generator
  implements `Default`.
- Tests against the RFC 3217 vector with a given and a generated IV; round
  trips of keys of 0, 1, 7, 8, 15, 16, 31 and 255 bytes through a trait
  object; contract tests of
  tampering, an IV supplied for unwrapping and a rejected re-initialization; a
  test that every public API documents whether it is constant or variable
  time; and doctests for every public type.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024. Every build depends
  on `rand_core` and follows its minimum Rust version, which is 1.85 for
  0.10.1.
- Depends on `tc_rc_cipher` 0.1 (with `alloc`), `tc_key_wrap` 0.1,
  `tc_block_cipher` 0.1, `tc_sha` 0.1, `tc_digest` 0.1, `tc_constant_time`
  0.1, `tc_zeroize` 0.1 (with `alloc`) and `rand_core` 0.10, and needs an
  allocator.
- The wrapper is variable time: the RC2 engine indexes tables with secret
  data.
- RC2 is provided for interoperability with existing formats and is not
  suitable for new designs.
- Wiping does not reach the caller's buffers or copies left in registers and on
  the stack.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
