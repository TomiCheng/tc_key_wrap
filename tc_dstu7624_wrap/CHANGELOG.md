# Changelog

All notable changes to `tc_dstu7624_wrap` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `Dstu7624WrapEngine`, DSTU 7624:2014 (Kalyna) key wrapping over the engines
  of `tc_dstu7624`, implementing the `KeyWrap` and `KeyWrapInit` contracts of
  `tc_key_wrap`. Its const parameter counts 64-bit block words, and the
  `Dstu7624WrapEngine128`, `Dstu7624WrapEngine256` and `Dstu7624WrapEngine512`
  aliases run over the 128-, 256- and 512-bit engines; each width has
  `const fn new` and `Default`.
- The wrapper appends an all-zero integrity block and applies the DSTU 7624
  wrapping transformation over half-block registers. It wraps a key of whole
  cipher blocks, possibly none, into one block more, and unwraps one block or
  more in whole blocks. It takes any `KeyParams` with a key length the engine
  accepts, and no IV.
- A failed `init` leaves the wrapper uninitialized. Wrapping and unwrapping
  return an error before `init` or in the other direction, and
  `OutputTooShort` for a short output, without touching the output. A failed
  wrap or unwrap, including an integrity block that is not zero, wipes the
  output it was writing.
- `Dstu7624WrapError` and `Dstu7624WrapInitError`, aliases of the
  `tc_key_wrap` errors over the Kalyna engine's errors.
- `Display` for every width, writing `"DSTU7624Wrap"`.
- Tests against Bouncy Castle's vectors for every block width in both
  directions; contract tests of the sizing rules, an empty key through a trait
  object, tampering and a rejected re-initialization; a test that every public
  API documents whether it is constant or variable time; and a doctest for the
  wrapper.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_dstu7624` 0.1, `tc_key_wrap` 0.1, `tc_block_cipher` 0.1 and
  `tc_zeroize` 0.1. Needs neither an allocator nor a random generator.
- The wrapper is variable time: the Kalyna engine looks up S-boxes with secret
  data.
- The wrap is deterministic, since it takes no IV.
- Wiping does not reach the caller's buffers or copies left in registers and on
  the stack.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
