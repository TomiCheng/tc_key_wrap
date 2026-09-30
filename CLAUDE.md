# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules

- Comments and documentation are written in English only — doc comments,
  README, changelog, and inline comments alike.
- Never wire a README into rustdoc (`#![doc = include_str!("../README.md")]`).
  The README's badges and relative links do not survive rustdoc rendering.
  Crate documentation lives in `//!` and `///` comments; the README repeats what
  a reader on crates.io needs.
- No breaking changes. Public API work is additive: adding items, trait
  implementations, or default methods. If a change cannot be made additively,
  stop and raise it rather than altering an existing signature or behavior.
- Every crate README opens with the badge block: crates.io, docs.rs, CI,
  license, and rustc.
- Crate READMEs use no Markdown tables; crates.io renders them badly. Traits,
  types and features are flat one-line bullets (`` `Item` — what it does. ``),
  with any further detail in the paragraph below the list. Benchmark results
  and how to reproduce them live in the crate's `BENCHES.md`, which is in the
  `include` list, and the README links to it. `BENCHES.md` is read on GitHub,
  so its results may use tables.

The crate list and workspace-wide checks live in the root
[README.md](README.md); read it rather than restating it here. `tc_key_wrap` is
`no_std` and needs no allocator by default. Its features are default-off and
additive: `rfc3394`, `rfc5649` (which enables `rfc3394`, whose register loop it
shares), `rfc3211` (which enables `alloc` and the `rand_core` dependency) and
`alloc`. The default build carries only the traits, parameter containers and
errors and depends on `tc_block_cipher` and `tc_zeroize`; `rfc3394` adds
`tc_constant_time` and `rfc3211` adds `rand_core`. CI enforces each of these
dependency sets with `cargo tree` on the `wasm32-unknown-unknown`,
`aarch64-unknown-none` and x86 targets, and runs Clippy on each feature alone so
that no algorithm silently relies on another's items. `tc_key_wrap` carries no
cipher: key lengths and timing guarantees of the engines belong to their own
crates, such as `tc_aes`.

`tc_key_wrap` owns the `KeyWrap` and `KeyWrapInit` contracts; algorithm-specific
wrappers implement them rather than defining their own. `tc_rc2_wrap` is one:
the CMS RC2 key wrap (RFC 3217) over `tc_rc_cipher`. It has no features and
needs an allocator and `rand_core` in every build, so its dependency set is
`rand_core`, `tc_block_cipher`, `tc_constant_time`, `tc_digest`, `tc_key_wrap`,
`tc_rc_cipher`, `tc_sha` and `tc_zeroize`. The workspace also holds
`tc_des_wrap` and `tc_dstu7624_wrap`, which are not prepared for release yet:
they have no README, changelog or license texts, and CI neither packages them
nor checks their dependency sets.

`Rfc3394WrapEngine` is constant time exactly when its cipher is.
`Rfc5649WrapEngine` is too, except that its padding check follows the recovered
length. `Rfc3211WrapEngine` is constant time exactly when its cipher is, apart
from the key length and whether its check passed. `Rc2WrapEngine` is
variable time, because the RC2 engine indexes tables with secret data.
`tests/documentation.rs` requires each declaration it scans to say which, and
matches the phrase within one line, so never wrap a line between "constant" or
"variable" and "time".
Keep the timing contract of each item stated in its doc comment. A failed
unwrap must never leave unauthenticated key material in the output.

Rust 1.85 is guaranteed only where the workspace controls every crate: the
default build and first-party features such as `rfc3394`, `rfc5649` and
`alloc`, whose dependencies are all `tc_*` crates. A feature that enables a
third-party crate (`rfc3211` enables `rand_core`, 0.10.1 of which declares
1.85) follows that crate's MSRV, as does `tc_rc2_wrap`, whose every build
needs `rand_core`; dev-dependencies are exempt. The MSRV job
therefore runs `cargo check` on 1.85 for the guaranteed builds only; tests run
on stable. `.cargo/config.toml` sets `incompatible-rust-versions = "allow"` so
`Cargo.lock` tracks the latest releases and stable CI tests what current
toolchains resolve. Adding a third-party dependency to a default build or a
first-party feature hands the 1.85 guarantee to that crate; raise it before
doing so.

A crate depends on a workspace sibling through `path` plus `version`, so the
workspace builds and tests against the local crate while the published package
requires the release. When a change needs a sibling API that is not released
yet, raise the `version` requirement to the release that adds it; that release
has to be published first.

## Conventions

Each crate ships its own `README.md`, `CHANGELOG.md`, `LICENSE-MIT`,
`LICENSE-APACHE`, and an explicit `include` list in `Cargo.toml`. Changelog
entries are written as `## <version> - Unreleased` and dated in a separate
commit at release, with `### Added` and `### Compatibility` sections.

Preparing a crate for release means five edits beyond the crate itself: the
`members` list, a `-p <crate>` on the single `cargo package --locked` step in
the CI `quality` job (the only place package archives are verified; packaging
the crates in one invocation checks each against its siblings' local sources
rather than their releases), a `cargo tree` check of its dependency set in the
CI `portable` job, a row in the root `README.md`, and
workspace inheritance for `edition`, `rust-version`, `license`, and
`repository`. A missing `rust-version` also leaves clippy suggesting APIs newer
than 1.85.

Documentation is part of the contract: crates use `#![deny(missing_docs)]`,
doctests carry the executable examples, and CI runs `cargo doc` with
`RUSTDOCFLAGS: -D warnings`, with and without `--all-features`. Doc links to
feature-gated items break the build without that feature, so name them in plain
code spans. An additive public API change belongs in the crate README's
contract lists — "Types", "Traits" and "Features" in `tc_key_wrap/README.md`,
"Types" in `tc_rc2_wrap/README.md` —
and in the changelog, not only in the code.

Work happens on `feat/*` branches off `develop`; pull requests target `develop`,
which merges to `main`. Commit messages use an imperative subject and a wrapped
body that explains the reasoning, not a bullet list of the diff.

Note: the root `Cargo.toml` uses CRLF line endings while the rest of the tree
uses LF. Tools that rewrite whole files will flip it and produce a noisy diff.
