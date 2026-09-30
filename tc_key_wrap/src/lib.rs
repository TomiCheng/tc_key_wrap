//! Key wrapping over the `tc_block_cipher` traits: RFC 3394 (AES key wrap),
//! RFC 5649 (AES key wrap with padding) and RFC 3211, with the `KeyWrap` and
//! `KeyWrapInit` contracts that algorithm-specific wrappers such as
//! `tc_des_wrap` also implement.
//!
//! The crate is `no_std` and needs no allocator by default. The default build
//! provides the traits, parameter containers and errors that wrappers such as
//! `tc_des_wrap` build on; each algorithm is behind its own feature:
//!
//! - `rfc3394` — `Rfc3394WrapEngine`.
//! - `rfc5649` — `Rfc5649WrapEngine`; enables `rfc3394`, whose register loop
//!   it shares.
//! - `rfc3211` — `Rfc3211WrapEngine`; enables `alloc` and the `rand_core`
//!   dependency, since it sizes its state from the cipher at run time and
//!   draws random padding from a caller-supplied generator.
//! - `alloc` — `KeyWithIvOwned` and `KeyWithIvOptOwned`.
//!
//! Each engine's documentation carries a usage example.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
mod params;
#[cfg(feature = "rfc3211")]
mod rfc3211;
#[cfg(feature = "rfc3394")]
mod rfc3394;
#[cfg(feature = "rfc5649")]
mod rfc5649;
mod traits;
mod wrap_direction;

pub use error::{KeyWrapError, KeyWrapInitError};
pub use params::{KeyWithIvFixed, KeyWithIvOptFixed, KeyWithIvOptRef, KeyWithIvRef};
#[cfg(feature = "alloc")]
pub use params::{KeyWithIvOptOwned, KeyWithIvOwned};
#[cfg(feature = "rfc3211")]
pub use rfc3211::Rfc3211WrapEngine;
#[cfg(feature = "rfc3394")]
pub use rfc3394::Rfc3394WrapEngine;
#[cfg(feature = "rfc5649")]
pub use rfc5649::Rfc5649WrapEngine;
pub use traits::{IvOptParams, IvParams, KeyWrap, KeyWrapInit};
pub use wrap_direction::WrapDirection;
