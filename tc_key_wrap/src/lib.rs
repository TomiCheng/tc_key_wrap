//! Key wrapping over the `tc_block_cipher` traits: RFC 3394 (AES key wrap),
//! RFC 5649 (AES key wrap with padding) and RFC 3211, with the `KeyWrap` and
//! `KeyWrapInit` contracts that algorithm-specific wrappers such as
//! `tc_des_wrap` also implement.
//!
//! The crate is `no_std` and needs no allocator by default. The `alloc`
//! feature adds `KeyWithIvOwned` and `KeyWithIvOptOwned`; RFC 3211, which
//! draws random padding from a caller-supplied generator, needs both `alloc`
//! and `rand_core`.
//!
//! # Example
//!
//! Wrapping a 128-bit key with a 128-bit AES key-encryption key, the first
//! RFC 3394 test vector:
//!
//! ```
//! use tc_aes::AesEngine;
//! use tc_key_wrap::{KeyWithIvOptRef, KeyWrap, KeyWrapInit, Rfc3394WrapEngine, WrapDirection};
//!
//! let kek: [u8; 16] = core::array::from_fn(|i| i as u8);
//! let key = [
//!     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
//!     0xff,
//! ];
//! let mut wrapper = Rfc3394WrapEngine::new(AesEngine::new());
//! wrapper.init(WrapDirection::Wrap, &KeyWithIvOptRef::new(&kek, None))?;
//! let mut wrapped = [0; 24];
//! assert_eq!(wrapper.wrap_into(&key, &mut wrapped)?, 24);
//! assert_eq!(wrapped[..8], [0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47]);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
mod params;
#[cfg(all(feature = "alloc", feature = "rand_core"))]
mod rfc3211;
mod rfc3394;
mod rfc5649;
mod traits;
mod wrap_direction;

pub use error::{KeyWrapError, KeyWrapInitError};
pub use params::{KeyWithIvFixed, KeyWithIvOptFixed, KeyWithIvOptRef, KeyWithIvRef};
#[cfg(feature = "alloc")]
pub use params::{KeyWithIvOptOwned, KeyWithIvOwned};
#[cfg(all(feature = "alloc", feature = "rand_core"))]
pub use rfc3211::Rfc3211WrapEngine;
pub use rfc3394::Rfc3394WrapEngine;
pub use rfc5649::Rfc5649WrapEngine;
pub use traits::{IvOptParams, IvParams, KeyWrap, KeyWrapInit};
pub use wrap_direction::WrapDirection;
