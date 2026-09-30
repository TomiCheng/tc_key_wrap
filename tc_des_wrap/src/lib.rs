//! CMS Triple-DES key wrapping as specified by RFC 3217, over the `tc_des`
//! Triple DES engine, with SHA-1 integrity and the `tc_key_wrap` contracts.
//!
//! Wrapping needs an IV, drawn from a caller-supplied generator unless the
//! caller provides one, and unwrapping copies the input, so the crate needs
//! an allocator and `rand_core`. Triple DES is provided for interoperability
//! with existing formats and is not suitable for new designs.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

mod engine;

pub use engine::DesEdeWrapEngine;

/// CMS Triple-DES key-wrap operation error.
pub type DesEdeWrapError = tc_key_wrap::KeyWrapError<tc_block_cipher::BlockError>;
/// CMS Triple-DES key-wrapper initialization error.
pub type DesEdeWrapInitError = tc_key_wrap::KeyWrapInitError<tc_block_cipher::InitError>;
