//! CMS RC2 key wrapping as specified by RFC 3217, over the `tc_rc_cipher`
//! RC2 engine, with SHA-1 integrity and the `tc_key_wrap` contracts.
//!
//! Wrapping needs an IV and random padding, drawn from a caller-supplied
//! generator, and unwrapping copies the input, so the crate needs an
//! allocator and `rand_core`. RC2 is provided for interoperability with
//! existing formats and is not suitable for new designs.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

mod engine;

pub use engine::Rc2WrapEngine;

/// CMS RC2 key-wrap operation error.
pub type Rc2WrapError = tc_key_wrap::KeyWrapError<tc_block_cipher::BlockError>;
/// CMS RC2 key-wrapper initialization error.
pub type Rc2WrapInitError = tc_key_wrap::KeyWrapInitError<tc_block_cipher::InitError>;
