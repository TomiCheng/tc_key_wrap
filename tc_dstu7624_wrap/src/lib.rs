//! DSTU 7624:2014 (Kalyna) key wrapping over the `tc_dstu7624` engines, with
//! the `tc_key_wrap` contracts.
//!
//! The wrapper appends an all-zero integrity block and applies the DSTU 7624
//! wrapping transformation over half-block registers. The standard defines no
//! padding, so the wrapped key must be a whole number of cipher blocks. The
//! crate is `no_std` and needs no allocator.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod engine;

pub use engine::{
    Dstu7624WrapEngine, Dstu7624WrapEngine128, Dstu7624WrapEngine256, Dstu7624WrapEngine512,
};

/// DSTU 7624 key-wrap operation error.
pub type Dstu7624WrapError = tc_key_wrap::KeyWrapError<tc_block_cipher::BlockError>;
/// DSTU 7624 key-wrapper initialization error.
pub type Dstu7624WrapInitError = tc_key_wrap::KeyWrapInitError<tc_block_cipher::InitError>;
