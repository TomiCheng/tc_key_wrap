//! Key-wrapper initialization contract.

use crate::WrapDirection;

/// Initializes a key wrapper from parameters of type `P`.
///
/// This trait is independent of [`KeyWrap`](crate::KeyWrap). Consumers that
/// need both capabilities use `W: KeyWrap + KeyWrapInit<P>`. Keeping `P` as a
/// trait parameter lets one caller-owned parameter object flow through
/// composing cryptographic layers.
pub trait KeyWrapInit<P: ?Sized> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the implementation for wrapping or unwrapping.
    fn init(&mut self, direction: WrapDirection, params: &P) -> Result<(), Self::Error>;
}
