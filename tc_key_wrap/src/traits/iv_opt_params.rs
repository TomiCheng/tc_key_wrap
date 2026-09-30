//! Optional initialization-vector parameter abstraction.

use crate::IvParams;

/// Parameters that may provide an initialization vector.
///
/// Key wrappers with a standard IV accept this trait: `None` selects the
/// standard value and `Some` a custom one, which the wrapper validates. Every
/// [`IvParams`] type implements it and returns `Some`; the `KeyWithIvOpt*`
/// containers carry an `Option`, and a key-only type of your own can return
/// `None`.
///
/// # Example
///
/// ```
/// use tc_key_wrap::{IvOptParams, KeyWithIvOptRef, KeyWithIvRef};
///
/// let key = [0x42; 16];
/// assert_eq!(KeyWithIvOptRef::new(&key, None).iv_opt(), None);
/// assert_eq!(KeyWithIvRef::new(&key, &[0xa6; 8]).iv_opt(), Some([0xa6; 8].as_slice()));
/// ```
pub trait IvOptParams {
    /// Returns the IV bytes, or `None` to select the wrapper's standard IV.
    ///
    /// Constant time in this crate's containers, which return their slice
    /// without inspecting it; other implementations define their own timing.
    fn iv_opt(&self) -> Option<&[u8]>;
}

impl<T: IvParams + ?Sized> IvOptParams for T {
    /// Returns `Some` with the [`IvParams::iv`] bytes; timing is that of `iv`,
    /// which is constant time in this crate's containers.
    fn iv_opt(&self) -> Option<&[u8]> {
        Some(self.iv())
    }
}
