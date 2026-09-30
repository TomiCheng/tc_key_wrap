//! Initialization-vector parameter abstraction.

/// Parameters that provide an initialization vector.
///
/// Implementations only expose the caller's value; the consuming key wrapper
/// defines and validates the supported IV lengths. Implement this trait,
/// alongside the engine's key parameter trait, to pass your own parameter type
/// to a key wrapper, or use [`KeyWithIvRef`](crate::KeyWithIvRef),
/// [`KeyWithIvFixed`](crate::KeyWithIvFixed) or
/// `KeyWithIvOwned`.
pub trait IvParams {
    /// Returns the initialization-vector bytes.
    ///
    /// Constant time in this crate's containers, which return their slice
    /// without inspecting it; other implementations define their own timing.
    fn iv(&self) -> &[u8];
}
