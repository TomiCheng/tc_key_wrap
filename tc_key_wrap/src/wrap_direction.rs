//! Key-wrapping operation direction.

/// The operation selected during key-wrapper initialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapDirection {
    /// Protect key material and produce a wrapped blob.
    Wrap,
    /// Recover and authenticate key material from a wrapped blob.
    Unwrap,
}
