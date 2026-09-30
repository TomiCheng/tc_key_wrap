use core::error::Error;
use core::fmt;
use core::fmt::Display;

/// Why a key wrapper could not be initialized; `E` is the cipher's
/// initialization error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyWrapInitError<E> {
    /// A custom IV was supplied while initializing for unwrap.
    IvNotAllowedForUnwrap,
    /// The supplied initialization-vector length is not supported.
    InvalidIvLength {
        /// Supplied IV length, in bytes.
        actual: usize,
        /// IV length required by the wrapper, in bytes.
        required: usize,
    },
    /// The underlying cipher's block size is not supported.
    UnsupportedBlockSize {
        /// The underlying cipher's block size, in bytes.
        actual: usize,
        /// The block size required by the wrapper, in bytes.
        required: usize,
    },
    /// The underlying cipher's block size is shorter than the wrapper permits.
    BlockSizeTooShort {
        /// The underlying cipher's block size, in bytes.
        actual: usize,
        /// The minimum block size accepted by the wrapper, in bytes.
        minimum: usize,
    },
    /// The underlying cipher reported an initialization error.
    Cipher(E),
}

impl<E: Error> Display for KeyWrapInitError<E> {
    /// Writes a description of the error, including the cipher's error for
    /// `Cipher`. Constant time: no key material is involved.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IvNotAllowedForUnwrap => {
                f.write_str("an external IV is not allowed when unwrapping")
            }
            Self::InvalidIvLength { actual, required } => write!(
                f,
                "invalid key-wrap IV length: {actual} bytes; expected {required}"
            ),
            Self::UnsupportedBlockSize { actual, required } => write!(
                f,
                "unsupported block size: {actual} bytes; key wrapper requires {required} bytes"
            ),
            Self::BlockSizeTooShort { actual, minimum } => write!(
                f,
                "block size {actual} is too short; key wrapper requires at least {minimum} bytes"
            ),
            Self::Cipher(error) => write!(f, "underlying cipher initialization error: {error}"),
        }
    }
}

impl<E: Error> Error for KeyWrapInitError<E> {}
