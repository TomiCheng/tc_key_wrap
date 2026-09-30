use core::error::Error;
use core::fmt;
use core::fmt::Display;

/// Why a key wrapper could not size, wrap or unwrap; `E` is the cipher's error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyWrapError<E> {
    /// A key-wrap operation was requested before successful initialization.
    NotInitialized,
    /// The engine was initialized for unwrapping, but wrapping was requested.
    NotForWrapping,
    /// The engine was initialized for wrapping, but unwrapping was requested.
    NotForUnwrapping,
    /// The wrap input length is invalid for the selected algorithm.
    InvalidWrapLength,
    /// The unwrap input length is invalid for the selected algorithm.
    InvalidUnwrapLength,
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
    /// The output buffer is shorter than required.
    OutputTooShort {
        /// Required output capacity in bytes.
        required: usize,
        /// Available output capacity in bytes.
        available: usize,
    },
    /// The wrapped data failed its integrity validation.
    IntegrityCheckFailed,
    /// The underlying cipher reported a processing error.
    Cipher(E),
}

impl<E: Error> Display for KeyWrapError<E> {
    /// Writes a description of the error, including the cipher's error for
    /// `Cipher`. Constant time: no key material is involved.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("key wrapper not initialized"),
            Self::NotForWrapping => f.write_str("key wrapper not set for wrapping"),
            Self::NotForUnwrapping => f.write_str("key wrapper not set for unwrapping"),
            Self::InvalidWrapLength => f.write_str("invalid key-wrap input length"),
            Self::InvalidUnwrapLength => f.write_str("invalid key-unwrap input length"),
            Self::UnsupportedBlockSize { actual, required } => write!(
                f,
                "unsupported block size: {actual} bytes; key wrapper requires {required} bytes"
            ),
            Self::BlockSizeTooShort { actual, minimum } => write!(
                f,
                "block size {actual} is too short; key wrapper requires at least {minimum} bytes"
            ),
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::IntegrityCheckFailed => f.write_str("key-wrap integrity check failed"),
            Self::Cipher(error) => write!(f, "underlying cipher error: {error}"),
        }
    }
}

impl<E: Error> Error for KeyWrapError<E> {}
