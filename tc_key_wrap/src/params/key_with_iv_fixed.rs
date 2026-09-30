use crate::IvParams;
use core::fmt;
use tc_block_cipher::KeyParams;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

/// Owned, fixed-size key and initialization-vector parameters, wiped on drop.
///
/// No allocator is required. The array sizes are part of the type. This
/// wrapper does not restrict them; the key wrapper and the engine validate both
/// lengths when initialized. Storing the arrays here does not erase other
/// copies, including the caller's originals. The IV is not secret, but is
/// wiped with the key to keep one rule. `Debug` prints only the lengths.
///
/// Constant time: no method inspects the key or IV contents.
///
/// # Example
///
/// ```
/// use tc_block_cipher::KeyParams;
/// use tc_key_wrap::{IvParams, KeyWithIvFixed};
///
/// let params = KeyWithIvFixed::new([0x42; 16], [0xa6; 8]);
/// assert_eq!(params.key(), &[0x42; 16]);
/// assert_eq!(params.iv(), &[0xa6; 8]);
/// assert_eq!(format!("{params:?}"), "KeyWithIvFixed { key_len: 16, iv_len: 8 }");
/// ```
pub struct KeyWithIvFixed<const K: usize, const I: usize> {
    key: [u8; K],
    iv: [u8; I],
}

impl<const K: usize, const I: usize> KeyWithIvFixed<K, I> {
    /// Takes ownership of `key` and `iv` without validating their sizes.
    /// Constant time with respect to their contents; copying cost depends on
    /// `K` and `I`.
    pub const fn new(key: [u8; K], iv: [u8; I]) -> Self {
        Self { key, iv }
    }
}

impl<const K: usize, const I: usize> KeyParams for KeyWithIvFixed<K, I> {
    /// Returns the stored key bytes without copying them.
    /// Constant time: does not inspect key contents.
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl<const K: usize, const I: usize> IvParams for KeyWithIvFixed<K, I> {
    /// Returns the stored IV bytes without copying them.
    /// Constant time: does not inspect the IV.
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

impl<const K: usize, const I: usize> fmt::Debug for KeyWithIvFixed<K, I> {
    /// Writes the key and IV lengths, never their bytes.
    /// Constant time with respect to their contents; output timing depends on
    /// the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWithIvFixed")
            .field("key_len", &K)
            .field("iv_len", &I)
            .finish()
    }
}

impl<const K: usize, const I: usize> Zeroize for KeyWithIvFixed<K, I> {
    /// Overwrites the key and the IV with zeros. Constant time.
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl<const K: usize, const I: usize> Drop for KeyWithIvFixed<K, I> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const K: usize, const I: usize> ZeroizeOnDrop for KeyWithIvFixed<K, I> {}
