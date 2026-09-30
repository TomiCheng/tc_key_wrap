use crate::IvOptParams;
use core::fmt;
use tc_block_cipher::KeyParams;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

/// Owned, fixed-size key and optional initialization vector, wiped on drop.
///
/// `None` selects the key wrapper's standard IV; the IV size `I` is still part
/// of the type. No allocator is required, and nothing is validated here.
/// Storing the arrays does not erase other copies. `Debug` prints only the
/// lengths.
///
/// Constant time: no method inspects the key or IV contents.
///
/// # Example
///
/// ```
/// use tc_key_wrap::{IvOptParams, KeyWithIvOptFixed};
///
/// let params = KeyWithIvOptFixed::<16, 8>::new([0x42; 16], None);
/// assert_eq!(params.iv_opt(), None);
/// ```
pub struct KeyWithIvOptFixed<const K: usize, const I: usize> {
    key: [u8; K],
    iv: Option<[u8; I]>,
}

impl<const K: usize, const I: usize> KeyWithIvOptFixed<K, I> {
    /// Takes ownership of `key` and `iv` without validating them. Constant time
    /// with respect to their contents.
    pub const fn new(key: [u8; K], iv: Option<[u8; I]>) -> Self {
        Self { key, iv }
    }
}

impl<const K: usize, const I: usize> KeyParams for KeyWithIvOptFixed<K, I> {
    /// Returns the stored key without copying it. Constant time.
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl<const K: usize, const I: usize> IvOptParams for KeyWithIvOptFixed<K, I> {
    /// Returns the stored IV, or `None` for the wrapper's standard IV.
    /// Constant time.
    fn iv_opt(&self) -> Option<&[u8]> {
        self.iv.as_ref().map(|iv| iv.as_slice())
    }
}

impl<const K: usize, const I: usize> fmt::Debug for KeyWithIvOptFixed<K, I> {
    /// Writes the key and IV lengths, never their bytes. Constant time with
    /// respect to their contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWithIvOptFixed")
            .field("key_len", &K)
            .field("iv_len", &self.iv.as_ref().map(|_| I))
            .finish()
    }
}

impl<const K: usize, const I: usize> Zeroize for KeyWithIvOptFixed<K, I> {
    /// Overwrites the key and the IV with zeros and leaves the IV `None`.
    /// Constant time.
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl<const K: usize, const I: usize> Drop for KeyWithIvOptFixed<K, I> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const K: usize, const I: usize> ZeroizeOnDrop for KeyWithIvOptFixed<K, I> {}
