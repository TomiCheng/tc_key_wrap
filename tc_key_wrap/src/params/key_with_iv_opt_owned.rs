use crate::IvOptParams;
use alloc::vec::Vec;
use core::fmt;
use tc_block_cipher::KeyParams;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

/// Owned key and optional initialization-vector vectors, wiped on drop.
///
/// Available with the `alloc` feature. `None` selects the key wrapper's
/// standard IV. Construction transfers the vectors without cloning them, and
/// nothing is validated here. Wiping does not erase copies held elsewhere.
/// `Debug` prints only the lengths.
///
/// Constant time: no method inspects the key or IV contents.
///
/// # Example
///
/// ```
/// use tc_key_wrap::{IvOptParams, KeyWithIvOptOwned};
///
/// let params = KeyWithIvOptOwned::new(vec![0x42; 32], Some(vec![0xa6; 8]));
/// assert_eq!(params.iv_opt(), Some([0xa6; 8].as_slice()));
/// ```
pub struct KeyWithIvOptOwned {
    key: Vec<u8>,
    iv: Option<Vec<u8>>,
}

impl KeyWithIvOptOwned {
    /// Takes ownership of `key` and `iv` without allocating or validating them.
    /// Constant time.
    pub const fn new(key: Vec<u8>, iv: Option<Vec<u8>>) -> Self {
        Self { key, iv }
    }
}

impl KeyParams for KeyWithIvOptOwned {
    /// Returns the stored key without copying it. Constant time.
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl IvOptParams for KeyWithIvOptOwned {
    /// Returns the stored IV, or `None` for the wrapper's standard IV.
    /// Constant time.
    fn iv_opt(&self) -> Option<&[u8]> {
        self.iv.as_deref()
    }
}

impl fmt::Debug for KeyWithIvOptOwned {
    /// Writes the key and IV lengths, never their bytes. Constant time with
    /// respect to their contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWithIvOptOwned")
            .field("key_len", &self.key.len())
            .field("iv_len", &self.iv.as_ref().map(Vec::len))
            .finish()
    }
}

impl Zeroize for KeyWithIvOptOwned {
    /// Overwrites the key and the IV with zeros and leaves the IV `None`.
    /// Constant time.
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl Drop for KeyWithIvOptOwned {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KeyWithIvOptOwned {}
