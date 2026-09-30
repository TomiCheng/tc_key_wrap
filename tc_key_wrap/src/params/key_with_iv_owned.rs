use crate::IvParams;
use alloc::vec::Vec;
use core::fmt;
use tc_block_cipher::KeyParams;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

/// Owned key and initialization-vector vectors, wiped on drop.
///
/// Available with the `alloc` feature.
///
/// Construction transfers the vectors rather than cloning their bytes. The key
/// wrapper and the engine validate both lengths when initialized. Wiping this
/// container does not erase copies held elsewhere. The IV is not secret, but is
/// wiped with the key to keep one rule. `Debug` prints only the lengths.
///
/// Constant time: no method inspects the key or IV contents.
///
/// # Example
///
/// ```
/// use tc_key_wrap::{IvParams, KeyWithIvOwned};
///
/// let params = KeyWithIvOwned::new(vec![0x42; 32], vec![0xa6; 8]);
/// assert_eq!(params.iv(), &[0xa6; 8]);
/// assert_eq!(format!("{params:?}"), "KeyWithIvOwned { key_len: 32, iv_len: 8 }");
/// ```
pub struct KeyWithIvOwned {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl KeyWithIvOwned {
    /// Takes ownership of `key` and `iv` without allocating or validating the
    /// lengths. Constant time: moves vector metadata without inspecting the
    /// bytes.
    pub const fn new(key: Vec<u8>, iv: Vec<u8>) -> Self {
        Self { key, iv }
    }
}

impl KeyParams for KeyWithIvOwned {
    /// Returns the stored key bytes without copying them.
    /// Constant time: does not inspect key contents.
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl IvParams for KeyWithIvOwned {
    /// Returns the stored IV bytes without copying them.
    /// Constant time: does not inspect the IV.
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

impl fmt::Debug for KeyWithIvOwned {
    /// Writes the key and IV lengths, never their bytes.
    /// Constant time with respect to their contents; output timing depends on
    /// the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWithIvOwned")
            .field("key_len", &self.key.len())
            .field("iv_len", &self.iv.len())
            .finish()
    }
}

impl Zeroize for KeyWithIvOwned {
    /// Overwrites the key and the IV with zeros. Constant time.
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl Drop for KeyWithIvOwned {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KeyWithIvOwned {}
