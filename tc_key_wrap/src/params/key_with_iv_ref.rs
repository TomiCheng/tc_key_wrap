//! Key-with-IV parameter abstraction.

use crate::IvParams;
use core::fmt;
use tc_block_cipher::KeyParams;

/// Borrowed key and initialization-vector parameters.
///
/// No allocation or copying. The caller owns the bytes and is responsible for
/// wiping the key; dropping this view modifies neither slice. The key wrapper
/// and the engine validate both lengths when initialized. `Debug` prints only
/// the lengths.
///
/// Constant time: no method inspects the key or IV contents.
///
/// # Example
///
/// ```
/// use tc_block_cipher::KeyParams;
/// use tc_key_wrap::{IvParams, KeyWithIvRef};
///
/// let (key, iv) = ([0x42; 16], [0xa6; 8]);
/// let params = KeyWithIvRef::new(&key, &iv);
/// assert_eq!(params.key(), &key);
/// assert_eq!(params.iv(), &iv);
/// assert_eq!(format!("{params:?}"), "KeyWithIvRef { key_len: 16, iv_len: 8 }");
/// ```
pub struct KeyWithIvRef<'a> {
    key: &'a [u8],
    iv: &'a [u8],
}

impl<'a> KeyWithIvRef<'a> {
    /// Borrows `key` and `iv` without copying or validating them.
    /// Constant time: does not inspect the bytes.
    pub const fn new(key: &'a [u8], iv: &'a [u8]) -> Self {
        Self { key, iv }
    }
}

impl KeyParams for KeyWithIvRef<'_> {
    /// Returns the borrowed key bytes.
    /// Constant time: does not inspect key contents.
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl IvParams for KeyWithIvRef<'_> {
    /// Returns the borrowed IV bytes.
    /// Constant time: does not inspect the IV.
    fn iv(&self) -> &[u8] {
        self.iv
    }
}

impl fmt::Debug for KeyWithIvRef<'_> {
    /// Writes the key and IV lengths, never their bytes.
    /// Constant time with respect to their contents; output timing depends on
    /// the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWithIvRef")
            .field("key_len", &self.key.len())
            .field("iv_len", &self.iv.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;
    #[cfg(feature = "alloc")]
    use std::vec;

    use super::{IvParams, KeyParams, KeyWithIvRef};
    #[cfg(feature = "alloc")]
    use crate::KeyWithIvOwned;

    struct KeyAndIv<'a> {
        key: &'a [u8],
        iv: &'a [u8],
    }

    impl KeyParams for KeyAndIv<'_> {
        fn key(&self) -> &[u8] {
            self.key
        }
    }

    impl IvParams for KeyAndIv<'_> {
        fn iv(&self) -> &[u8] {
            self.iv
        }
    }

    #[test]
    fn values_are_reachable_through_the_individual_traits() {
        let key = [0x01_u8, 0x02, 0x03];
        let iv = [0x04_u8, 0x05];
        let params = KeyAndIv { key: &key, iv: &iv };

        assert_eq!((&params as &dyn KeyParams).key(), &key);
        assert_eq!((&params as &dyn IvParams).iv(), &iv);
    }

    #[test]
    fn borrowed_values_are_reachable_through_a_trait_object() {
        let key = [0x01_u8, 0x02, 0x03];
        let iv = [0x04_u8, 0x05];
        let params = KeyWithIvRef::new(&key, &iv);

        assert_eq!((&params as &dyn KeyParams).key(), &key);
        assert_eq!((&params as &dyn IvParams).iv(), &iv);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owned_values_outlive_the_source_scope() {
        let params = {
            let key = vec![0x11_u8; 4];
            let iv = vec![0x22_u8; 2];
            KeyWithIvOwned::new(key, iv)
        };

        assert_eq!((&params as &dyn KeyParams).key(), &[0x11; 4]);
        assert_eq!((&params as &dyn IvParams).iv(), &[0x22; 2]);
    }

    #[test]
    fn debug_redacts_key_and_iv_material() {
        assert_eq!(
            format!("{:?}", KeyWithIvRef::new(&[0xff; 4], &[0xee; 2])),
            "KeyWithIvRef { key_len: 4, iv_len: 2 }"
        );
        #[cfg(feature = "alloc")]
        assert_eq!(
            format!("{:?}", KeyWithIvOwned::new(vec![0xff; 4], vec![0xee; 2])),
            "KeyWithIvOwned { key_len: 4, iv_len: 2 }"
        );
    }
}
