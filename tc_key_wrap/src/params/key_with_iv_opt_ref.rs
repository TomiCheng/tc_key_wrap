use crate::IvOptParams;
use core::fmt;
use tc_block_cipher::KeyParams;

/// Borrowed key and optional initialization vector.
///
/// `None` selects the key wrapper's standard IV. Nothing is copied or
/// validated; the wrapper and its cipher check both lengths in `init`. The
/// caller owns the bytes and wipes the key. `Debug` prints only the lengths.
///
/// Constant time: no method inspects the key or IV contents.
///
/// # Example
///
/// ```
/// use tc_key_wrap::{IvOptParams, KeyWithIvOptRef};
///
/// let kek = [0x42; 16];
/// assert_eq!(KeyWithIvOptRef::new(&kek, None).iv_opt(), None);
/// assert_eq!(
///     format!("{:?}", KeyWithIvOptRef::new(&kek, Some(&[0xa6; 8]))),
///     "KeyWithIvOptRef { key_len: 16, iv_len: Some(8) }"
/// );
/// ```
pub struct KeyWithIvOptRef<'a> {
    key: &'a [u8],
    iv: Option<&'a [u8]>,
}

impl<'a> KeyWithIvOptRef<'a> {
    /// Borrows `key` and `iv` without copying or validating them.
    /// Constant time.
    pub const fn new(key: &'a [u8], iv: Option<&'a [u8]>) -> Self {
        Self { key, iv }
    }
}

impl KeyParams for KeyWithIvOptRef<'_> {
    /// Returns the stored key without copying it. Constant time.
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl IvOptParams for KeyWithIvOptRef<'_> {
    /// Returns the stored IV, or `None` for the wrapper's standard IV.
    /// Constant time.
    fn iv_opt(&self) -> Option<&[u8]> {
        self.iv
    }
}

impl fmt::Debug for KeyWithIvOptRef<'_> {
    /// Writes the key and IV lengths, never their bytes. Constant time with
    /// respect to their contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWithIvOptRef")
            .field("key_len", &self.key.len())
            .field("iv_len", &self.iv.map(<[u8]>::len))
            .finish()
    }
}
