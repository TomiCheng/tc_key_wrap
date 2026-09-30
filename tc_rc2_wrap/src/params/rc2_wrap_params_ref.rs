use core::fmt;
use tc_block_cipher::KeyParams;
use tc_key_wrap::IvOptParams;
use tc_rc_cipher::{Rc2Params, Rc2ParamsRef};

/// Borrowed RC2 key-encryption key, effective key size and optional IV.
///
/// The one parameter type that `Rc2WrapEngine` needs: it implements
/// `KeyParams`, `Rc2Params` and `IvOptParams`. For wrapping, `None` draws a
/// random IV from the wrapper's generator and `Some` supplies an 8-byte IV;
/// unwrapping takes `None`. Nothing is copied or validated; the wrapper checks
/// the IV and the RC2 engine checks the key and effective size in `init`. The
/// caller owns the bytes and wipes the key. `Debug` prints only the lengths
/// and the effective size.
///
/// Constant time: no method inspects the key or IV contents.
///
/// # Example
///
/// ```
/// use tc_key_wrap::IvOptParams;
/// use tc_rc_cipher::Rc2Params;
/// use tc_rc2_wrap::Rc2WrapParamsRef;
///
/// let kek = [0x42; 16];
/// let params = Rc2WrapParamsRef::new(&kek, None);
/// assert_eq!(params.effective_key_bits(), 128);
/// assert_eq!(params.iv_opt(), None);
///
/// let params = Rc2WrapParamsRef::with_effective_key_bits(&kek, 40, Some(&[0x24; 8]));
/// assert_eq!(
///     format!("{params:?}"),
///     "Rc2WrapParamsRef { key_len: 16, effective_key_bits: 40, iv_len: Some(8) }"
/// );
/// ```
#[derive(Clone, Copy)]
pub struct Rc2WrapParamsRef<'a> {
    rc2: Rc2ParamsRef<'a>,
    iv: Option<&'a [u8]>,
}

impl<'a> Rc2WrapParamsRef<'a> {
    /// Borrows `key` and `iv`, using the key's full length as the effective
    /// size as `Rc2ParamsRef::new` does. Constant time.
    pub const fn new(key: &'a [u8], iv: Option<&'a [u8]>) -> Self {
        Self {
            rc2: Rc2ParamsRef::new(key),
            iv,
        }
    }

    /// Borrows `key` and `iv` with an explicit effective size in bits.
    /// Constant time.
    pub const fn with_effective_key_bits(
        key: &'a [u8],
        effective_key_bits: usize,
        iv: Option<&'a [u8]>,
    ) -> Self {
        Self {
            rc2: Rc2ParamsRef::with_effective_key_bits(key, effective_key_bits),
            iv,
        }
    }
}

impl KeyParams for Rc2WrapParamsRef<'_> {
    /// Returns the borrowed key-encryption key. Constant time.
    fn key(&self) -> &[u8] {
        self.rc2.key()
    }
}

impl Rc2Params for Rc2WrapParamsRef<'_> {
    /// Returns the effective key size in bits. Constant time.
    fn effective_key_bits(&self) -> usize {
        self.rc2.effective_key_bits()
    }
}

impl IvOptParams for Rc2WrapParamsRef<'_> {
    /// Returns the borrowed IV, or `None` to draw one when wrapping.
    /// Constant time.
    fn iv_opt(&self) -> Option<&[u8]> {
        self.iv
    }
}

impl fmt::Debug for Rc2WrapParamsRef<'_> {
    /// Writes the key and IV lengths and the effective size, never the bytes.
    /// Constant time with respect to their contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rc2WrapParamsRef")
            .field("key_len", &self.rc2.key().len())
            .field("effective_key_bits", &self.rc2.effective_key_bits())
            .field("iv_len", &self.iv.map(<[u8]>::len))
            .finish()
    }
}
