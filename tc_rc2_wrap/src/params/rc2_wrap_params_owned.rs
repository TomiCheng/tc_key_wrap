use alloc::vec::Vec;
use core::fmt;
use tc_block_cipher::KeyParams;
use tc_key_wrap::IvOptParams;
use tc_rc_cipher::{Rc2Params, Rc2ParamsOwned};
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

/// Owned RC2 key-encryption key, effective key size and optional IV, wiped on
/// drop.
///
/// The owning counterpart of `Rc2WrapParamsRef`, with the same `None` and
/// `Some` rules for the IV. Construction takes the vectors without copying
/// them, and nothing is validated here. Wiping does not erase copies held
/// elsewhere. `Debug` prints only the lengths and the effective size.
///
/// Constant time: no method inspects the key or IV contents.
///
/// # Example
///
/// ```
/// use tc_key_wrap::IvOptParams;
/// use tc_rc_cipher::Rc2Params;
/// use tc_rc2_wrap::Rc2WrapParamsOwned;
///
/// let params = Rc2WrapParamsOwned::with_effective_key_bits(vec![0x42; 16], 40, None);
/// assert_eq!(params.effective_key_bits(), 40);
/// assert_eq!(params.iv_opt(), None);
/// assert_eq!(
///     format!("{params:?}"),
///     "Rc2WrapParamsOwned { key_len: 16, effective_key_bits: 40, iv_len: None }"
/// );
/// ```
pub struct Rc2WrapParamsOwned {
    rc2: Rc2ParamsOwned,
    iv: Option<Vec<u8>>,
}

impl Rc2WrapParamsOwned {
    /// Takes `key` and `iv`, using the key's full length as the effective size
    /// as `Rc2ParamsOwned::new` does. Constant time: moves the vectors without
    /// inspecting their bytes.
    pub fn new(key: Vec<u8>, iv: Option<Vec<u8>>) -> Self {
        Self {
            rc2: Rc2ParamsOwned::new(key),
            iv,
        }
    }

    /// Takes `key` and `iv` with an explicit effective size in bits.
    /// Constant time: moves the vectors without inspecting their bytes.
    pub const fn with_effective_key_bits(
        key: Vec<u8>,
        effective_key_bits: usize,
        iv: Option<Vec<u8>>,
    ) -> Self {
        Self {
            rc2: Rc2ParamsOwned::with_effective_key_bits(key, effective_key_bits),
            iv,
        }
    }
}

impl KeyParams for Rc2WrapParamsOwned {
    /// Returns the stored key-encryption key without copying it. Constant time.
    fn key(&self) -> &[u8] {
        self.rc2.key()
    }
}

impl Rc2Params for Rc2WrapParamsOwned {
    /// Returns the effective key size in bits. Constant time.
    fn effective_key_bits(&self) -> usize {
        self.rc2.effective_key_bits()
    }
}

impl IvOptParams for Rc2WrapParamsOwned {
    /// Returns the stored IV, or `None` to draw one when wrapping.
    /// Constant time.
    fn iv_opt(&self) -> Option<&[u8]> {
        self.iv.as_deref()
    }
}

impl fmt::Debug for Rc2WrapParamsOwned {
    /// Writes the key and IV lengths and the effective size, never the bytes.
    /// Constant time with respect to their contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rc2WrapParamsOwned")
            .field("key_len", &self.rc2.key().len())
            .field("effective_key_bits", &self.rc2.effective_key_bits())
            .field("iv_len", &self.iv.as_ref().map(Vec::len))
            .finish()
    }
}

impl Zeroize for Rc2WrapParamsOwned {
    /// Overwrites the key and the IV with zeros and leaves the IV `None`.
    /// Constant time.
    fn zeroize(&mut self) {
        self.rc2.zeroize();
        self.iv.zeroize();
    }
}

impl Drop for Rc2WrapParamsOwned {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Rc2WrapParamsOwned {}
