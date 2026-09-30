pub(crate) mod register;

use crate::{IvOptParams, KeyWrap, KeyWrapError, KeyWrapInit, KeyWrapInitError, WrapDirection};
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_constant_time::fixed_time_eq;
use tc_zeroize::Zeroize;

const BLOCK_BYTES: usize = 16;
const DEFAULT_IV: [u8; 8] = [0xa6; 8];

/// RFC 3394 key wrapping (AES key wrap) over a cipher `C` with 16-byte blocks.
///
/// The key to wrap is 8 bytes or more, in multiples of 8, and the output is 8
/// bytes longer. The IV comes through [`IvOptParams`]: `None` selects the
/// standard `A6A6A6A6A6A6A6A6`, `Some` an 8-byte custom value that unwrapping
/// must match.
///
/// Constant time exactly when the cipher is: the register loop and the IV
/// check do no data-dependent work. Output that failed its check is wiped.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_key_wrap::{KeyWithIvOptRef, KeyWrap, KeyWrapInit, Rfc3394WrapEngine, WrapDirection};
///
/// let kek = [0x42; 32];
/// let key = [0x11; 16];
/// let params = KeyWithIvOptRef::new(&kek, None);
/// let mut wrapper = Rfc3394WrapEngine::new(AesEngine::new());
///
/// wrapper.init(WrapDirection::Wrap, &params)?;
/// let mut wrapped = [0; 24];
/// wrapper.wrap_into(&key, &mut wrapped)?;
///
/// wrapper.init(WrapDirection::Unwrap, &params)?;
/// let mut recovered = [0; 16];
/// assert_eq!(wrapper.unwrap_into(&wrapped, &mut recovered)?, 16);
/// assert_eq!(recovered, key);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Rfc3394WrapEngine<C> {
    cipher: C,
    reverse_direction: bool,
    iv: [u8; 8],
    direction: Option<WrapDirection>,
}

impl<C> Rfc3394WrapEngine<C> {
    /// Creates a wrapper over `cipher`; call `init` before use. Constant time.
    pub const fn new(cipher: C) -> Self {
        Self::with_reverse_direction(cipher, false)
    }

    /// Creates a wrapper that, when `reverse_direction` is true, wraps with the
    /// cipher's decryption direction and unwraps with its encryption direction,
    /// as Bouncy Castle's `useReverseDirection` does. Constant time.
    pub const fn with_reverse_direction(cipher: C, reverse_direction: bool) -> Self {
        Self {
            cipher,
            reverse_direction,
            iv: DEFAULT_IV,
            direction: None,
        }
    }
}

impl<C: Default> Default for Rfc3394WrapEngine<C> {
    /// Wraps the cipher's default value, as [`new`](Self::new) does.
    /// Constant time.
    fn default() -> Self {
        Self::new(C::default())
    }
}

impl<C: Display> Display for Rfc3394WrapEngine<C> {
    /// Writes the cipher's name followed by `/RFC3394Wrap`. Constant time: no
    /// key material is inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/RFC3394Wrap")
    }
}

impl<C: BlockCipher> Rfc3394WrapEngine<C> {
    fn check_block_size(&self) -> Result<(), KeyWrapError<C::Error>> {
        let actual = self.cipher.block_size();
        if actual != BLOCK_BYTES {
            return Err(KeyWrapError::UnsupportedBlockSize {
                actual,
                required: BLOCK_BYTES,
            });
        }
        Ok(())
    }
}

impl<C: BlockCipher> KeyWrap for Rfc3394WrapEngine<C> {
    type Error = KeyWrapError<C::Error>;

    /// Returns `input_len + 8`; the key must be 8 bytes or more, in multiples
    /// of 8. Constant time: depends only on the public length.
    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.check_block_size()?;
        if input_len < 8 || input_len % 8 != 0 {
            return Err(KeyWrapError::InvalidWrapLength);
        }
        input_len
            .checked_add(8)
            .ok_or(KeyWrapError::InvalidWrapLength)
    }

    /// Returns `input_len - 8`; the input must be 16 bytes or more, in multiples
    /// of 8. Constant time: depends only on the public length.
    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.check_block_size()?;
        if input_len < 16 || input_len % 8 != 0 {
            return Err(KeyWrapError::InvalidUnwrapLength);
        }
        Ok(input_len - 8)
    }

    /// Wraps `input` into `output` and returns the wrapped length.
    ///
    /// On a cipher error the output is wiped. Constant time exactly when the
    /// cipher is.
    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Wrap) => {}
            Some(WrapDirection::Unwrap) => return Err(KeyWrapError::NotForWrapping),
            None => return Err(KeyWrapError::NotInitialized),
        }

        let required = self.wrapped_len(input.len())?;
        if output.len() < required {
            return Err(KeyWrapError::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        let block = &mut output[..required];
        block[..8].copy_from_slice(&self.iv);
        block[8..].copy_from_slice(input);
        if let Err(error) = register::wrap_in_place(&mut self.cipher, block) {
            // The block still holds the plaintext key or partly processed data; do not leave it to
            // the caller.
            block.zeroize();
            return Err(KeyWrapError::Cipher(error));
        }
        Ok(required)
    }

    /// Unwraps `input` into `output` and returns the key length.
    ///
    /// A recovered IV that does not match returns `IntegrityCheckFailed` and
    /// wipes the output. Constant time exactly when the cipher is; only the
    /// result reveals whether the check passed.
    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Unwrap) => {}
            Some(WrapDirection::Wrap) => return Err(KeyWrapError::NotForUnwrapping),
            None => return Err(KeyWrapError::NotInitialized),
        }

        let required = self.max_unwrapped_len(input.len())?;
        if output.len() < required {
            return Err(KeyWrapError::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        let recovered = &mut output[..required];
        let a = match register::unwrap_into(&mut self.cipher, input, recovered) {
            Ok(a) => a,
            Err(error) => {
                recovered.zeroize();
                return Err(KeyWrapError::Cipher(error));
            }
        };
        if !fixed_time_eq(&a, &self.iv) {
            recovered.zeroize();
            return Err(KeyWrapError::IntegrityCheckFailed);
        }
        Ok(required)
    }
}

impl<C, P> KeyWrapInit<P> for Rfc3394WrapEngine<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvOptParams + ?Sized,
{
    type Error = KeyWrapInitError<<C as BlockCipherInit<P>>::Error>;

    /// Installs the cipher key and the IV from `params` for `direction`; a custom
    /// IV must be 8 bytes. A failed `init` leaves the wrapper uninitialized. Constant time exactly
    /// when the cipher's key setup is.
    fn init(&mut self, direction: WrapDirection, params: &P) -> Result<(), Self::Error> {
        // Invalidate first, so a failure at any step leaves neither the previous direction nor the
        // previous IV usable.
        self.direction = None;

        let actual = self.cipher.block_size();
        if actual != BLOCK_BYTES {
            return Err(KeyWrapInitError::UnsupportedBlockSize {
                actual,
                required: BLOCK_BYTES,
            });
        }

        let iv = match params.iv_opt() {
            Some(iv) => iv
                .try_into()
                .map_err(|_| KeyWrapInitError::InvalidIvLength {
                    actual: iv.len(),
                    required: 8,
                })?,
            None => DEFAULT_IV,
        };

        let encrypt = (direction == WrapDirection::Wrap) != self.reverse_direction;
        let cipher_direction = if encrypt {
            CipherDirection::Encrypt
        } else {
            CipherDirection::Decrypt
        };
        self.cipher
            .init(cipher_direction, params)
            .map_err(KeyWrapInitError::Cipher)?;

        self.iv = iv;
        self.direction = Some(direction);
        Ok(())
    }
}
