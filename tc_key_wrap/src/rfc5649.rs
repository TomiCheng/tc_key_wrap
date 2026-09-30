use crate::rfc3394::register;
use crate::{IvOptParams, KeyWrap, KeyWrapError, KeyWrapInit, KeyWrapInitError, WrapDirection};
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_constant_time::fixed_time_eq;
use tc_zeroize::Zeroize;

const BLOCK_BYTES: usize = 16;
const DEFAULT_AIV_PREFIX: [u8; 4] = [0xa6, 0x59, 0x59, 0xa6];

/// RFC 5649 key wrapping with padding over a cipher `C` with 16-byte blocks.
///
/// Wraps a key of any length from 1 byte; the output is the key rounded up to
/// a multiple of 8, plus 8. The alternative IV's 4-byte prefix comes through
/// [`IvOptParams`]: `None` selects the standard `A65959A6`, `Some` a custom
/// value that unwrapping must match.
///
/// Constant time exactly when the cipher is, except that unwrapping's padding
/// check follows the recovered length, which a successful result reveals.
/// Output that failed its check is wiped.
///
/// # Example
///
/// Wrapping a 7-byte key with a 192-bit AES key-encryption key, the second
/// RFC 5649 test vector:
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_key_wrap::{KeyWithIvOptRef, KeyWrap, KeyWrapInit, Rfc5649WrapEngine, WrapDirection};
///
/// let kek = [
///     0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70,
///     0x5b, 0xf1, 0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
/// ];
/// let key = [0x46, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69];
/// let mut wrapper = Rfc5649WrapEngine::new(AesEngine::new());
/// wrapper.init(WrapDirection::Wrap, &KeyWithIvOptRef::new(&kek, None))?;
/// let mut wrapped = [0; 16];
/// assert_eq!(wrapper.wrap_into(&key, &mut wrapped)?, 16);
/// assert_eq!(
///     wrapped,
///     [
///         0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41,
///         0x92, 0x00, 0xf2, 0xcc, 0xb5, 0x0b, 0xb2, 0x4f,
///     ]
/// );
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Rfc5649WrapEngine<C> {
    cipher: C,
    pre_iv: [u8; 4],
    direction: Option<WrapDirection>,
}

impl<C> Rfc5649WrapEngine<C> {
    /// Creates a wrapper over `cipher`; call `init` before use. Constant time.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            pre_iv: DEFAULT_AIV_PREFIX,
            direction: None,
        }
    }
}

impl<C: Default> Default for Rfc5649WrapEngine<C> {
    /// Wraps the cipher's default value, as [`new`](Self::new) does.
    /// Constant time.
    fn default() -> Self {
        Self::new(C::default())
    }
}

impl<C: Display> Display for Rfc5649WrapEngine<C> {
    /// Writes the cipher's name followed by `/RFC5649Wrap`. Constant time: no
    /// key material is inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/RFC5649Wrap")
    }
}

impl<C: BlockCipher> Rfc5649WrapEngine<C> {
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

impl<C: BlockCipher> KeyWrap for Rfc5649WrapEngine<C> {
    type Error = KeyWrapError<C::Error>;

    /// Returns the key length rounded up to a multiple of 8, plus 8; the key must
    /// be 1 byte to 4 GiB. Constant time: depends only on the public length.
    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.check_block_size()?;
        if input_len == 0 || u32::try_from(input_len).is_err() {
            return Err(KeyWrapError::InvalidWrapLength);
        }
        input_len
            .checked_add(7)
            .map(|length| length & !7)
            .and_then(|length| length.checked_add(8))
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
        // Zero-fill first: these zeros are the padding up to a multiple of 8 bytes.
        block.fill(0);
        block[..4].copy_from_slice(&self.pre_iv);
        block[4..8].copy_from_slice(&(input.len() as u32).to_be_bytes());
        block[8..8 + input.len()].copy_from_slice(input);
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
    /// A prefix, length or padding that does not match returns
    /// `IntegrityCheckFailed` and wipes the output. Constant time exactly when
    /// the cipher is, except that the padding check follows the recovered
    /// length, which a successful result reveals.
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

        let padded = &mut output[..required];
        let aiv = match register::unwrap_into(&mut self.cipher, input, padded) {
            Ok(aiv) => aiv,
            Err(error) => {
                padded.zeroize();
                return Err(KeyWrapError::Cipher(error));
            }
        };

        let mut valid = fixed_time_eq(&aiv[..4], &self.pre_iv);
        let message_len = u32::from_be_bytes([aiv[4], aiv[5], aiv[6], aiv[7]]) as usize;
        let upper = padded.len();
        let lower = upper - 8;
        if message_len <= lower || message_len > upper {
            valid = false;
        }
        let padding_len = match upper.checked_sub(message_len) {
            Some(length) if length < 8 => length,
            _ => {
                valid = false;
                4
            }
        };
        let zeroes = [0u8; 8];
        if !fixed_time_eq(&padded[upper - padding_len..], &zeroes[..padding_len]) {
            valid = false;
        }
        if !valid {
            padded.zeroize();
            return Err(KeyWrapError::IntegrityCheckFailed);
        }
        Ok(message_len)
    }
}

impl<C, P> KeyWrapInit<P> for Rfc5649WrapEngine<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvOptParams + ?Sized,
{
    type Error = KeyWrapInitError<<C as BlockCipherInit<P>>::Error>;

    /// Installs the cipher key and the AIV prefix from `params` for `direction`;
    /// a custom prefix must be 4 bytes. A failed `init` leaves the wrapper uninitialized.
    /// Constant time exactly when the cipher's key setup is.
    fn init(&mut self, direction: WrapDirection, params: &P) -> Result<(), Self::Error> {
        // Invalidate first, so a failure at any step leaves neither the previous direction nor the
        // previous AIV prefix usable.
        self.direction = None;

        let actual = self.cipher.block_size();
        if actual != BLOCK_BYTES {
            return Err(KeyWrapInitError::UnsupportedBlockSize {
                actual,
                required: BLOCK_BYTES,
            });
        }

        let pre_iv = match params.iv_opt() {
            Some(iv) => iv
                .try_into()
                .map_err(|_| KeyWrapInitError::InvalidIvLength {
                    actual: iv.len(),
                    required: 4,
                })?,
            None => DEFAULT_AIV_PREFIX,
        };

        let cipher_direction = match direction {
            WrapDirection::Wrap => CipherDirection::Encrypt,
            WrapDirection::Unwrap => CipherDirection::Decrypt,
        };
        self.cipher
            .init(cipher_direction, params)
            .map_err(KeyWrapInitError::Cipher)?;

        self.pre_iv = pre_iv;
        self.direction = Some(direction);
        Ok(())
    }
}
