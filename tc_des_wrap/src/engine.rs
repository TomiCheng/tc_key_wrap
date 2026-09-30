//! CMS Triple-DES key-wrap engine.

use core::fmt::{Display, Formatter};
use rand_core::CryptoRng;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyParams, KeyRef};
use tc_constant_time::fixed_time_eq;
use tc_des::DesEdeEngine;
use tc_digest::Digest;
use tc_key_wrap::{IvOptParams, KeyWrap, KeyWrapInit, WrapDirection};
use tc_sha::Sha1Digest;
use tc_zeroize::{Zeroize, Zeroizing};

use crate::{DesEdeWrapError, DesEdeWrapInitError};

const BLOCK_BYTES: usize = 8;
const CHECKSUM_BYTES: usize = 8;
const WRAP_OVERHEAD: usize = BLOCK_BYTES + CHECKSUM_BYTES;
const IV2: [u8; BLOCK_BYTES] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

/// CMS Triple-DES key wrapping (RFC 3217) with SHA-1 integrity.
///
/// Wraps a key whose length is a multiple of 8 bytes, normally a 24-byte
/// Triple DES key, under a 16- or 24-byte key-encryption key. The output is 16
/// bytes longer. Wrapping takes an 8-byte IV from its parameters or, given
/// `None`, draws one from `R`; unwrapping recovers the IV from the input.
///
/// Variable time: the Triple DES engine looks up S-boxes with secret data.
/// Output left by a failed wrap is wiped.
///
/// # Example
///
/// ```
/// use rand::SeedableRng;
/// use rand::rngs::StdRng;
/// use tc_des_wrap::DesEdeWrapEngine;
/// use tc_key_wrap::{KeyWithIvOptRef, KeyWrap, KeyWrapInit, WrapDirection};
///
/// let kek: [u8; 24] = core::array::from_fn(|i| i as u8);
/// let key = [0x11; 24];
/// let params = KeyWithIvOptRef::new(&kek, None);
/// let mut wrapper = DesEdeWrapEngine::new(StdRng::seed_from_u64(1));
///
/// wrapper.init(WrapDirection::Wrap, &params)?;
/// let mut wrapped = [0; 40];
/// wrapper.wrap_into(&key, &mut wrapped)?;
///
/// wrapper.init(WrapDirection::Unwrap, &params)?;
/// let mut recovered = [0; 24];
/// assert_eq!(wrapper.unwrap_into(&wrapped, &mut recovered)?, 24);
/// assert_eq!(recovered, key);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct DesEdeWrapEngine<R> {
    cipher: DesEdeEngine,
    sha1: Sha1Digest,
    rng: R,
    iv: [u8; BLOCK_BYTES],
    direction: Option<WrapDirection>,
}

impl<R> DesEdeWrapEngine<R> {
    /// Creates a wrapper that draws a random IV from `rng` when `init` is given
    /// none; call `init` before use. Constant time.
    pub fn new(rng: R) -> Self {
        Self {
            cipher: DesEdeEngine::new(),
            sha1: Sha1Digest::new(),
            rng,
            iv: [0; BLOCK_BYTES],
            direction: None,
        }
    }

    fn checksum(&mut self, input: &[u8]) -> Zeroizing<[u8; CHECKSUM_BYTES]> {
        let mut digest = Zeroizing::new([0u8; 20]);
        self.sha1.update(input);
        self.sha1.do_final(&mut digest[..]);
        let mut checksum = Zeroizing::new([0u8; CHECKSUM_BYTES]);
        checksum.copy_from_slice(&digest[..CHECKSUM_BYTES]);
        checksum
    }

    fn encrypt_cbc(
        &mut self,
        buffer: &mut [u8],
        iv: &[u8; BLOCK_BYTES],
    ) -> Result<(), DesEdeWrapError> {
        let mut chain = Zeroizing::new(*iv);
        let mut input = Zeroizing::new([0u8; BLOCK_BYTES]);
        for block in buffer.chunks_exact_mut(BLOCK_BYTES) {
            for index in 0..BLOCK_BYTES {
                input[index] = block[index] ^ chain[index];
            }
            self.cipher
                .process_block(&input[..], block)
                .map_err(DesEdeWrapError::Cipher)?;
            chain.copy_from_slice(block);
        }
        Ok(())
    }

    fn decrypt_cbc(
        &mut self,
        buffer: &mut [u8],
        iv: &[u8; BLOCK_BYTES],
    ) -> Result<(), DesEdeWrapError> {
        let mut chain = Zeroizing::new(*iv);
        let mut input = Zeroizing::new([0u8; BLOCK_BYTES]);
        for block in buffer.chunks_exact_mut(BLOCK_BYTES) {
            input.copy_from_slice(block);
            self.cipher
                .process_block(&input[..], block)
                .map_err(DesEdeWrapError::Cipher)?;
            for index in 0..BLOCK_BYTES {
                block[index] ^= chain[index];
            }
            chain.copy_from_slice(&input[..]);
        }
        Ok(())
    }
}

impl<R: Default> Default for DesEdeWrapEngine<R> {
    /// Uses the generator's default value, as [`new`](Self::new) does.
    /// Constant time.
    fn default() -> Self {
        Self::new(R::default())
    }
}

impl<R> Display for DesEdeWrapEngine<R> {
    /// Writes `"DESede"`. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("DESede")
    }
}

impl<R: CryptoRng> KeyWrap for DesEdeWrapEngine<R> {
    type Error = DesEdeWrapError;

    /// Returns `input_len + 16`; the key must be a multiple of 8 bytes.
    /// Constant time: depends only on the public length.
    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if input_len % BLOCK_BYTES != 0 {
            return Err(DesEdeWrapError::InvalidWrapLength);
        }
        input_len
            .checked_add(WRAP_OVERHEAD)
            .ok_or(DesEdeWrapError::InvalidWrapLength)
    }

    /// Returns `input_len - 16`; the input must be 16 bytes or more, in multiples
    /// of 8. Constant time: depends only on the public length.
    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if input_len < WRAP_OVERHEAD || input_len % BLOCK_BYTES != 0 {
            return Err(DesEdeWrapError::InvalidUnwrapLength);
        }
        Ok(input_len - WRAP_OVERHEAD)
    }

    /// Wraps `input` into `output` and returns the wrapped length.
    ///
    /// On a cipher error the output is wiped. Variable time: the Triple DES
    /// engine looks up S-boxes with secret data.
    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Wrap) => {}
            Some(WrapDirection::Unwrap) => return Err(DesEdeWrapError::NotForWrapping),
            None => return Err(DesEdeWrapError::NotInitialized),
        }
        let required = self.wrapped_len(input.len())?;
        if output.len() < required {
            return Err(DesEdeWrapError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let buffer = &mut output[..required];
        buffer[..BLOCK_BYTES].copy_from_slice(&self.iv);
        buffer[BLOCK_BYTES..BLOCK_BYTES + input.len()].copy_from_slice(input);
        let checksum = self.checksum(input);
        buffer[BLOCK_BYTES + input.len()..].copy_from_slice(&checksum[..]);

        // On failure the buffer still holds the plaintext key or partly processed data; do not
        // leave it to the caller.
        let iv = self.iv;
        if let Err(error) = self.encrypt_cbc(&mut buffer[BLOCK_BYTES..], &iv) {
            buffer.zeroize();
            return Err(error);
        }
        buffer.reverse();
        if let Err(error) = self.encrypt_cbc(buffer, &IV2) {
            buffer.zeroize();
            return Err(error);
        }
        Ok(required)
    }

    /// Unwraps `input` into `output` and returns the key length.
    ///
    /// A checksum that does not match returns `IntegrityCheckFailed` and leaves
    /// the output untouched. Variable time: the Triple DES engine looks up
    /// S-boxes with secret data.
    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Unwrap) => {}
            Some(WrapDirection::Wrap) => return Err(DesEdeWrapError::NotForUnwrapping),
            None => return Err(DesEdeWrapError::NotInitialized),
        }
        let required = self.max_unwrapped_len(input.len())?;
        if output.len() < required {
            return Err(DesEdeWrapError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let mut recovered = Zeroizing::new(input.to_vec());
        self.decrypt_cbc(&mut recovered[..], &IV2)?;
        recovered.reverse();
        self.iv.copy_from_slice(&recovered[..BLOCK_BYTES]);
        let iv = self.iv;
        self.decrypt_cbc(&mut recovered[BLOCK_BYTES..], &iv)?;

        let key_start = BLOCK_BYTES;
        let checksum_start = key_start + required;
        let expected = self.checksum(&recovered[key_start..checksum_start]);
        if !fixed_time_eq(&expected[..], &recovered[checksum_start..]) {
            return Err(DesEdeWrapError::IntegrityCheckFailed);
        }

        output[..required].copy_from_slice(&recovered[key_start..checksum_start]);
        Ok(required)
    }
}

impl<R, P> KeyWrapInit<P> for DesEdeWrapEngine<R>
where
    R: CryptoRng,
    P: KeyParams + IvOptParams + ?Sized,
{
    type Error = DesEdeWrapInitError;

    /// Installs the 16- or 24-byte Triple DES key from `params` for `direction`.
    ///
    /// Wrapping takes an 8-byte IV from `params` or, given `None`, draws one from
    /// the generator; unwrapping takes no IV and returns `IvNotAllowedForUnwrap`
    /// for one. A failed `init` leaves the wrapper uninitialized. Variable time: Triple DES key
    /// setup depends on the key bits.
    fn init(&mut self, direction: WrapDirection, params: &P) -> Result<(), Self::Error> {
        // Invalidate first, so a failure at any step leaves neither the previous direction nor the
        // previous IV usable.
        self.direction = None;

        let (cipher_direction, iv) = match direction {
            WrapDirection::Wrap => {
                let iv = match params.iv_opt() {
                    Some(iv) => {
                        iv.try_into()
                            .map_err(|_| DesEdeWrapInitError::InvalidIvLength {
                                actual: iv.len(),
                                required: BLOCK_BYTES,
                            })?
                    }
                    None => {
                        let mut iv = [0u8; BLOCK_BYTES];
                        self.rng.fill_bytes(&mut iv);
                        iv
                    }
                };
                (CipherDirection::Encrypt, iv)
            }
            WrapDirection::Unwrap => {
                if params.iv_opt().is_some() {
                    return Err(DesEdeWrapInitError::IvNotAllowedForUnwrap);
                }
                (CipherDirection::Decrypt, [0u8; BLOCK_BYTES])
            }
        };
        self.cipher
            .init(cipher_direction, &KeyRef::new(params.key()))
            .map_err(DesEdeWrapInitError::Cipher)?;

        self.iv = iv;
        self.direction = Some(direction);
        Ok(())
    }
}
