//! CMS RC2 key-wrap engine.

use core::fmt::{Display, Formatter};
use rand_core::CryptoRng;
use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_constant_time::fixed_time_eq;
use tc_digest::Digest;
use tc_key_wrap::{
    IvOptParams, KeyWrap, KeyWrapError, KeyWrapInit, KeyWrapInitError, WrapDirection,
};
use tc_rc_cipher::{Rc2Engine, Rc2Params};
use tc_sha::Sha1Digest;
use tc_zeroize::{Zeroize, Zeroizing};

const BLOCK_BYTES: usize = 8;
const CHECKSUM_BYTES: usize = 8;
const WRAP_OVERHEAD: usize = BLOCK_BYTES + CHECKSUM_BYTES;
const MAX_KEY_BYTES: usize = u8::MAX as usize;
const MAX_WRAPPED_BYTES: usize = MAX_KEY_BYTES + 1 + WRAP_OVERHEAD;
const IV2: [u8; BLOCK_BYTES] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

/// CMS RC2 key wrapping (RFC 3217) with SHA-1 integrity and random padding.
///
/// Wraps a key of up to 255 bytes: a length byte and the key, padded to whole
/// blocks with random bytes from `R`, under an RC2 key-encryption key of 1 to
/// 128 bytes with an effective size of 1 to 1024 bits. The output is 16 bytes
/// longer than the padded key. Wrapping takes an 8-byte IV from its
/// parameters or, given `None`, draws one from `R`. The parameters implement
/// `KeyParams`, `Rc2Params` for the effective size and `IvOptParams` for the
/// IV, as [`Rc2WrapParamsRef`](crate::Rc2WrapParamsRef) does.
///
/// Variable time: the RC2 engine indexes tables with secret data. Output left
/// by a failed wrap is wiped.
///
/// # Example
///
/// ```
/// use rand::SeedableRng;
/// use rand::rngs::StdRng;
/// use tc_key_wrap::{KeyWrap, KeyWrapInit, WrapDirection};
/// use tc_rc2_wrap::{Rc2WrapEngine, Rc2WrapParamsRef};
///
/// let kek = [0x42; 16];
/// let params = Rc2WrapParamsRef::new(&kek, None);
/// let key = [0x11; 16];
/// let mut wrapper = Rc2WrapEngine::new(StdRng::seed_from_u64(1));
///
/// wrapper.init(WrapDirection::Wrap, &params)?;
/// let mut wrapped = vec![0; wrapper.wrapped_len(key.len())?];
/// wrapper.wrap_into(&key, &mut wrapped)?;
///
/// wrapper.init(WrapDirection::Unwrap, &params)?;
/// let mut recovered = vec![0; wrapper.max_unwrapped_len(wrapped.len())?];
/// let length = wrapper.unwrap_into(&wrapped, &mut recovered)?;
/// assert_eq!(recovered[..length], key);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Rc2WrapEngine<R> {
    cipher: Rc2Engine,
    sha1: Sha1Digest,
    rng: R,
    iv: [u8; BLOCK_BYTES],
    direction: Option<WrapDirection>,
}

impl<R> Rc2WrapEngine<R> {
    /// Creates a wrapper that draws its padding, and a random IV when `init` is
    /// given none, from `rng`; call `init` before use. Constant time.
    pub fn new(rng: R) -> Self {
        Self {
            cipher: Rc2Engine::new(),
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
        iv: &[u8; 8],
    ) -> Result<(), KeyWrapError<BlockError>> {
        let mut chain = Zeroizing::new(*iv);
        let mut input = Zeroizing::new([0u8; BLOCK_BYTES]);
        for block in buffer.chunks_exact_mut(BLOCK_BYTES) {
            for index in 0..BLOCK_BYTES {
                input[index] = block[index] ^ chain[index];
            }
            self.cipher
                .process_block(&input[..], block)
                .map_err(KeyWrapError::Cipher)?;
            chain.copy_from_slice(block);
        }
        Ok(())
    }

    fn decrypt_cbc(
        &mut self,
        buffer: &mut [u8],
        iv: &[u8; 8],
    ) -> Result<(), KeyWrapError<BlockError>> {
        let mut chain = Zeroizing::new(*iv);
        let mut input = Zeroizing::new([0u8; BLOCK_BYTES]);
        for block in buffer.chunks_exact_mut(BLOCK_BYTES) {
            input.copy_from_slice(block);
            self.cipher
                .process_block(&input[..], block)
                .map_err(KeyWrapError::Cipher)?;
            for index in 0..BLOCK_BYTES {
                block[index] ^= chain[index];
            }
            chain.copy_from_slice(&input[..]);
        }
        Ok(())
    }
}

impl<R: Default> Default for Rc2WrapEngine<R> {
    /// Uses the generator's default value, as [`new`](Self::new) does.
    /// Constant time.
    fn default() -> Self {
        Self::new(R::default())
    }
}

impl<R> Display for Rc2WrapEngine<R> {
    /// Writes `"RC2"`. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("RC2")
    }
}

impl<R: CryptoRng> KeyWrap for Rc2WrapEngine<R> {
    type Error = KeyWrapError<BlockError>;

    /// Returns the length byte and the key, padded to whole blocks, plus 16; the
    /// key must be at most 255 bytes. Constant time: depends only on the public length.
    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if input_len > MAX_KEY_BYTES {
            return Err(KeyWrapError::InvalidWrapLength);
        }
        let padded = input_len
            .checked_add(1)
            .ok_or(KeyWrapError::InvalidWrapLength)?
            .div_ceil(BLOCK_BYTES)
            .checked_mul(BLOCK_BYTES)
            .ok_or(KeyWrapError::InvalidWrapLength)?;
        padded
            .checked_add(WRAP_OVERHEAD)
            .ok_or(KeyWrapError::InvalidWrapLength)
    }

    /// Returns `input_len - 17`, an upper bound on the key length; the input must
    /// be 24 to 272 bytes, in multiples of 8. Constant time: depends only on the public length.
    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if !(WRAP_OVERHEAD + BLOCK_BYTES..=MAX_WRAPPED_BYTES).contains(&input_len)
            || input_len % BLOCK_BYTES != 0
        {
            return Err(KeyWrapError::InvalidUnwrapLength);
        }
        Ok(input_len - WRAP_OVERHEAD - 1)
    }

    /// Wraps `input` into `output` and returns the wrapped length.
    ///
    /// On a cipher error the output is wiped. Variable time: the RC2 engine
    /// indexes tables with secret data.
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

        let padded_end = required - CHECKSUM_BYTES;
        let buffer = &mut output[..required];
        buffer[..BLOCK_BYTES].copy_from_slice(&self.iv);
        buffer[BLOCK_BYTES] = input.len() as u8;
        buffer[BLOCK_BYTES + 1..BLOCK_BYTES + 1 + input.len()].copy_from_slice(input);
        self.rng
            .fill_bytes(&mut buffer[BLOCK_BYTES + 1 + input.len()..padded_end]);
        let checksum = self.checksum(&buffer[BLOCK_BYTES..padded_end]);
        buffer[padded_end..].copy_from_slice(&checksum[..]);

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
    /// A checksum, length or padding that does not match returns
    /// `IntegrityCheckFailed` and leaves the output untouched. Variable time:
    /// the RC2 engine indexes tables with secret data.
    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Unwrap) => {}
            Some(WrapDirection::Wrap) => return Err(KeyWrapError::NotForUnwrapping),
            None => return Err(KeyWrapError::NotInitialized),
        }
        let capacity = self.max_unwrapped_len(input.len())?;
        if output.len() < capacity {
            return Err(KeyWrapError::OutputTooShort {
                required: capacity,
                available: output.len(),
            });
        }

        let mut recovered = Zeroizing::new(input.to_vec());
        self.decrypt_cbc(&mut recovered[..], &IV2)?;
        recovered.reverse();
        self.iv.copy_from_slice(&recovered[..BLOCK_BYTES]);
        let iv = self.iv;
        self.decrypt_cbc(&mut recovered[BLOCK_BYTES..], &iv)?;

        let checksum_start = recovered.len() - CHECKSUM_BYTES;
        let expected = self.checksum(&recovered[BLOCK_BYTES..checksum_start]);
        let checksum_valid = fixed_time_eq(&expected[..], &recovered[checksum_start..]);
        let encoded_len = usize::from(recovered[BLOCK_BYTES]);
        let maximum_len = checksum_start - BLOCK_BYTES - 1;
        let length_valid = encoded_len <= maximum_len;
        let padding_len = maximum_len.saturating_sub(encoded_len);
        let padding_valid = length_valid && padding_len < BLOCK_BYTES;
        if !checksum_valid || !padding_valid {
            return Err(KeyWrapError::IntegrityCheckFailed);
        }

        let key_start = BLOCK_BYTES + 1;
        output[..encoded_len].copy_from_slice(&recovered[key_start..key_start + encoded_len]);
        Ok(encoded_len)
    }
}

impl<R, P> KeyWrapInit<P> for Rc2WrapEngine<R>
where
    R: CryptoRng,
    P: Rc2Params + IvOptParams + ?Sized,
{
    type Error = KeyWrapInitError<InitError>;

    /// Installs the RC2 key and effective size from `params` for `direction`.
    ///
    /// Wrapping takes an 8-byte IV from `params` or, given `None`, draws one from
    /// the generator; unwrapping takes no IV and returns `IvNotAllowedForUnwrap`
    /// for one. A failed `init` leaves the wrapper uninitialized. Variable time: RC2 key setup
    /// indexes the PI table with key bytes.
    fn init(&mut self, direction: WrapDirection, params: &P) -> Result<(), Self::Error> {
        // Invalidate first, so a failure at any step leaves neither the previous direction nor the
        // previous IV usable.
        self.direction = None;

        let (cipher_direction, iv) = match direction {
            WrapDirection::Wrap => {
                let iv = match params.iv_opt() {
                    Some(iv) => iv
                        .try_into()
                        .map_err(|_| KeyWrapInitError::InvalidIvLength {
                            actual: iv.len(),
                            required: BLOCK_BYTES,
                        })?,
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
                    return Err(KeyWrapInitError::IvNotAllowedForUnwrap);
                }
                (CipherDirection::Decrypt, [0u8; BLOCK_BYTES])
            }
        };
        self.cipher
            .init(cipher_direction, params)
            .map_err(KeyWrapInitError::Cipher)?;

        self.iv = iv;
        self.direction = Some(direction);
        Ok(())
    }
}
