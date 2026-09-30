#![cfg(feature = "rfc3211")]

use core::convert::Infallible;

use rand::SeedableRng;
use rand::rngs::StdRng;
use rand_core::{TryCryptoRng, TryRng};
use tc_aes::AesEngine;
use tc_aria::AriaEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_des::{DesEdeEngine, DesEngine};
use tc_key_wrap::{
    KeyWithIvRef, KeyWrap, KeyWrapError, KeyWrapInit, KeyWrapInitError, Rfc3211WrapEngine,
    WrapDirection,
};

fn hex(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&input[index..index + 2], 16).unwrap())
        .collect()
}

// An RNG that returns fixed bytes in order, so RFC 3211's random padding reproduces Bouncy Castle's
// vectors.
struct FixedRng {
    bytes: Vec<u8>,
    offset: usize,
}

impl FixedRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl TryRng for FixedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unreachable!("RFC 3211 only fills bytes")
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unreachable!("RFC 3211 only fills bytes")
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        let end = self.offset + output.len();
        assert!(end <= self.bytes.len(), "fixed RNG exhausted");
        output.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

// Wrapping must match Bouncy Castle's vector, and a fresh engine must unwrap it back to the key.
fn check_vector<C>(cipher: fn() -> C, kek: &str, iv: &str, random: &str, key: &str, wrapped: &str)
where
    C: BlockCipher + for<'a> BlockCipherInit<KeyWithIvRef<'a>>,
{
    let (kek, iv, key, expected) = (hex(kek), hex(iv), hex(key), hex(wrapped));
    let params = KeyWithIvRef::new(&kek, &iv);

    let mut wrapper = Rfc3211WrapEngine::new(cipher(), FixedRng::new(hex(random)));
    wrapper.init(WrapDirection::Wrap, &params).unwrap();
    let mut wrapped = vec![0; wrapper.wrapped_len(key.len()).unwrap()];
    let wrapped_len = wrapper.wrap_into(&key, &mut wrapped).unwrap();
    assert_eq!(wrapped_len, wrapped.len());
    assert_eq!(wrapped, expected);

    let mut unwrapper = Rfc3211WrapEngine::new(cipher(), FixedRng::new(Vec::new()));
    unwrapper.init(WrapDirection::Unwrap, &params).unwrap();
    let mut recovered = vec![0; unwrapper.max_unwrapped_len(expected.len()).unwrap()];
    let recovered_len = unwrapper.unwrap_into(&expected, &mut recovered).unwrap();
    assert_eq!(recovered[..recovered_len], key[..]);
}

#[test]
fn des_wrap_matches_the_bouncy_castle_vector_and_unwraps_back() {
    check_vector(
        DesEngine::new,
        "D1DAA78615F287E6",
        "EFE598EF21B33D6D",
        "C436F541",
        "8C627C897323A2F8",
        "B81B2565EE373CA6DEDCA26A178B0C10",
    );
}

#[test]
fn des_ede_wrap_matches_the_bouncy_castle_vector_and_unwraps_back() {
    check_vector(
        DesEdeEngine::new,
        "6A8970BF68C92CAEA84A8DF28510858607126380CC47AB2D",
        "BAF1CA7931213C4E",
        "FA060A45",
        "8C637D887223A2F965B566EB014B0FA5D52300A3F7EA40FFFC577203C71BAF3B",
        "C03C514ABDB9E2C5AAC038572B5E24553876B377AAFB82ECA5A9D73F8AB143D9EC74E6CAD7DB260C",
    );
}

#[test]
fn aes_wrap_matches_the_bouncy_castle_vector_and_unwraps_back() {
    check_vector(
        AesEngine::new,
        "000102030405060708090A0B0C0D0E0F",
        "000102030405060708090A0B0C0D0E0F",
        "9688DF2AF1B7B1AC9688DF2A",
        "00112233445566778899AABBCCDDEEFF",
        "7C8798DFC802553B3F00BB4315E3A087322725C92398B9C112C74D0925C63B61",
    );
}

#[test]
fn aria_wrap_matches_the_bouncy_castle_vector_and_unwraps_back() {
    check_vector(
        AriaEngine::new,
        "000102030405060708090A0B0C0D0E0F",
        "000102030405060708090A0B0C0D0E0F",
        "9688DF2AF1B7B1AC9688DF2A",
        "00112233445566778899AABBCCDDEEFF",
        "9B2D3CAC0ACF9D4BDE7C1BDB0313FBEF931F025ACC77BF57D3D1CABC88B514D0",
    );
}

#[test]
fn aes_wrap_with_a_seeded_std_rng_unwraps_back_to_the_key() {
    let kek = [0x42_u8; 16];
    let iv = [0x24_u8; 16];
    let key = [0x5a_u8; 24];
    let params = KeyWithIvRef::new(&kek, &iv);
    let mut wrapper = Rfc3211WrapEngine::new(AesEngine::new(), StdRng::seed_from_u64(0x3211));

    wrapper.init(WrapDirection::Wrap, &params).unwrap();
    let mut wrapped = vec![0; wrapper.wrapped_len(key.len()).unwrap()];
    let wrapped_len = wrapper.wrap_into(&key, &mut wrapped).unwrap();

    wrapper.init(WrapDirection::Unwrap, &params).unwrap();
    let mut recovered = vec![0; wrapper.max_unwrapped_len(wrapped_len).unwrap()];
    let recovered_len = wrapper
        .unwrap_into(&wrapped[..wrapped_len], &mut recovered)
        .unwrap();
    assert_eq!(recovered[..recovered_len], key);
}

#[test]
fn name_sizing_direction_and_output_errors_are_reported() {
    let key = hex("000102030405060708090A0B0C0D0E0F");
    let iv = hex("000102030405060708090A0B0C0D0E0F");
    let params = KeyWithIvRef::new(&key, &iv);
    let mut wrapper = Rfc3211WrapEngine::new(AesEngine::new(), FixedRng::new(vec![0; 32]));

    assert_eq!(wrapper.to_string(), "AES/RFC3211Wrap");
    assert_eq!(wrapper.wrapped_len(0).unwrap(), 32);
    assert_eq!(wrapper.wrapped_len(28).unwrap(), 32);
    assert_eq!(wrapper.wrapped_len(29).unwrap(), 48);
    assert_eq!(wrapper.max_unwrapped_len(32).unwrap(), 28);
    assert!(matches!(
        wrapper.wrapped_len(256),
        Err(KeyWrapError::InvalidWrapLength)
    ));
    assert!(matches!(
        wrapper.max_unwrapped_len(16),
        Err(KeyWrapError::InvalidUnwrapLength)
    ));
    assert!(matches!(
        wrapper.max_unwrapped_len(33),
        Err(KeyWrapError::InvalidUnwrapLength)
    ));
    assert!(matches!(
        wrapper.wrap_into(&[], &mut [0_u8; 32]),
        Err(KeyWrapError::NotInitialized)
    ));

    wrapper.init(WrapDirection::Wrap, &params).unwrap();
    assert!(matches!(
        wrapper.wrap_into(&[0_u8; 16], &mut [0_u8; 31]),
        Err(KeyWrapError::OutputTooShort {
            required: 32,
            available: 31,
        })
    ));
    assert!(matches!(
        wrapper.unwrap_into(&[0_u8; 32], &mut [0_u8; 28]),
        Err(KeyWrapError::NotForUnwrapping)
    ));

    wrapper.init(WrapDirection::Unwrap, &params).unwrap();
    assert!(matches!(
        wrapper.wrap_into(&[], &mut [0_u8; 32]),
        Err(KeyWrapError::NotForWrapping)
    ));
    assert!(matches!(
        wrapper.unwrap_into(&[0_u8; 32], &mut [0_u8; 27]),
        Err(KeyWrapError::OutputTooShort {
            required: 28,
            available: 27,
        })
    ));
}

#[test]
fn an_iv_shorter_than_the_block_is_rejected_at_initialization() {
    let key = [0_u8; 16];
    let short_iv = [0_u8; 15];
    let params = KeyWithIvRef::new(&key, &short_iv);
    let mut wrapper = Rfc3211WrapEngine::new(AesEngine::new(), FixedRng::new(Vec::new()));

    assert!(matches!(
        wrapper.init(WrapDirection::Wrap, &params),
        Err(KeyWrapInitError::InvalidIvLength {
            actual: 15,
            required: 16,
        })
    ));
}

#[test]
fn unwrap_rejects_tampering_without_exposing_key_material() {
    let key = hex("000102030405060708090A0B0C0D0E0F");
    let iv = hex("000102030405060708090A0B0C0D0E0F");
    let params = KeyWithIvRef::new(&key, &iv);
    let mut wrapped = hex("7C8798DFC802553B3F00BB4315E3A087322725C92398B9C112C74D0925C63B61");
    wrapped[20] ^= 0x01;

    let mut unwrapper = Rfc3211WrapEngine::new(AesEngine::new(), FixedRng::new(Vec::new()));
    unwrapper.init(WrapDirection::Unwrap, &params).unwrap();
    let mut output = [0xa5_u8; 28];

    assert!(matches!(
        unwrapper.unwrap_into(&wrapped, &mut output),
        Err(KeyWrapError::IntegrityCheckFailed)
    ));
    assert_eq!(output, [0xa5; 28]);
}

// Encrypts `plaintext` as RFC 3211 wrapping does, CBC under `iv` and then CBC again from the last
// ciphertext block, so a test can choose the length and check bytes that `wrap_into` would set.
fn aes_double_cbc(kek: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut cipher = AesEngine::new();
    cipher
        .init(CipherDirection::Encrypt, &KeyWithIvRef::new(kek, iv))
        .unwrap();
    let mut data = plaintext.to_vec();
    let mut chain = iv.to_vec();
    for _ in 0..2 {
        for block in data.chunks_exact_mut(16) {
            let input: Vec<u8> = block.iter().zip(&chain).map(|(b, c)| b ^ c).collect();
            cipher.process_block(&input, block).unwrap();
            chain.copy_from_slice(block);
        }
    }
    data
}

#[test]
fn a_length_byte_beyond_the_padded_key_is_rejected_even_with_valid_check_bytes() {
    let kek = hex("000102030405060708090A0B0C0D0E0F");
    let iv = hex("000102030405060708090A0B0C0D0E0F");
    let params = KeyWithIvRef::new(&kek, &iv);
    let mut unwrapper = Rfc3211WrapEngine::new(AesEngine::new(), FixedRng::new(Vec::new()));
    unwrapper.init(WrapDirection::Unwrap, &params).unwrap();

    // The check bytes complement the first key bytes, so only the length byte can fail.
    let mut plaintext = [0x5a_u8; 32];
    plaintext[1..4].fill(!0x5a);

    // 28 bytes is the most that two AES blocks hold after the 4-byte header.
    plaintext[0] = 28;
    let mut output = [0xa5_u8; 28];
    let wrapped = aes_double_cbc(&kek, &iv, &plaintext);
    assert_eq!(unwrapper.unwrap_into(&wrapped, &mut output).unwrap(), 28);
    assert_eq!(output[..], plaintext[4..]);

    plaintext[0] = 29;
    let mut output = [0xa5_u8; 28];
    let wrapped = aes_double_cbc(&kek, &iv, &plaintext);
    assert!(matches!(
        unwrapper.unwrap_into(&wrapped, &mut output),
        Err(KeyWrapError::IntegrityCheckFailed)
    ));
    assert_eq!(output, [0xa5; 28]);
}

#[test]
fn keys_at_the_length_boundaries_round_trip() {
    let kek = [0x42_u8; 16];
    let iv = [0x24_u8; 16];
    let params = KeyWithIvRef::new(&kek, &iv);
    let mut wrapper = Rfc3211WrapEngine::new(AesEngine::new(), StdRng::seed_from_u64(0x3211));

    // Keys shorter than 3 bytes take part of their check bytes from the random padding; 255 bytes
    // is the most the length byte can express.
    for (key_len, wrapped_len) in [(0, 32), (1, 32), (2, 32), (255, 272)] {
        let key: Vec<u8> = (0..key_len).map(|index| index as u8).collect();

        wrapper.init(WrapDirection::Wrap, &params).unwrap();
        let mut wrapped = vec![0; wrapper.wrapped_len(key_len).unwrap()];
        assert_eq!(wrapper.wrap_into(&key, &mut wrapped).unwrap(), wrapped_len);

        wrapper.init(WrapDirection::Unwrap, &params).unwrap();
        let mut recovered = vec![0; wrapper.max_unwrapped_len(wrapped_len).unwrap()];
        let recovered_len = wrapper.unwrap_into(&wrapped, &mut recovered).unwrap();
        assert_eq!(
            recovered[..recovered_len],
            key[..],
            "key of {key_len} bytes"
        );
    }
}

#[test]
fn a_rejected_reinitialization_leaves_the_wrapper_uninitialized() {
    let key = [0_u8; 16];
    let iv = [0x24_u8; 16];
    let short_iv = [0x24_u8; 15];
    let mut wrapper = Rfc3211WrapEngine::new(AesEngine::new(), StdRng::seed_from_u64(1));
    wrapper
        .init(WrapDirection::Wrap, &KeyWithIvRef::new(&key, &iv))
        .unwrap();

    assert!(matches!(
        wrapper.init(WrapDirection::Unwrap, &KeyWithIvRef::new(&key, &short_iv)),
        Err(KeyWrapInitError::InvalidIvLength {
            actual: 15,
            required: 16,
        })
    ));
    assert!(matches!(
        wrapper.wrap_into(&[0_u8; 16], &mut [0_u8; 32]),
        Err(KeyWrapError::NotInitialized)
    ));
    assert!(matches!(
        wrapper.unwrap_into(&[0_u8; 32], &mut [0_u8; 28]),
        Err(KeyWrapError::NotInitialized)
    ));
}

#[derive(Debug, PartialEq)]
struct Exhausted;

impl core::fmt::Display for Exhausted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("test cipher exhausted")
    }
}

impl core::error::Error for Exhausted {}

// A cipher with a chosen block size that passes blocks through unchanged, and fails once it has
// processed `blocks_left` blocks.
struct TestCipher {
    block_size: usize,
    blocks_left: usize,
}

impl BlockCipher for TestCipher {
    type Error = Exhausted;

    fn block_size(&self) -> usize {
        self.block_size
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if self.blocks_left == 0 {
            return Err(Exhausted);
        }
        self.blocks_left -= 1;
        output[..self.block_size].copy_from_slice(&input[..self.block_size]);
        Ok(self.block_size)
    }
}

impl<P: ?Sized> BlockCipherInit<P> for TestCipher {
    type Error = Infallible;

    fn init(&mut self, _direction: CipherDirection, _params: &P) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn a_cipher_failure_wipes_a_partial_wrap_and_leaves_the_unwrap_output_untouched() {
    let key = [0x11_u8; 16];
    let iv = [0x24_u8; 16];
    let params = KeyWithIvRef::new(&key, &iv);

    // A 16-byte key wraps into two blocks, and each direction processes four blocks in total, so
    // every budget below four fails in the first or the second pass.
    for blocks_left in 0..4 {
        let cipher = TestCipher {
            block_size: 16,
            blocks_left,
        };
        let mut wrapper = Rfc3211WrapEngine::new(cipher, StdRng::seed_from_u64(1));
        wrapper.init(WrapDirection::Wrap, &params).unwrap();
        let mut output = [0xa5_u8; 40];
        assert_eq!(
            wrapper.wrap_into(&key, &mut output),
            Err(KeyWrapError::Cipher(Exhausted))
        );
        assert_eq!(output[..32], [0; 32], "budget of {blocks_left} blocks");
        assert_eq!(output[32..], [0xa5; 8], "budget of {blocks_left} blocks");

        let cipher = TestCipher {
            block_size: 16,
            blocks_left,
        };
        let mut unwrapper = Rfc3211WrapEngine::new(cipher, StdRng::seed_from_u64(1));
        unwrapper.init(WrapDirection::Unwrap, &params).unwrap();
        let mut output = [0xa5_u8; 28];
        assert_eq!(
            unwrapper.unwrap_into(&[0x5a; 32], &mut output),
            Err(KeyWrapError::Cipher(Exhausted))
        );
        assert_eq!(output, [0xa5; 28], "budget of {blocks_left} blocks");
    }
}

#[test]
fn blocks_shorter_than_four_bytes_are_rejected_and_four_byte_blocks_round_trip() {
    let key = [0_u8; 16];
    let short_iv = [0x24_u8; 2];
    let mut wrapper = Rfc3211WrapEngine::new(
        TestCipher {
            block_size: 2,
            blocks_left: usize::MAX,
        },
        StdRng::seed_from_u64(1),
    );
    let too_short = || KeyWrapError::BlockSizeTooShort {
        actual: 2,
        minimum: 4,
    };
    assert_eq!(wrapper.wrapped_len(16), Err(too_short()));
    assert_eq!(wrapper.max_unwrapped_len(16), Err(too_short()));
    assert!(matches!(
        wrapper.init(WrapDirection::Wrap, &KeyWithIvRef::new(&key, &short_iv)),
        Err(KeyWrapInitError::BlockSizeTooShort {
            actual: 2,
            minimum: 4,
        })
    ));

    let iv = [0x24_u8; 4];
    let params = KeyWithIvRef::new(&key, &iv);
    let secret = [0x11_u8, 0x22, 0x33, 0x44, 0x55];
    let mut wrapper = Rfc3211WrapEngine::new(
        TestCipher {
            block_size: 4,
            blocks_left: usize::MAX,
        },
        StdRng::seed_from_u64(1),
    );
    wrapper.init(WrapDirection::Wrap, &params).unwrap();
    let mut wrapped = [0; 12];
    assert_eq!(wrapper.wrap_into(&secret, &mut wrapped), Ok(12));

    wrapper.init(WrapDirection::Unwrap, &params).unwrap();
    let mut recovered = [0; 8];
    assert_eq!(wrapper.unwrap_into(&wrapped, &mut recovered), Ok(5));
    assert_eq!(recovered[..5], secret);
}
