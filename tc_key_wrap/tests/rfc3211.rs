#![cfg(feature = "rfc3211")]

use core::convert::Infallible;

use rand::SeedableRng;
use rand::rngs::StdRng;
use rand_core::{TryCryptoRng, TryRng};
use tc_aes::AesEngine;
use tc_aria::AriaEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit};
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
