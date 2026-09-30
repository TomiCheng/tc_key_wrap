#![cfg(feature = "rfc5649")]

use tc_aes::AesEngine;
use tc_aria::AriaEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit};
use tc_key_wrap::{
    KeyWithIvOptRef, KeyWithIvRef, KeyWrap, KeyWrapError, KeyWrapInit, Rfc5649WrapEngine,
    WrapDirection,
};

fn hex(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&input[index..index + 2], 16).unwrap())
        .collect()
}

// Wrapping with the default AIV prefix must match the vector and unwrap back to the key.
fn check_vector<C>(cipher: fn() -> C, kek: &str, key: &str, wrapped: &str)
where
    C: BlockCipher + for<'a> BlockCipherInit<KeyWithIvOptRef<'a>>,
{
    let (kek, key, expected) = (hex(kek), hex(key), hex(wrapped));
    let params = KeyWithIvOptRef::new(&kek, None);
    let mut engine = Rfc5649WrapEngine::new(cipher());

    engine.init(WrapDirection::Wrap, &params).unwrap();
    let mut wrapped = vec![0; engine.wrapped_len(key.len()).unwrap()];
    assert_eq!(engine.wrap_into(&key, &mut wrapped).unwrap(), wrapped.len());
    assert_eq!(wrapped, expected);

    engine.init(WrapDirection::Unwrap, &params).unwrap();
    let mut recovered = vec![0; engine.max_unwrapped_len(expected.len()).unwrap()];
    let recovered_len = engine.unwrap_into(&expected, &mut recovered).unwrap();
    assert_eq!(recovered[..recovered_len], key[..]);
}

#[test]
fn aes_wrap_matches_the_rfc_5649_vectors_and_unwraps_back() {
    let kek = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8";
    check_vector(
        AesEngine::new,
        kek,
        "c37b7e6492584340bed12207808941155068f738",
        "138BDEAA9B8FA7FC61F97742E72248EE5AE6AE5360D1AE6A5F54F373FA543B6A",
    );
    check_vector(
        AesEngine::new,
        kek,
        "466f7250617369",
        "AFBEB0F07DFBF5419200F2CCB50BB24F",
    );
}

#[test]
fn aria_wrap_matches_the_independent_vectors_and_unwraps_back() {
    let kek = "000102030405060708090A0B0C0D0E0F";
    let vectors = [
        ("466f7250617369", "FF5DF3FABA86BD7802800F420B6BB16A"),
        (
            "00112233445566778899AABBCCDDEEFF",
            "AC0E22699A036CED63ADEB75F4946F82DC98AD8AF43B24D5",
        ),
        (
            "c37b7e6492584340bed12207808941155068f738",
            "9EC1DA50BA6665264E0C75C4C4FD2E652DEB5F4C0F3FCFD478624C1A9AF35FFA",
        ),
        (
            "00112233445566778899AABBCCDDEEFF0001020304050607",
            "A08391E5159F4DE68EBD1F9E7DB722E1A9D9AAF206F7DACB62CA0FEAD47C1B96",
        ),
        (
            "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
            "1F59D0D10409835594531BF7B721CBF260816766D71BF2647D8BA6AB3125334E34FA018ABB39C280",
        ),
    ];
    for (key, wrapped) in vectors {
        check_vector(AriaEngine::new, kek, key, wrapped);
    }
}

#[test]
fn tampering_is_rejected_and_clears_the_output() {
    let kek = hex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
    let mut wrapped = hex("AFBEB0F07DFBF5419200F2CCB50BB24F");
    wrapped[0] ^= 1;
    let mut engine = Rfc5649WrapEngine::new(AesEngine::new());
    engine
        .init(WrapDirection::Unwrap, &KeyWithIvOptRef::new(&kek, None))
        .unwrap();
    let mut output = [0xa5; 8];
    assert!(matches!(
        engine.unwrap_into(&wrapped, &mut output),
        Err(KeyWrapError::IntegrityCheckFailed)
    ));
    assert_eq!(output, [0; 8]);
}

#[test]
fn a_custom_aiv_prefix_round_trips() {
    let key = hex("000102030405060708090A0B0C0D0E0F");
    let input = hex("466f7250617369");
    let pre_iv = [1u8, 2, 3, 4];
    let params = KeyWithIvRef::new(&key, &pre_iv);
    let mut engine = Rfc5649WrapEngine::new(AesEngine::new());
    engine.init(WrapDirection::Wrap, &params).unwrap();
    let mut wrapped = [0u8; 16];
    engine.wrap_into(&input, &mut wrapped).unwrap();

    engine.init(WrapDirection::Unwrap, &params).unwrap();
    let mut recovered = [0u8; 8];
    let recovered_len = engine.unwrap_into(&wrapped, &mut recovered).unwrap();
    assert_eq!(recovered[..recovered_len], input[..]);
}
