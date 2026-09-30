use tc_aes::AesEngine;
use tc_block_cipher::BlockCipher;
use tc_key_wrap::{
    KeyWithIvOptRef, KeyWithIvRef, KeyWrap, KeyWrapError, KeyWrapInit, Rfc3394WrapEngine,
    WrapDirection,
};

fn hex(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&input[index..index + 2], 16).unwrap())
        .collect()
}

// Wrapping with the default IV must match the vector and unwrap back to the key.
fn check_vector(kek: &str, key: &str, wrapped: &str) {
    let (kek, key, expected) = (hex(kek), hex(key), hex(wrapped));
    let params = KeyWithIvOptRef::new(&kek, None);
    let mut engine = Rfc3394WrapEngine::new(AesEngine::new());

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
fn aes_wrap_matches_the_rfc_3394_vectors_and_unwraps_back() {
    let vectors = [
        (
            "000102030405060708090A0B0C0D0E0F",
            "00112233445566778899AABBCCDDEEFF",
            "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
        ),
        (
            "000102030405060708090A0B0C0D0E0F1011121314151617",
            "00112233445566778899AABBCCDDEEFF",
            "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
        ),
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "00112233445566778899AABBCCDDEEFF",
            "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
        ),
        (
            "000102030405060708090A0B0C0D0E0F1011121314151617",
            "00112233445566778899AABBCCDDEEFF0001020304050607",
            "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
        ),
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "00112233445566778899AABBCCDDEEFF0001020304050607",
            "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
        ),
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        ),
    ];
    for (kek, key, wrapped) in vectors {
        check_vector(kek, key, wrapped);
    }
}

#[test]
fn a_custom_iv_round_trips_through_a_trait_object() {
    let kek = hex("000102030405060708090A0B0C0D0E0F");
    let key = hex("00112233445566778899AABBCCDDEEFF");
    let iv = [1u8; 8];
    let mut engine = Rfc3394WrapEngine::new(AesEngine::new());
    engine
        .init(WrapDirection::Wrap, &KeyWithIvRef::new(&kek, &iv))
        .unwrap();
    let wrapper: &mut dyn KeyWrap<Error = KeyWrapError<<AesEngine as BlockCipher>::Error>> =
        &mut engine;
    let mut wrapped = [0u8; 24];
    wrapper.wrap_into(&key, &mut wrapped).unwrap();

    engine
        .init(WrapDirection::Unwrap, &KeyWithIvRef::new(&kek, &iv))
        .unwrap();
    let mut recovered = [0u8; 16];
    assert_eq!(engine.unwrap_into(&wrapped, &mut recovered).unwrap(), 16);
    assert_eq!(recovered.as_slice(), key);
}

#[test]
fn tampering_is_rejected_and_clears_the_output() {
    let kek = hex("000102030405060708090A0B0C0D0E0F");
    let mut wrapped = hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
    wrapped[0] ^= 1;
    let mut engine = Rfc3394WrapEngine::new(AesEngine::new());
    engine
        .init(WrapDirection::Unwrap, &KeyWithIvOptRef::new(&kek, None))
        .unwrap();
    let mut output = [0xa5; 16];
    assert!(matches!(
        engine.unwrap_into(&wrapped, &mut output),
        Err(KeyWrapError::IntegrityCheckFailed)
    ));
    assert_eq!(output, [0; 16]);
}
