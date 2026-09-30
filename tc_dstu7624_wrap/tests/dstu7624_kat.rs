use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, InitError, KeyRef};
use tc_dstu7624::Dstu7624Engine;
use tc_dstu7624_wrap::{Dstu7624WrapEngine, Dstu7624WrapError, Dstu7624WrapInitError};
use tc_key_wrap::{KeyWrap, KeyWrapInit, WrapDirection};

fn hex(input: &str) -> Vec<u8> {
    let digits: Vec<u8> = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    digits
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap();
            let low = (pair[1] as char).to_digit(16).unwrap();
            (high * 16 + low) as u8
        })
        .collect()
}

fn check<const BLOCK_WORDS: usize>(
    mut wrapper: Dstu7624WrapEngine<BLOCK_WORDS>,
    key: &str,
    input: &str,
    expected: &str,
) where
    Dstu7624Engine<BLOCK_WORDS>:
        BlockCipher<Error = BlockError> + for<'a> BlockCipherInit<KeyRef<'a>, Error = InitError>,
{
    let key = hex(key);
    let input = hex(input);
    let expected = hex(expected);
    let params = KeyRef::new(&key);

    wrapper.init(WrapDirection::Wrap, &params).unwrap();
    let mut wrapped = vec![0; wrapper.wrapped_len(input.len()).unwrap()];
    assert_eq!(
        wrapper.wrap_into(&input, &mut wrapped).unwrap(),
        wrapped.len()
    );
    assert_eq!(wrapped, expected);

    wrapper.init(WrapDirection::Unwrap, &params).unwrap();
    let mut recovered = vec![0; wrapper.max_unwrapped_len(wrapped.len()).unwrap()];
    let written = wrapper.unwrap_into(&wrapped, &mut recovered).unwrap();
    assert_eq!(&recovered[..written], input);
}

#[test]
fn bouncy_castle_vectors() {
    check(
        Dstu7624WrapEngine::<2>::new(),
        "000102030405060708090A0B0C0D0E0F",
        "101112131415161718191A1B1C1D1E1F20219000000000000000800000000000",
        "0EA983D6CE48484D51462C32CC61672210FCC44196ABE635BAF878FDB83E1A63114128585D49DB355C5819FD38039169",
    );
    check(
        Dstu7624WrapEngine::<2>::new(),
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
        "2D09A7C18E6A5A0816331EC27CEA596903F77EC8D63F3BDB73299DE7FD9F4558E05992B0B24B39E02EA496368E0841CC1E3FA44556A3048C5A6E9E335717D17D",
    );
    check(
        Dstu7624WrapEngine::<4>::new(),
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
        "BE59D3C3C31B2685A8FA57CD000727F16AF303F0D87BC2D7ABD80DC2796BBC4CDBC4E0408943AF4DAF7DE9084DC81BFEF15FDCDD0DF399983DF69BF730D7AE2A199CA4F878E4723B7171DD4D1E8DF59C0F25FA0C20946BA64F9037D724BB1D50B6C2BD9788B2AF83EF6163087CD2D4488BC19F3A858D813E3A8947A529B6D65D",
    );
    check(
        Dstu7624WrapEngine::<4>::new(),
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",
        "599217EB2B5270ECEF0BB716D70E251234A2451CE04FCFBAEEA92022C581F19B7C9386BB7476B4AD721D40778F49062C3605F1E8FAC9F3F3AC04E46E89E1844DBF4F18FA9303B288741ABD71013CF208F31B4C76FBE342F89B1ABFD97E830457555651B74D3CCDBF94CC5E5EEC22821536A96F44C8BC4346B0271303E67FD313",
    );
    check(
        Dstu7624WrapEngine::<8>::new(),
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
        "9618AE6065069D5054464040F17337D58BEB51AE92391D740BDF7ABB239709C46270832039FF045BCF7878E7DA9C3B4CF89326CA8B4D29DB8680EEAE1B5A18463284713A323A69AEBF33CFC4B11283C7C8041FFC97668EDF727823411C9559816C108C11EC401643765527860D8DA0ED7254792C21DB775DEB1D6971C924CC83EB626173D894694943B1828ABDE8F9495BCEBA9AC3A4A03592C085AA29CC9A0C65786E631A702D589B819C89E79EEFF29C4EC312C8860BB68F02272EA770FB8D",
    );
}

#[test]
fn sizing_empty_input_and_dynamic_dispatch() {
    let key = [0u8; 16];
    let params = KeyRef::new(&key);
    let mut concrete = Dstu7624WrapEngine::<2>::new();
    assert_eq!(concrete.wrapped_len(0), Ok(16));
    assert_eq!(concrete.max_unwrapped_len(16), Ok(0));
    assert_eq!(
        concrete.wrapped_len(15),
        Err(Dstu7624WrapError::InvalidWrapLength)
    );
    assert_eq!(
        concrete.max_unwrapped_len(0),
        Err(Dstu7624WrapError::InvalidUnwrapLength)
    );

    concrete.init(WrapDirection::Wrap, &params).unwrap();
    let wrapper: &mut dyn KeyWrap<Error = Dstu7624WrapError> = &mut concrete;
    let mut wrapped = [0u8; 16];
    wrapper.wrap_into(&[], &mut wrapped).unwrap();

    concrete.init(WrapDirection::Unwrap, &params).unwrap();
    assert_eq!(concrete.unwrap_into(&wrapped, &mut []), Ok(0));
}

#[test]
fn tampering_clears_output_and_init_error_is_separate() {
    let key = hex("000102030405060708090A0B0C0D0E0F");
    let mut wrapped = hex(
        "0EA983D6CE48484D51462C32CC61672210FCC44196ABE635BAF878FDB83E1A63114128585D49DB355C5819FD38039169",
    );
    wrapped[0] ^= 1;
    let mut wrapper = Dstu7624WrapEngine::<2>::new();
    wrapper
        .init(WrapDirection::Unwrap, &KeyRef::new(&key))
        .unwrap();
    let mut output = [0xa5; 32];
    assert_eq!(
        wrapper.unwrap_into(&wrapped, &mut output),
        Err(Dstu7624WrapError::IntegrityCheckFailed)
    );
    assert_eq!(output, [0; 32]);

    assert_eq!(
        wrapper.init(WrapDirection::Wrap, &KeyRef::new(&[0u8; 15])),
        Err(Dstu7624WrapInitError::Cipher(InitError::InvalidKeyLength(
            15
        )))
    );
}
