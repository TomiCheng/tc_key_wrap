use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use tc_des_wrap::{DesEdeWrapEngine, DesEdeWrapError, DesEdeWrapInitError};
use tc_key_wrap::{KeyWithIvOptRef, KeyWrap, KeyWrapInit, WrapDirection};

fn hex(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
        .collect()
}

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
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        let end = self.offset + output.len();
        output.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

const KEK: &str = "255e0d1c07b646dfb3134cc843ba8aa71f025b7c0838251f";
const IV: &str = "5dd4cbfc96f5453b";
const INPUT: &str = "2923bf85e06dd6ae529149f1f1bae9eab3a7da3d860d3e98";
const WRAPPED: &str =
    "690107618ef092b3b48ca1796b234ae9fa33ebb4159604037db5d6a84eb3aac2768c632775a467d4";

#[test]
fn bouncy_castle_vector_and_generated_iv() {
    let key = hex(KEK);
    let iv = hex(IV);
    let input = hex(INPUT);
    let expected = hex(WRAPPED);
    let explicit = KeyWithIvOptRef::new(&key, Some(&iv));
    let mut wrapper = DesEdeWrapEngine::new(FixedRng::new(Vec::new()));
    wrapper.init(WrapDirection::Wrap, &explicit).unwrap();
    let mut output = vec![0; wrapper.wrapped_len(input.len()).unwrap()];
    wrapper.wrap_into(&input, &mut output).unwrap();
    assert_eq!(output, expected);

    let generated = KeyWithIvOptRef::new(&key, None);
    let mut wrapper = DesEdeWrapEngine::new(FixedRng::new(iv));
    wrapper.init(WrapDirection::Wrap, &generated).unwrap();
    wrapper.wrap_into(&input, &mut output).unwrap();
    assert_eq!(output, expected);

    let mut unwrapper = DesEdeWrapEngine::new(FixedRng::new(Vec::new()));
    unwrapper.init(WrapDirection::Unwrap, &generated).unwrap();
    let mut recovered = vec![0; unwrapper.max_unwrapped_len(output.len()).unwrap()];
    let written = unwrapper.unwrap_into(&output, &mut recovered).unwrap();
    assert_eq!(&recovered[..written], input);
}

#[test]
fn two_key_des_dynamic_dispatch_and_tampering() {
    let key = hex("0123456789abcdeffedcba9876543210");
    let iv = hex(IV);
    let input = hex("00112233445566778899aabbccddeeff");
    let wrap_params = KeyWithIvOptRef::new(&key, Some(&iv));
    let mut concrete = DesEdeWrapEngine::new(FixedRng::new(Vec::new()));
    concrete.init(WrapDirection::Wrap, &wrap_params).unwrap();
    let wrapper: &mut dyn KeyWrap<Error = DesEdeWrapError> = &mut concrete;
    let mut wrapped = vec![0; wrapper.wrapped_len(input.len()).unwrap()];
    wrapper.wrap_into(&input, &mut wrapped).unwrap();

    let unwrap_params = KeyWithIvOptRef::new(&key, None);
    let mut unwrapper = DesEdeWrapEngine::new(FixedRng::new(Vec::new()));
    unwrapper
        .init(WrapDirection::Unwrap, &unwrap_params)
        .unwrap();
    let mut recovered = vec![0; unwrapper.max_unwrapped_len(wrapped.len()).unwrap()];
    let written = unwrapper.unwrap_into(&wrapped, &mut recovered).unwrap();
    assert_eq!(&recovered[..written], input);

    wrapped[20] ^= 1;
    let mut protected = [0xa5; 16];
    assert_eq!(
        unwrapper.unwrap_into(&wrapped, &mut protected),
        Err(DesEdeWrapError::IntegrityCheckFailed)
    );
    assert_eq!(protected, [0xa5; 16]);
}

#[test]
fn rejects_external_iv_for_unwrap() {
    let key = hex(KEK);
    let iv = hex(IV);
    let params = KeyWithIvOptRef::new(&key, Some(&iv));
    let mut wrapper = DesEdeWrapEngine::new(FixedRng::new(Vec::new()));
    assert_eq!(
        wrapper.init(WrapDirection::Unwrap, &params),
        Err(DesEdeWrapInitError::IvNotAllowedForUnwrap)
    );
}
