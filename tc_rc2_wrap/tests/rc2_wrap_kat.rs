use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use tc_block_cipher::KeyParams;
use tc_key_wrap::{IvOptParams, KeyWrap, KeyWrapInit, WrapDirection};
use tc_rc_cipher::Rc2Params;
use tc_rc2_wrap::{Rc2WrapEngine, Rc2WrapError, Rc2WrapInitError};

fn hex(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
        .collect()
}

struct Params<'a> {
    key: &'a [u8],
    effective_bits: usize,
    iv: Option<&'a [u8]>,
}
impl KeyParams for Params<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}
impl Rc2Params for Params<'_> {
    fn effective_key_bits(&self) -> usize {
        self.effective_bits
    }
}
impl IvOptParams for Params<'_> {
    fn iv_opt(&self) -> Option<&[u8]> {
        self.iv
    }
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
        let mut b = [0; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        let end = self.offset + out.len();
        out.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(())
    }
}
impl TryCryptoRng for FixedRng {}

const KEK: &str = "fd04fd08060707fb0003fefffd02fe05";
const IV: &str = "c7d90059b29e97f7";
const PADDING: &str = "4845cce7fd1250";
const INPUT: &str = "b70a25fbc9d86a86050ce0d711ead4d9";
const WRAPPED: &str =
    "70e699fb5701f7833330fb71e87c85a420bdc99af05d22af5a0e48d35f3138986cbaafb4b28d4f35";

#[test]
fn rfc3217_vector_and_generated_iv() {
    let key = hex(KEK);
    let iv = hex(IV);
    let input = hex(INPUT);
    let expected = hex(WRAPPED);
    let params = Params {
        key: &key,
        effective_bits: 40,
        iv: Some(&iv),
    };
    let mut w = Rc2WrapEngine::new(FixedRng::new(hex(PADDING)));
    w.init(WrapDirection::Wrap, &params).unwrap();
    let mut output = vec![0; w.wrapped_len(input.len()).unwrap()];
    w.wrap_into(&input, &mut output).unwrap();
    assert_eq!(output, expected);

    let mut random = iv.clone();
    random.extend_from_slice(&hex(PADDING));
    let params = Params {
        key: &key,
        effective_bits: 40,
        iv: None,
    };
    let mut w = Rc2WrapEngine::new(FixedRng::new(random));
    w.init(WrapDirection::Wrap, &params).unwrap();
    w.wrap_into(&input, &mut output).unwrap();
    assert_eq!(output, expected);
    let mut u = Rc2WrapEngine::new(FixedRng::new(Vec::new()));
    u.init(WrapDirection::Unwrap, &params).unwrap();
    let mut recovered = vec![0; u.max_unwrapped_len(output.len()).unwrap()];
    let n = u.unwrap_into(&output, &mut recovered).unwrap();
    assert_eq!(&recovered[..n], input);
}

#[test]
fn variable_lengths_dynamic_dispatch_and_tampering() {
    let key = [0x5a; 16];
    for length in [0, 1, 7, 8, 15, 16, 31, 255] {
        let input: Vec<u8> = (0..length).map(|i| i as u8).collect();
        let params = Params {
            key: &key,
            effective_bits: 128,
            iv: None,
        };
        let mut concrete = Rc2WrapEngine::new(FixedRng::new(vec![0xa5; 16]));
        concrete.init(WrapDirection::Wrap, &params).unwrap();
        let w: &mut dyn KeyWrap<Error = Rc2WrapError> = &mut concrete;
        let mut wrapped = vec![0; w.wrapped_len(length).unwrap()];
        w.wrap_into(&input, &mut wrapped).unwrap();
        let mut u = Rc2WrapEngine::new(FixedRng::new(Vec::new()));
        u.init(WrapDirection::Unwrap, &params).unwrap();
        let mut recovered = vec![0; u.max_unwrapped_len(wrapped.len()).unwrap()];
        let n = u.unwrap_into(&wrapped, &mut recovered).unwrap();
        assert_eq!(&recovered[..n], input, "length {length}");
    }

    let key = hex(KEK);
    let params = Params {
        key: &key,
        effective_bits: 40,
        iv: None,
    };
    let mut wrapped = hex(WRAPPED);
    wrapped[20] ^= 1;
    let mut u = Rc2WrapEngine::new(FixedRng::new(Vec::new()));
    u.init(WrapDirection::Unwrap, &params).unwrap();
    let mut output = [0xa5; 23];
    assert!(matches!(
        u.unwrap_into(&wrapped, &mut output),
        Err(Rc2WrapError::IntegrityCheckFailed)
    ));
    assert_eq!(output, [0xa5; 23]);
}

#[test]
fn rejects_external_iv_for_unwrap() {
    let key = hex(KEK);
    let iv = hex(IV);
    let params = Params {
        key: &key,
        effective_bits: 40,
        iv: Some(&iv),
    };
    let mut w = Rc2WrapEngine::new(FixedRng::new(Vec::new()));
    assert_eq!(
        w.init(WrapDirection::Unwrap, &params),
        Err(Rc2WrapInitError::IvNotAllowedForUnwrap)
    );
}
