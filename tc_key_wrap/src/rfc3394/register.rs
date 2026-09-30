use tc_block_cipher::BlockCipher;
use tc_zeroize::Zeroizing;

/// Runs the RFC 3394 register loop over `A || R` in place.
///
/// Constant time exactly when the cipher is: the loop does no data-dependent
/// work.
pub(crate) fn wrap_in_place<C: BlockCipher>(
    cipher: &mut C,
    block: &mut [u8],
) -> Result<(), C::Error> {
    let n = block.len() / 8 - 1;

    if n == 1 {
        return crypt_block(cipher, block);
    }

    let mut buffer = Zeroizing::new([0u8; 16]);
    for j in 0..6 {
        for i in 1..=n {
            buffer[..8].copy_from_slice(&block[..8]);
            buffer[8..].copy_from_slice(&block[8 * i..8 * i + 8]);
            crypt_block(cipher, &mut buffer[..])?;

            xor_counter(&mut buffer[..8], counter(n, j, i));
            block[..8].copy_from_slice(&buffer[..8]);
            block[8 * i..8 * i + 8].copy_from_slice(&buffer[8..]);
        }
    }
    Ok(())
}

/// Unwinds the registers and returns the recovered A; checking A is left to
/// the caller.
///
/// Constant time exactly when the cipher is: the loop does no data-dependent
/// work.
pub(crate) fn unwrap_into<C: BlockCipher>(
    cipher: &mut C,
    input: &[u8],
    output: &mut [u8],
) -> Result<[u8; 8], C::Error> {
    let n = input.len() / 8 - 1;
    let block = &mut output[..input.len() - 8];
    let mut a = [0u8; 8];
    let mut buffer = Zeroizing::new([0u8; 16]);

    if n == 1 {
        cipher.process_block(&input[..16], &mut buffer[..])?;
        a.copy_from_slice(&buffer[..8]);
        block[..8].copy_from_slice(&buffer[8..]);
        return Ok(a);
    }

    a.copy_from_slice(&input[..8]);
    block.copy_from_slice(&input[8..]);
    for j in (0..6).rev() {
        for i in (1..=n).rev() {
            buffer[..8].copy_from_slice(&a);
            buffer[8..].copy_from_slice(&block[8 * (i - 1)..8 * i]);
            xor_counter(&mut buffer[..8], counter(n, j, i));
            crypt_block(cipher, &mut buffer[..])?;
            a.copy_from_slice(&buffer[..8]);
            block[8 * (i - 1)..8 * i].copy_from_slice(&buffer[8..]);
        }
    }
    Ok(a)
}

// t = n * j + i, computed in u64 so that large inputs cannot truncate it as u32 would.
fn counter(n: usize, j: u64, i: usize) -> u64 {
    n as u64 * j + i as u64
}

fn xor_counter(a: &mut [u8], counter: u64) {
    for (byte, counter_byte) in a.iter_mut().rev().zip(counter.to_le_bytes()) {
        *byte ^= counter_byte;
    }
}

fn crypt_block<C: BlockCipher>(cipher: &mut C, block: &mut [u8]) -> Result<(), C::Error> {
    let mut scratch = Zeroizing::new([0u8; 16]);
    cipher.process_block(block, &mut scratch[..])?;
    block.copy_from_slice(&scratch[..]);
    Ok(())
}
