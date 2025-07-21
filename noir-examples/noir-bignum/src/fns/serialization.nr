/**
* @brief construct a BigNum instance out of an array of bytes in BIG ENDIAN format
* @description: each 120-bit limb represents 15 bytes, we require that the size of the byte array
*               is precisely large enough to cover MOD_BITS
* @param x: input byte array
**/
pub(crate) fn from_be_bytes<let N: u32, let MOD_BITS: u32, let NBytes: u32>(
    x: [u8; NBytes],
) -> [u128; N] {
    let num_bits = NBytes * 8;
    assert(num_bits >= MOD_BITS);
    assert(num_bits - MOD_BITS < 8);
    let mut result: [u128; N] = [0; N];

    let excess_bytes = N * 15 - NBytes;
    let final_limb_bytes = 15 - excess_bytes;
    let mut limb: u128 = 0;
    let mut k = 0;
    for _j in 0..final_limb_bytes {
        limb *= 256;
        limb += x[k] as u128;
        k += 1;
    }
    result[N - 1] = limb;

    for i in 1..N {
        let mut limb: u128 = 0;
        for _j in 0..15 {
            limb *= 256;
            limb += x[k] as u128;
            k += 1;
        }
        result[N - i - 1] = limb;
    }

    let most_significant_byte: Field = x[0] as Field;

    most_significant_byte.assert_max_bit_size::<8 - (NBytes * 8 - MOD_BITS)>();
    result
}

pub(crate) fn to_le_bytes<let N: u32, let MOD_BITS: u32, let NBytes: u32>(
    val: [u128; N],
) -> [u8; NBytes] {
    let nbytes = (MOD_BITS / 8) + (MOD_BITS % 8 != 0) as u32;
    assert(nbytes <= NBytes);

    let mut result: [u8; NBytes] = [0; NBytes];
    for i in 0..N - 1 {
        let limb_bytes: [u8; 15] = (val[i] as Field).to_le_bytes();
        for j in 0..15 {
            result[i * 15 + j] = limb_bytes[j];
        }
    }
    let last_limb_bytes: [u8; 15] = (val[N - 1] as Field).to_le_bytes();
    let num_last_bytes = (NBytes - (N - 1) * 15);
    for i in 0..num_last_bytes {
        result[(N - 1) * 15 + i] = last_limb_bytes[i];
    }
    result
}
