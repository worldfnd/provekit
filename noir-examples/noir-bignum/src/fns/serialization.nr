use crate::utils::map::invert_array;
/// conversions between big endian and little endian byte arrays and BigNum instances
/// the byte serialization should have `(MOD_BITS + 7) / 8` bytes.
/// each 120-bit limb is represented by 15 bytes, and there are fewer bytes for covering the most significant limb
pub(crate) fn from_be_bytes<let N: u32, let MOD_BITS: u32>(
    x: [u8; (MOD_BITS + 7) / 8],
) -> [u128; N] {
    let num_bits = (MOD_BITS + 7) / 8 * 8;
    assert(num_bits >= MOD_BITS);
    assert(num_bits - MOD_BITS < 8);
    let mut result: [u128; N] = [0; N];

    let excess_bytes = N * 15 - (MOD_BITS + 7) / 8;
    let final_limb_bytes = 15 - excess_bytes;
    let mut limb: Field = 0;
    let mut k = 0;
    for _j in 0..final_limb_bytes {
        limb *= 256;
        limb += x[k] as Field;
        k += 1;
    }
    limb.assert_max_bit_size::<128>();
    result[N - 1] = limb as u128;

    for i in 1..N {
        let mut limb: Field = 0;
        for _j in 0..15 {
            limb *= 256;
            limb += x[k] as Field;
            k += 1;
        }
        limb.assert_max_bit_size::<128>();
        result[N - i - 1] = limb as u128;
    }

    let most_significant_byte: Field = x[0] as Field;

    most_significant_byte.assert_max_bit_size::<8 - ((MOD_BITS + 7) / 8 * 8 - MOD_BITS)>();
    result
}

pub(crate) fn to_be_bytes<let N: u32, let MOD_BITS: u32>(
    val: [u128; N],
) -> [u8; (MOD_BITS + 7) / 8] {
    let mut result: [u8; (MOD_BITS + 7) / 8] = [0; (MOD_BITS + 7) / 8];
    // the last limb will not have all the 15 bytes so we deal with the full limbs first
    for i in 0..N - 1 {
        let index = N - i - 2;
        let limb_bytes: [u8; 15] = (val[index] as Field).to_be_bytes();
        for j in 0..15 {
            // we leave the space for the first byte empty, which would take (MOD_BITS+7)/8 - MOD_BITS/8 bytes
            result[i * 15 + j + (MOD_BITS + 7) / 8 - (N - 1) * 15] = limb_bytes[j];
        }
    }
    // now we deal with the last limb
    let last_limb_bytes: [u8; ((MOD_BITS + 7) / 8 - (N - 1) * 15)] =
        (val[N - 1] as Field).to_be_bytes();

    for i in 0..((MOD_BITS + 7) / 8 - (N - 1) * 15) {
        result[i] = last_limb_bytes[i];
    }
    result
}

pub(crate) fn to_le_bytes<let N: u32, let MOD_BITS: u32>(
    val: [u128; N],
) -> [u8; (MOD_BITS + 7) / 8] {
    let result_be: [u8; (MOD_BITS + 7) / 8] = to_be_bytes(val);
    let result = invert_array(result_be);
    result
}

pub(crate) fn from_le_bytes<let N: u32, let MOD_BITS: u32>(
    x: [u8; (MOD_BITS + 7) / 8],
) -> [u128; N] {
    // make the bytes big endian
    let be_x = invert_array(x);
    from_be_bytes(be_x)
}
