use crate::constants::LIMB_SIZE;
use super::unconstrained_helpers::__pack_be_bytes_into_limbs;

// Reverse the bytes of an array so you can switch from
// big endian to little endian order and vice versa
pub fn reverse_bytes_array<let N: u32>(arr: [u8; N]) -> [u8; N] {
    let mut reversed_arr = [0 as u8; N];
    for i in 0..N {
        // Reverse
        reversed_arr[i] = arr[N - 1 - i];
    }
    reversed_arr
}

/**
 * @brief Prove that a chunk of bytes equals a limb
 * @description Both representations should equal the same 32-bit (or less) number
 */
fn prove_chunk_equivalence(bytes: [u8; 4], limb: u64, num_bytes: u32) {
    let mut byte_value: u64 = 0;
    let mut power_of_2: u64 = 1;
    for i in 0..num_bytes {
        byte_value += power_of_2 * (bytes[i] as u64);
        power_of_2 *= 256;
    }

    // Ensure the limb is within 32-bit range
    (limb as Field).assert_max_bit_size::<LIMB_SIZE>();

    // Prove equivalence
    assert(byte_value == limb, "Byte and limb representations must be equal");
}

/**
* @brief construct a BigNum instance out of an array of bytes in BIG ENDIAN format
* @description: each 120-bit limb represents 15 bytes, we require that the size of the byte array
*               is precisely large enough to cover MOD_BITS
* @param x: input byte array
**/
pub(crate) fn from_be_bytes<let N: u32, let MOD_BITS: u32, let NBytes: u32>(
    x: [u8; NBytes],
) -> [u64; N] {
    // safety: Get the unconstrained result
    let result = unsafe { __pack_be_bytes_into_limbs(x) };

    let x_rev = reverse_bytes_array(x);

    // Prove equivalence by processing 4 bytes = 1 limb at a time
    let chunks_of_4_bytes = (NBytes + 3) / 4; // Ceiling division

    for chunk_idx in 0..chunks_of_4_bytes {
        let byte_start = chunk_idx * 4;

        // Extract up to 4 bytes for this chunk
        let mut chunk_bytes: [u8; 4] = [0; 4];
        let bytes_in_chunk = if (byte_start + 4 <= NBytes) {
            4
        } else {
            NBytes - byte_start
        };

        for i in 0..bytes_in_chunk {
            chunk_bytes[i] = x_rev[byte_start + i];
        }

        // Get the corresponding limb
        if chunk_idx < N {
            let chunk_limb = result[chunk_idx];

            // Prove that the byte representation equals the limb representation
            prove_chunk_equivalence(chunk_bytes, chunk_limb, bytes_in_chunk);
        }
    }

    result
}

pub(crate) fn to_le_bytes<let N: u32, let MOD_BITS: u32, let NBytes: u32>(
    val: [u64; N],
) -> [u8; NBytes] {
    let nbytes = (MOD_BITS / 8) + (MOD_BITS % 8 != 0) as u32;
    assert(nbytes <= NBytes);

    let mut result: [u8; NBytes] = [0; NBytes];

    // With 32-bit limbs, each limb is exactly 4 bytes
    for i in 0..N {
        let limb = val[i];
        let byte_start = i * 4;

        // Extract 4 bytes from each limb (little-endian byte order)
        for j in 0..4 {
            let byte_index = byte_start + j;
            if byte_index < NBytes {
                result[byte_index] = ((limb >> (j * 8) as u8) & 0xFF) as u8;
            }
        }
    }

    result
}
