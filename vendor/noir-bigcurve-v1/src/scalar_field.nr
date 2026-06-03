use bignum::BigNum;

/// Represents a scalar multiplier as a sequence of 4-bit slices.
///
/// # Overview
/// `ScalarField` efficiently encodes scalars for twisted Edwards curve operations. Since these curves
/// typically have prime group orders that fit within a field element, scalars can often be reconstructed
/// from their 4-bit slices by summing the slices and verifying equality with the original scalar.
///
/// For arbitrary field elements (scalars that may be multiples of the curve's group order), additional
/// validation is required. In these cases, the sum of the 4-bit slices, interpreted as an integer,
/// must be less than the field modulus. This check is computationally expensive and avoided when possible.
///
/// The `ScalarField<N>` type is flexible:
/// - `ScalarField<63>`: Efficient bitslice conversions for scalars less than 2^252.
/// - `ScalarField<64>`: Supports bitslice conversions for arbitrary field elements.
///
/// **Note:** The bit values in `ScalarField` are not constrained to be less than the curve's group order.
/// This type is intended for use in scalar multiplication, where all operations are performed modulo the
/// curve order.
pub struct ScalarField<let N: u32> {
    pub(crate) base4_slices: [u8; N],
    pub(crate) skew: bool,
}

// 1, 2, 3, 4
unconstrained fn get_wnaf_slices<let N: u32>(x: Field) -> ScalarField<N> {
    let mut base4_slices: [u8; N] = [0; N];
    let bytes = x.to_le_bytes::<32>();
    let mut nibbles: [u8; N] = [0; N];
    nibbles = extract_nibbles_from_bytes(bytes);

    let skew: bool = nibbles[0] & 1 == 0;
    nibbles[0] = nibbles[0] + (skew as u8);
    base4_slices[N - 1] = (nibbles[0] + 15) / 2;

    for i in 1..N {
        let mut nibble: u8 = nibbles[i];
        base4_slices[N - 1 - i] = (nibble + 15) / 2;
        if (nibble & 1 == 0) {
            base4_slices[N - 1 - i] += 1;
            base4_slices[N - i] -= 8;
        }
    }

    ScalarField { base4_slices, skew }
}

unconstrained fn get_wnaf_slices2<let N: u32, B>(x: B) -> ScalarField<N>
where
    B: BigNum,
{
    let mut base4_slices: [u8; N] = [0; N];
    let mut nibbles: [[u8; 30]; (N / 30) + 1] = [[0; 30]; (N / 30) + 1];
    let x: [u128; _] = x.get_limbs();
    for i in 0..x.len() {
        let bytes = (x[i] as Field).to_le_bytes::<30>();
        nibbles[i] = extract_nibbles_from_bytes(bytes);
    }

    let skew: bool = nibbles[0][0] & 1 == 0;
    nibbles[0][0] = nibbles[0][0] + (skew as u8);
    base4_slices[N - 1] = (nibbles[0][0] + 15) / 2;

    for i in 1..N {
        let major_index = i / 30;
        let minor_index = i % 30;
        let mut nibble: u8 = nibbles[major_index][minor_index];
        base4_slices[N - 1 - i] = (nibble + 15) / 2;
        if (nibble & 1 == 0) {
            base4_slices[N - 1 - i] += 1;
            base4_slices[N - i] -= 8;
        }
    }

    ScalarField { base4_slices, skew }
}

pub(crate) fn get_modulus_slices<let N: u32>() -> [u8; N] {
    let mut expected_slices: [u8; N] = [0; N];

    if N == 64 {
        let slice: [u8; 64] = [
            9, 8, 3, 2, 2, 7, 3, 9, 7, 0, 9, 8, 13, 0, 1, 4, 13, 12, 2, 8, 2, 2, 13, 11, 4, 0, 12,
            0, 10, 12, 2, 14, 9, 4, 1, 9, 15, 4, 2, 4, 3, 12, 13, 12, 11, 8, 4, 8, 10, 1, 15, 0, 15,
            10, 12, 9, 15, 8, 0, 0, 0, 0, 0, 0,
        ];
        for i in 0..N {
            expected_slices[i] = slice[i];
        }
    } else if N == 65 {
        let slice: [u8; 65] = [
            8, 1, 8, 3, 2, 2, 7, 3, 9, 7, 0, 9, 8, 13, 0, 1, 4, 13, 12, 2, 8, 2, 2, 13, 11, 4, 0,
            12, 0, 10, 12, 2, 14, 9, 4, 1, 9, 15, 4, 2, 4, 3, 12, 13, 12, 11, 8, 4, 8, 10, 1, 15, 0,
            15, 10, 12, 9, 15, 8, 0, 0, 0, 0, 0, 0,
        ];
        for i in 0..N {
            expected_slices[i] = slice[i];
        }
    } else if N > 65 {
        // For N > 65, we need to insert zeros at the beginning
        let num_zeros = N - 65;
        expected_slices[0] = 8;
        for i in 1..num_zeros + 1 {
            expected_slices[i] = 0;
        }
        let slice: [u8; 65] = [
            8, 1, 8, 3, 2, 2, 7, 3, 9, 7, 0, 9, 8, 13, 0, 1, 4, 13, 12, 2, 8, 2, 2, 13, 11, 4, 0,
            12, 0, 10, 12, 2, 14, 9, 4, 1, 9, 15, 4, 2, 4, 3, 12, 13, 12, 11, 8, 4, 8, 10, 1, 15, 0,
            15, 10, 12, 9, 15, 8, 0, 0, 0, 0, 0, 0,
        ];
        for i in num_zeros + 1..N {
            expected_slices[i] = slice[i - num_zeros];
        }
    }
    expected_slices
}

pub fn compare_scalar_field_to_bignum<let N: u32>(result: ScalarField<N>) {
    let expected_slices: [u8; N] = get_modulus_slices::<N>();

    // Lexicographic comparison: stop when we find a strictly smaller number
    let mut should_continue: bool = true;
    for i in 0..N {
        if should_continue {
            if result.base4_slices[i] < expected_slices[i] {
                // Found a strictly smaller number, we can stop - this is valid
                should_continue = false;
            } else if result.base4_slices[i] > expected_slices[i] {
                // Found a strictly larger number, this is invalid
                panic(f"Reconstructed number is greater than modulus");
            }
            // If equal, continue to the next element (should_continue remains true)
        }
    }
}

impl<let N: u32> std::convert::From<Field> for ScalarField<N> {

    /// Constructs an instance from a field element.
    fn from(input: Field) -> Self {
        let result = unsafe { get_wnaf_slices(input) };

        if !std::runtime::is_unconstrained() {
            // Enforce that limbs are all 4 bits.
            for i in 0..N {
                (result.base4_slices[i] as Field).assert_max_bit_size::<4>();
            }

            // Enforce consistency with `input`.
            let reconstructed_input: Field = result.into();
            assert_eq(reconstructed_input, input);
            if N >= 64 {
                compare_scalar_field_to_bignum(result);
            }
        }
        result
    }
}

impl<let N: u32> std::convert::Into<Field> for ScalarField<N> {
    /**
     * @brief construct from tuple of field elements
     * @details use this method instead of `new` if you know x/y is on the curve
     **/
    fn into(self: Self) -> Field {
        // TODO: This is susceptible to overflow when N is large!
        if !std::runtime::is_unconstrained() {
            if N >= 64 {
                compare_scalar_field_to_bignum(self);
            }
        }
        let mut acc: Field = 0;
        for i in 0..N {
            acc = acc * 16;
            acc = acc + (self.base4_slices[i] as Field) * 2 - 15;
        }
        acc -= self.skew as Field;
        acc
    }
}

impl<let N: u32> ScalarField<N> {
    pub fn len(_: Self) -> u32 {
        N
    }

    pub fn zero() -> Self {
        let mut result: Self = ScalarField { base4_slices: [0; N], skew: true };
        result.base4_slices[0] = 8; // 8 = numeric value of 1, 0 = numeric value of -15
        result
    }

    // Note: I can't propagate ModulusBits or NumLimbs from a generic that satisfies BigNum due to bugs, so we have to pass NumLimbs and Params in directly. disgusting!
    pub fn from_bignum<B>(x: B) -> Self
    where
        B: BigNum,
    {
        x.validate_in_field();
        // Safety: separate verification
        let mut slices_result = unsafe { get_wnaf_slices2(x) };
        let mut slices = slices_result.base4_slices;
        let skew = slices_result.skew;
        for i in 0..N {
            (slices[i] as Field).assert_max_bit_size::<4>();
        }
        let mut result = B::zero();
        let mut count: u32 = 0;
        {
            let mut acc: u128 = 0;
            let mut last_bits = (result.modulus_bits() % 120) as u64;
            if (last_bits == 0) {
                last_bits = 120;
            }
            let mut last_nibbles = (last_bits / 4) + 1 as u64;
            for _ in 0..last_nibbles {
                acc = acc * 16;
                acc = acc + (slices[count] as u128) * 2 - 15;
                count = count + 1;
            }
            result.set_limb(result.num_limbs() - 1, acc);
        }
        for i in 1..result.num_limbs() {
            // Using a Field type to allow for negative numbers.
            let mut acc: Field = 0;
            for _ in 0..30 {
                acc = acc * 16;
                acc = acc + (slices[count] as Field) * 2 - 15;
                count = count + 1;
            }
            // Handle overflow using helper function
            let acc_u128 = handle_overflow::<B>(acc, &mut result, i);
            result.set_limb(result.num_limbs() - 1 - i, acc_u128);
        }
        result.set_limb(0, result.get_limb(0) - skew as u128);
        assert(result == x);
        Self { base4_slices: slices, skew }
    }

    pub fn into_bignum<B>(self) -> B
    where
        B: BigNum,
    {
        let mut result = B::zero();
        let mut count: u32 = 0;
        {
            let mut acc: u128 = 0;
            let mut last_bits = (result.modulus_bits() % 120) as u64;
            if (last_bits == 0) {
                last_bits = 120;
            }
            let mut last_nibbles = (last_bits / 4) + 1 as u64;
            for _ in 0..last_nibbles {
                acc = acc * 16;
                acc = acc + (self.base4_slices[count] as u128) * 2 - 15;
                count = count + 1;
            }
            result.set_limb(result.num_limbs() - 1, acc);
        }
        for i in 1..result.num_limbs() {
            // Using a Field type to allow for negative numbers.
            let mut acc: Field = 0;
            for _ in 0..30 {
                acc = acc * 16;
                acc = acc + (self.base4_slices[count] as Field) * 2 - 15;
                count = count + 1;
            }
            // Handle overflow using helper function
            let acc_u128 = handle_overflow::<B>(acc, &mut result, i);
            result.set_limb(result.num_limbs() - 1 - i, acc_u128);
        }
        result.set_limb(0, result.get_limb(0) - self.skew as u128);
        result
    }

    pub fn new() -> Self {
        Self { base4_slices: [0; N], skew: false }
    }

    pub fn get(self, idx: u32) -> u8 {
        self.base4_slices[idx]
    }
}

pub(crate) unconstrained fn extract_nibbles_from_bytes<let N: u32, let M: u32>(
    bytes: [u8; M],
) -> [u8; N] {
    let mut result: [u8; N] = [0; N];
    let mut nibble_idx = 0;

    for i in 0..M {
        if nibble_idx >= N {
            break;
        }
        // Extract low nibble (bits 0-3)
        result[nibble_idx] = bytes[i] & 0x0F;
        nibble_idx += 1;

        if nibble_idx >= N {
            break;
        }
        // Extract high nibble (bits 4-7)
        result[nibble_idx] = (bytes[i] >> 4);
        nibble_idx += 1;
    }

    result
}

// Helper function to handle overflow in wNAF reconstruction
fn handle_overflow<B: BigNum>(acc: Field, result: &mut B, limb_index: u32) -> u128 {
    let mut acc_u128: u128 = acc as u128;

    // Handle negative numbers. If the number is negative, it is greater than 2^120 in Field.
    // All positive numbers are less than 2^120 in Field.
    // For example, 42 is -6 + 3 * 2^4 with wnaf algorithm, but it should be 42 = 10 + 2 * 2^4
    // To get the actual number 10, we need to subtract the number 6 from 2^4.
    if acc_u128 >= 0x1000000000000000000000000000000 {
        // find the actual number needed to be subtracted.
        let reverse = (acc * -1) as u128;
        acc_u128 = (1 as u128 << 120) - reverse;
        result.set_limb(
            result.num_limbs() - limb_index,
            result.get_limb(result.num_limbs() - limb_index) - 1,
        );
    }
    acc_u128
}
