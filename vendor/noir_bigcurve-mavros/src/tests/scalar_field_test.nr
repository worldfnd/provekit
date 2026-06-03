use crate::scalar_field::get_modulus_slices;
use crate::scalar_field::ScalarField;

#[test]
// test even number of nibbles
unconstrained fn fuzz_test_scalar_field_conversion(f: Field) {
    let scalar_field: ScalarField<64> = ScalarField::from(f);
    let scalar_field2 = scalar_field.into();
    assert(f == scalar_field2);
}
#[test]
// test odd number of nibbles
unconstrained fn fuzz_test_scalar_field_conversion2(f: u128) {
    // 2^124 -1, 31 nibbles
    let mask_124: u128 = 0x10000000000000000000000000000000 - 1;
    let val: u128 = f & mask_124;
    let scalar_field: ScalarField<31> = ScalarField::from(val as Field);
    let scalar_field2 = scalar_field.into();
    assert(val as Field == scalar_field2);
}
#[test]
unconstrained fn test_get_modulus_slices() {
    let modulus_slices: [u8; 64] = get_modulus_slices::<64>();
    assert(
        modulus_slices
            == [
                9, 8, 3, 2, 2, 7, 3, 9, 7, 0, 9, 8, 13, 0, 1, 4, 13, 12, 2, 8, 2, 2, 13, 11, 4, 0,
                12, 0, 10, 12, 2, 14, 9, 4, 1, 9, 15, 4, 2, 4, 3, 12, 13, 12, 11, 8, 4, 8, 10, 1,
                15, 0, 15, 10, 12, 9, 15, 8, 0, 0, 0, 0, 0, 0,
            ],
    );
    let modulus_slices2: [u8; 65] = get_modulus_slices::<65>();
    assert(
        modulus_slices2
            == [
                8, 1, 8, 3, 2, 2, 7, 3, 9, 7, 0, 9, 8, 13, 0, 1, 4, 13, 12, 2, 8, 2, 2, 13, 11, 4,
                0, 12, 0, 10, 12, 2, 14, 9, 4, 1, 9, 15, 4, 2, 4, 3, 12, 13, 12, 11, 8, 4, 8, 10, 1,
                15, 0, 15, 10, 12, 9, 15, 8, 0, 0, 0, 0, 0, 0,
            ],
    );
    let modulus_slices3: [u8; 68] = get_modulus_slices::<68>();
    assert(
        modulus_slices3
            == [
                8, 0, 0, 0, 1, 8, 3, 2, 2, 7, 3, 9, 7, 0, 9, 8, 13, 0, 1, 4, 13, 12, 2, 8, 2, 2, 13,
                11, 4, 0, 12, 0, 10, 12, 2, 14, 9, 4, 1, 9, 15, 4, 2, 4, 3, 12, 13, 12, 11, 8, 4, 8,
                10, 1, 15, 0, 15, 10, 12, 9, 15, 8, 0, 0, 0, 0, 0, 0,
            ],
    );
}
#[test(should_fail_with = "Reconstructed number is greater than modulus")]
fn test_get_modulus_slices_fail_64() {
    //13th nibble is 14, which is greater than the modulus
    let modulus_slices: [u8; 64] = [
        9, 8, 3, 2, 2, 7, 3, 9, 7, 0, 9, 8, 14, 0, 1, 4, 13, 12, 2, 8, 2, 2, 13, 11, 4, 0, 12, 0,
        10, 12, 2, 14, 9, 4, 1, 9, 15, 4, 2, 4, 3, 12, 13, 12, 11, 8, 4, 8, 10, 1, 15, 0, 15, 10,
        12, 9, 15, 8, 0, 0, 0, 0, 0, 0,
    ];
    let mut result: ScalarField<64> = ScalarField { base4_slices: modulus_slices, skew: true };
    let _ = result.into();
}
#[test(should_fail_with = "Reconstructed number is greater than modulus")]
fn test_get_modulus_slices_fail_65() {
    //modulus slice represents a number that is greater than the modulus
    let modulus_slices2 = [
        8, 1, 8, 3, 2, 2, 7, 3, 10, 8, 0, 9, 8, 13, 0, 1, 4, 13, 12, 2, 8, 2, 2, 13, 11, 4, 0, 12,
        0, 10, 12, 2, 14, 9, 4, 1, 9, 15, 4, 2, 4, 3, 12, 13, 12, 11, 8, 4, 8, 10, 1, 15, 0, 15, 10,
        12, 9, 15, 8, 0, 0, 0, 0, 0, 0,
    ];
    let mut result: ScalarField<65> = ScalarField { base4_slices: modulus_slices2, skew: true };
    let _ = result.into();
}

#[test(should_fail_with = "Reconstructed number is greater than modulus")]
fn test_get_modulus_slices_fail_68() {
    //modulus slice represents a number that is greater than the modulus
    let modulus_slices3 = [
        8, 0, 0, 0, 2, 8, 3, 2, 2, 7, 3, 9, 7, 0, 9, 8, 13, 0, 1, 4, 13, 12, 2, 8, 2, 2, 13, 11, 4,
        0, 12, 0, 10, 12, 2, 14, 9, 4, 1, 9, 15, 4, 2, 4, 3, 12, 13, 12, 11, 8, 4, 8, 10, 1, 15, 0,
        15, 10, 12, 9, 15, 8, 0, 0, 0, 0, 0, 0,
    ];
    let mut result: ScalarField<68> = ScalarField { base4_slices: modulus_slices3, skew: true };
    let _ = result.into();
}
