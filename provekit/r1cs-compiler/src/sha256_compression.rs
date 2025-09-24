use {
    crate::{
        digits::{add_digital_decomposition, DigitalDecompositionWitnessesBuilder},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::Field,
    provekit_common::{witness::ConstantOrR1CSWitness, FieldElement},
    std::collections::BTreeMap,
};

/// Add two u32 values modulo 2^32, returning the witness index of the result
/// The solver will compute: result = (a + b) % 2^32, carry = (a + b) / 2^32
pub(crate) fn add_u32_addition(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    a_witness: usize,
    b_witness: usize,
) -> usize {
    // Reserve witnesses for carry and result (solver will compute these)
    let carry_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    let result_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    // Add constraint: a + b = result + carry * 2^32
    let two_pow_32 = FieldElement::from(1u64 << 32);
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::ONE, a_witness),
            (FieldElement::ONE, b_witness),
        ],
        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
        &[
            (FieldElement::ONE, result_witness),
            (two_pow_32, carry_witness),
        ],
    );

    // Range checks to ensure correctness
    range_checks.entry(1).or_default().push(carry_witness); // carry ∈ {0, 1}
    range_checks.entry(32).or_default().push(result_witness); // result ∈ [0, 2^32-1]

    result_witness
}

/// Perform right rotation of a 32-bit value: ROTR(x, n) = (x >> n) | (x <<
/// (32-n)) Returns the witness index of the rotated result
pub(crate) fn add_right_rotate(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x_witness: usize,
    rotation_amount: u32,
) -> usize {
    assert!(rotation_amount < 32, "Rotation amount must be less than 32");

    if rotation_amount == 0 {
        return x_witness; // No rotation needed
    }

    // Split x into two parts using digital decomposition:
    // x = high_bits * 2^n + low_bits
    // where low_bits has n bits and high_bits has (32-n) bits
    let log_bases = vec![rotation_amount as usize, (32 - rotation_amount) as usize];
    let dd_struct = add_digital_decomposition(r1cs_compiler, log_bases, vec![x_witness]);

    // Get the digit witnesses: [low_bits, high_bits]
    let low_bits_witness = dd_struct.get_digit_witness_index(0, 0);
    let high_bits_witness = dd_struct.get_digit_witness_index(1, 0);

    // Compute the shifts:
    // - low_bits shifted left by (32-n): low_bits * 2^(32-n)
    // - high_bits shifted right by n: high_bits / 2^n = high_bits (already shifted
    //   by the decomposition)

    let shift_left_amount = 32 - rotation_amount;
    let shift_multiplier = FieldElement::from(1u64 << shift_left_amount);

    // Create witness for low_bits << (32-n)
    let shifted_low_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    // Constraint: shifted_low = low_bits * 2^(32-n)
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, low_bits_witness)],
        &[(shift_multiplier, r1cs_compiler.witness_one())],
        &[(FieldElement::ONE, shifted_low_witness)],
    );

    // The result is: high_bits XOR shifted_low_bits
    // Since high_bits occupies the lower (32-n) bits and shifted_low occupies the
    // upper n bits, they don't overlap, so XOR is equivalent to addition
    let result_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    // Constraint: result = high_bits + shifted_low
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::ONE, high_bits_witness),
            (FieldElement::ONE, shifted_low_witness),
        ],
        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
        &[(FieldElement::ONE, result_witness)],
    );

    // Range check the result to ensure it's a valid 32-bit value
    range_checks.entry(32).or_default().push(result_witness);

    // Range check intermediate values
    range_checks
        .entry(32)
        .or_default()
        .push(shifted_low_witness);

    result_witness
}

/// Perform right shift of a 32-bit value: SHR(x, n) = x >> n
/// Returns the witness index of the shifted result
pub(crate) fn add_right_shift(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x_witness: usize,
    shift_amount: u32,
) -> usize {
    assert!(shift_amount < 32, "Shift amount must be less than 32");

    if shift_amount == 0 {
        return x_witness; // No shift needed
    }

    // Split x using digital decomposition: x = result * 2^n + discarded_bits
    // where discarded_bits has n bits (the bits that get shifted out)
    // and result has (32-n) bits (the bits that remain)
    let log_bases = vec![shift_amount as usize, (32 - shift_amount) as usize];
    let dd_struct = add_digital_decomposition(r1cs_compiler, log_bases, vec![x_witness]);

    // Get the digit witnesses: [discarded_bits, result]
    let _discarded_bits_witness = dd_struct.get_digit_witness_index(0, 0);
    let result_witness = dd_struct.get_digit_witness_index(1, 0);

    // The result is already computed by the digital decomposition
    // No additional constraints needed, just range check
    range_checks
        .entry(32 - shift_amount)
        .or_default()
        .push(result_witness);

    result_witness
}

pub(crate) fn add_sha256_compression(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    and_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    inputs_and_outputs: Vec<(
        Vec<ConstantOrR1CSWitness>,
        Vec<ConstantOrR1CSWitness>,
        Vec<usize>,
    )>,
) {
    // TODO: Implement full SHA256 compression using the primitive functions
    // above
}
