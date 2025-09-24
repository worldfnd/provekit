use {
    crate::{
        digits::{add_digital_decomposition, DigitalDecompositionWitnessesBuilder},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::Field,
    provekit_common::{
        witness::{ConstantOrR1CSWitness, SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::collections::BTreeMap,
};

/// SHA256 round constants K[0..63]
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Add two u32 values modulo 2^32, returning the witness index of the result
/// The solver will compute: result = (a + b) % 2^32, carry = (a + b) / 2^32
pub(crate) fn add_u32_addition(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    a: ConstantOrR1CSWitness,
    b: ConstantOrR1CSWitness,
) -> usize {
    // Reserve witnesses for carry and result (solver will compute these)
    let carry_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    let result_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    // Add witness builder with explicit computation logic
    r1cs_compiler.add_witness_builder(WitnessBuilder::U32Addition(
        result_witness,
        carry_witness,
        a.clone(),
        b.clone(),
    ));

    // Add constraint: a + b = result + carry * 2^32
    let two_pow_32 = FieldElement::from(1u64 << 32);
    r1cs_compiler.r1cs.add_constraint(
        &[a.to_tuple(), b.to_tuple()],
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
    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(shifted_low_witness, vec![SumTerm(
        Some(shift_multiplier),
        low_bits_witness,
    )]));

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
    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(result_witness, vec![
        SumTerm(None, high_bits_witness),
        SumTerm(None, shifted_low_witness),
    ]));

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

/// SHA256 sigma0 function: σ₀(x) = ROTR(x,7) ⊕ ROTR(x,18) ⊕ SHR(x,3)
/// Used in message schedule expansion
pub(crate) fn add_sigma0(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x_witness: usize,
) -> usize {
    // Compute the three components
    let rotr7 = add_right_rotate(r1cs_compiler, range_checks, x_witness, 7);
    let rotr18 = add_right_rotate(r1cs_compiler, range_checks, x_witness, 18);
    let shr3 = add_right_shift(r1cs_compiler, range_checks, x_witness, 3);

    // First XOR: rotr7 ⊕ rotr18
    let temp_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    xor_ops.push((
        ConstantOrR1CSWitness::Witness(rotr7),
        ConstantOrR1CSWitness::Witness(rotr18),
        temp_witness,
    ));

    // Second XOR: (rotr7 ⊕ rotr18) ⊕ shr3
    let result_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    xor_ops.push((
        ConstantOrR1CSWitness::Witness(temp_witness),
        ConstantOrR1CSWitness::Witness(shr3),
        result_witness,
    ));

    // Range check the result
    range_checks.entry(32).or_default().push(result_witness);

    result_witness
}

/// SHA256 sigma1 function: σ₁(x) = ROTR(x,17) ⊕ ROTR(x,19) ⊕ SHR(x,10)
/// Used in message schedule expansion
pub(crate) fn add_sigma1(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x_witness: usize,
) -> usize {
    // Compute the three components
    let rotr17 = add_right_rotate(r1cs_compiler, range_checks, x_witness, 17);
    let rotr19 = add_right_rotate(r1cs_compiler, range_checks, x_witness, 19);
    let shr10 = add_right_shift(r1cs_compiler, range_checks, x_witness, 10);

    // First XOR: rotr17 ⊕ rotr19
    let temp_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    xor_ops.push((
        ConstantOrR1CSWitness::Witness(rotr17),
        ConstantOrR1CSWitness::Witness(rotr19),
        temp_witness,
    ));

    // Second XOR: (rotr17 ⊕ rotr19) ⊕ shr10
    let result_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    xor_ops.push((
        ConstantOrR1CSWitness::Witness(temp_witness),
        ConstantOrR1CSWitness::Witness(shr10),
        result_witness,
    ));

    // Range check the result
    range_checks.entry(32).or_default().push(result_witness);

    result_witness
}

/// SHA256 capital sigma0 function: Σ₀(x) = ROTR(x,2) ⊕ ROTR(x,13) ⊕ ROTR(x,22)
/// Used in main compression rounds
pub(crate) fn add_cap_sigma0(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x_witness: usize,
) -> usize {
    // Compute the three components
    let rotr2 = add_right_rotate(r1cs_compiler, range_checks, x_witness, 2);
    let rotr13 = add_right_rotate(r1cs_compiler, range_checks, x_witness, 13);
    let rotr22 = add_right_rotate(r1cs_compiler, range_checks, x_witness, 22);

    // First XOR: rotr2 ⊕ rotr13
    let temp_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    xor_ops.push((
        ConstantOrR1CSWitness::Witness(rotr2),
        ConstantOrR1CSWitness::Witness(rotr13),
        temp_witness,
    ));

    // Second XOR: (rotr2 ⊕ rotr13) ⊕ rotr22
    let result_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    xor_ops.push((
        ConstantOrR1CSWitness::Witness(temp_witness),
        ConstantOrR1CSWitness::Witness(rotr22),
        result_witness,
    ));

    // Range check the result
    range_checks.entry(32).or_default().push(result_witness);

    result_witness
}

/// SHA256 capital sigma1 function: Σ₁(x) = ROTR(x,6) ⊕ ROTR(x,11) ⊕ ROTR(x,25)
/// Used in main compression rounds
pub(crate) fn add_cap_sigma1(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x_witness: usize,
) -> usize {
    // Compute the three components
    let rotr6 = add_right_rotate(r1cs_compiler, range_checks, x_witness, 6);
    let rotr11 = add_right_rotate(r1cs_compiler, range_checks, x_witness, 11);
    let rotr25 = add_right_rotate(r1cs_compiler, range_checks, x_witness, 25);

    // First XOR: rotr6 ⊕ rotr11
    let temp_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    xor_ops.push((
        ConstantOrR1CSWitness::Witness(rotr6),
        ConstantOrR1CSWitness::Witness(rotr11),
        temp_witness,
    ));

    // Second XOR: (rotr6 ⊕ rotr11) ⊕ rotr25
    let result_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    xor_ops.push((
        ConstantOrR1CSWitness::Witness(temp_witness),
        ConstantOrR1CSWitness::Witness(rotr25),
        result_witness,
    ));

    // Range check the result
    range_checks.entry(32).or_default().push(result_witness);

    result_witness
}

/// SHA256 choice function: Ch(x,y,z) = (x & y) ⊕ (~x & z)
/// Used in main compression rounds
pub(crate) fn add_ch(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    and_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x_witness: usize,
    y_witness: usize,
    z_witness: usize,
) -> usize {
    // First, compute x & y
    let xy_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    and_ops.push((
        ConstantOrR1CSWitness::Witness(x_witness),
        ConstantOrR1CSWitness::Witness(y_witness),
        xy_witness,
    ));

    // Next, compute ~x & z
    // ~x = (2^32 - 1) - x (bitwise NOT in u32)
    let max_u32 = FieldElement::from((1u64 << 32) - 1);
    let not_x_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);
    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(not_x_witness, vec![
        SumTerm(Some(max_u32), r1cs_compiler.witness_one()),
        SumTerm(Some(-FieldElement::ONE), x_witness),
    ]));

    // Constraint: not_x = 0xFFFFFFFF - x
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::ONE, x_witness),
            (FieldElement::ONE, not_x_witness),
        ],
        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
        &[(max_u32, r1cs_compiler.witness_one())],
    );

    // Compute (~x & z)
    let not_x_z_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    and_ops.push((
        ConstantOrR1CSWitness::Witness(not_x_witness),
        ConstantOrR1CSWitness::Witness(z_witness),
        not_x_z_witness,
    ));

    // Finally, compute (x & y) ⊕ (~x & z)
    let result_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    xor_ops.push((
        ConstantOrR1CSWitness::Witness(xy_witness),
        ConstantOrR1CSWitness::Witness(not_x_z_witness),
        result_witness,
    ));

    // Range checks
    range_checks.entry(32).or_default().push(not_x_witness);
    range_checks.entry(32).or_default().push(result_witness);

    result_witness
}

/// SHA256 majority function: Maj(x,y,z) = (x & y) ⊕ (x & z) ⊕ (y & z)
/// Used in main compression rounds
pub(crate) fn add_maj(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    and_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x_witness: usize,
    y_witness: usize,
    z_witness: usize,
) -> usize {
    // Compute x & y
    let xy_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    and_ops.push((
        ConstantOrR1CSWitness::Witness(x_witness),
        ConstantOrR1CSWitness::Witness(y_witness),
        xy_witness,
    ));

    // Compute x & z
    let xz_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    and_ops.push((
        ConstantOrR1CSWitness::Witness(x_witness),
        ConstantOrR1CSWitness::Witness(z_witness),
        xz_witness,
    ));

    // Compute y & z
    let yz_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    and_ops.push((
        ConstantOrR1CSWitness::Witness(y_witness),
        ConstantOrR1CSWitness::Witness(z_witness),
        yz_witness,
    ));

    // First XOR: (x & y) ⊕ (x & z)
    let temp_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    xor_ops.push((
        ConstantOrR1CSWitness::Witness(xy_witness),
        ConstantOrR1CSWitness::Witness(xz_witness),
        temp_witness,
    ));

    // Second XOR: ((x & y) ⊕ (x & z)) ⊕ (y & z)
    let result_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    xor_ops.push((
        ConstantOrR1CSWitness::Witness(temp_witness),
        ConstantOrR1CSWitness::Witness(yz_witness),
        result_witness,
    ));

    // Range check the result
    range_checks.entry(32).or_default().push(result_witness);

    result_witness
}

/// SHA256 message schedule expansion: expand 16 u32 words to 64 u32 words
/// W[i] = σ₁(W[i-2]) + W[i-7] + σ₀(W[i-15]) + W[i-16] for i = 16..64
pub(crate) fn add_message_schedule_expansion(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    input_words: &[usize; 16],
) -> [usize; 64] {
    let mut w: [usize; 64] = [0usize; 64];

    // First 16 words are the input
    for i in 0..16 {
        w[i] = input_words[i];
    }

    // Expand to 64 words
    for i in 16..64 {
        // Compute σ₁(W[i-2])
        let sigma1_w_i_minus_2 = add_sigma1(r1cs_compiler, xor_ops, range_checks, w[i - 2]);

        // Compute σ₀(W[i-15])
        let sigma0_w_i_minus_15 = add_sigma0(r1cs_compiler, xor_ops, range_checks, w[i - 15]);

        // First addition: σ₁(W[i-2]) + W[i-7]
        let temp1 = add_u32_addition(
            r1cs_compiler,
            range_checks,
            ConstantOrR1CSWitness::Witness(sigma1_w_i_minus_2),
            ConstantOrR1CSWitness::Witness(w[i - 7]),
        );

        // Second addition: temp1 + σ₀(W[i-15])
        let temp2 = add_u32_addition(
            r1cs_compiler,
            range_checks,
            ConstantOrR1CSWitness::Witness(temp1),
            ConstantOrR1CSWitness::Witness(sigma0_w_i_minus_15),
        );

        // Final addition: temp2 + W[i-16]
        w[i] = add_u32_addition(
            r1cs_compiler,
            range_checks,
            ConstantOrR1CSWitness::Witness(temp2),
            ConstantOrR1CSWitness::Witness(w[i - 16]),
        );
    }

    w
}

/// SHA256 single compression round
/// Updates working variables: a, b, c, d, e, f, g, h
/// T1 = h + Σ₁(e) + Ch(e,f,g) + K[i] + W[i]
/// T2 = Σ₀(a) + Maj(a,b,c)
/// Returns new (a, b, c, d, e, f, g, h) where a = T1+T2, e = d+T1, others
/// rotate
pub(crate) fn add_sha256_round(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    and_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    working_vars: [usize; 8], // [a, b, c, d, e, f, g, h]
    k_constant: FieldElement, // Round constant K[i]
    w_word: usize,            // Message schedule word W[i]
) -> [usize; 8] {
    let [a, b, c, d, e, f, g, h] = working_vars;

    // Compute T1 = h + Σ₁(e) + Ch(e,f,g) + K[i] + W[i]

    // Step 1: Σ₁(e)
    let sigma1_e = add_cap_sigma1(r1cs_compiler, xor_ops, range_checks, e);

    // Step 2: Ch(e,f,g)
    let ch_efg = add_ch(r1cs_compiler, and_ops, xor_ops, range_checks, e, f, g);

    // Step 3: h + Σ₁(e)
    let temp1 = add_u32_addition(
        r1cs_compiler,
        range_checks,
        ConstantOrR1CSWitness::Witness(h),
        ConstantOrR1CSWitness::Witness(sigma1_e),
    );

    // Step 4: temp1 + Ch(e,f,g)
    let temp2 = add_u32_addition(
        r1cs_compiler,
        range_checks,
        ConstantOrR1CSWitness::Witness(temp1),
        ConstantOrR1CSWitness::Witness(ch_efg),
    );

    // Step 5: temp2 + K[i]
    let temp3 = add_u32_addition(
        r1cs_compiler,
        range_checks,
        ConstantOrR1CSWitness::Witness(temp2),
        ConstantOrR1CSWitness::Constant(k_constant),
    );

    // Step 6: T1 = temp3 + W[i]
    let t1 = add_u32_addition(
        r1cs_compiler,
        range_checks,
        ConstantOrR1CSWitness::Witness(temp3),
        ConstantOrR1CSWitness::Witness(w_word),
    );

    // Compute T2 = Σ₀(a) + Maj(a,b,c)

    // Step 1: Σ₀(a)
    let sigma0_a = add_cap_sigma0(r1cs_compiler, xor_ops, range_checks, a);

    // Step 2: Maj(a,b,c)
    let maj_abc = add_maj(r1cs_compiler, and_ops, xor_ops, range_checks, a, b, c);

    // Step 3: T2 = Σ₀(a) + Maj(a,b,c)
    let t2 = add_u32_addition(
        r1cs_compiler,
        range_checks,
        ConstantOrR1CSWitness::Witness(sigma0_a),
        ConstantOrR1CSWitness::Witness(maj_abc),
    );

    // Update working variables
    // new_h = g
    // new_g = f
    // new_f = e
    // new_e = d + T1
    // new_d = c
    // new_c = b
    // new_b = a
    // new_a = T1 + T2

    let new_e = add_u32_addition(
        r1cs_compiler,
        range_checks,
        ConstantOrR1CSWitness::Witness(d),
        ConstantOrR1CSWitness::Witness(t1),
    );
    let new_a = add_u32_addition(
        r1cs_compiler,
        range_checks,
        ConstantOrR1CSWitness::Witness(t1),
        ConstantOrR1CSWitness::Witness(t2),
    );

    [new_a, a, b, c, new_e, e, f, g]
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
    for (inputs, hash_values, outputs) in inputs_and_outputs {
        // Ensure we have exactly 16 input words and 8 hash values and 8 outputs
        assert_eq!(
            inputs.len(),
            16,
            "SHA256 requires exactly 16 input u32 words"
        );
        assert_eq!(
            hash_values.len(),
            8,
            "SHA256 requires exactly 8 initial hash values"
        );
        assert_eq!(
            outputs.len(),
            8,
            "SHA256 produces exactly 8 output u32 words"
        );

        // Convert inputs to witness indices (assuming they're all witnesses for now)
        let input_witnesses: [usize; 16] = inputs
            .iter()
            .map(|input| match input {
                ConstantOrR1CSWitness::Witness(idx) => *idx,
                ConstantOrR1CSWitness::Constant(_) => {
                    panic!("Input constants not yet supported")
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Convert initial hash values to witness indices
        let initial_hash_witnesses: [usize; 8] = hash_values
            .iter()
            .map(|hash_val| match hash_val {
                ConstantOrR1CSWitness::Witness(idx) => *idx,
                ConstantOrR1CSWitness::Constant(_) => {
                    panic!("Hash value constants not yet supported")
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Step 1: Message schedule expansion (16 words -> 64 words)
        let w =
            add_message_schedule_expansion(r1cs_compiler, xor_ops, range_checks, &input_witnesses);

        // Step 2: Initialize working variables with initial hash values
        let mut working_vars = initial_hash_witnesses;

        // Step 3: Main compression loop - 64 rounds
        for i in 0..64 {
            let k_constant = FieldElement::from(SHA256_K[i] as u64);
            working_vars = add_sha256_round(
                r1cs_compiler,
                and_ops,
                xor_ops,
                range_checks,
                working_vars,
                k_constant,
                w[i],
            );
        }

        // Step 4: Add initial hash values to final working variables (modulo 2^32)
        let final_hash: [usize; 8] = (0..8)
            .map(|i| {
                add_u32_addition(
                    r1cs_compiler,
                    range_checks,
                    ConstantOrR1CSWitness::Witness(initial_hash_witnesses[i]),
                    ConstantOrR1CSWitness::Witness(working_vars[i]),
                )
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Step 5: Constrain outputs to equal computed hash
        for i in 0..8 {
            r1cs_compiler.r1cs.add_constraint(
                &[(FieldElement::ONE, final_hash[i])],
                &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                &[(FieldElement::ONE, outputs[i])],
            );
        }
    }
}
