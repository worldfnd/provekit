use {
    crate::noir_to_r1cs::NoirToR1CSCompiler,
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

pub(crate) fn add_sha256_compression(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    inputs_and_outputs: Vec<(
        Vec<ConstantOrR1CSWitness>,
        Vec<ConstantOrR1CSWitness>,
        Vec<usize>,
    )>,
) {
}
