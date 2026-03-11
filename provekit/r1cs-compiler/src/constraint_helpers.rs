//! General-purpose R1CS constraint helpers.

use {
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    ark_ff::{AdditiveGroup, Field},
    provekit_common::{
        witness::{ConstantTerm, SumTerm, WitnessBuilder},
        FieldElement,
    },
};

/// Constrains `flag` to be boolean: `flag * flag = flag`.
pub(crate) fn constrain_boolean(compiler: &mut NoirToR1CSCompiler, flag: usize) {
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, flag)],
        &[(FieldElement::ONE, flag)],
        &[(FieldElement::ONE, flag)],
    );
}

/// Single-witness conditional select: `out = on_false + flag * (on_true -
/// on_false)`.
///
/// Uses a single witness + single R1CS constraint:
///   flag * (on_true - on_false) = result - on_false
pub(crate) fn select_witness(
    compiler: &mut NoirToR1CSCompiler,
    flag: usize,
    on_false: usize,
    on_true: usize,
) -> usize {
    // When both branches are the same witness, result is trivially that witness.
    if on_false == on_true {
        return on_false;
    }
    let result = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::SelectWitness {
        output: result,
        flag,
        on_false,
        on_true,
    });
    // flag * (on_true - on_false) = result - on_false
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, flag)],
        &[(FieldElement::ONE, on_true), (-FieldElement::ONE, on_false)],
        &[(FieldElement::ONE, result), (-FieldElement::ONE, on_false)],
    );
    result
}

/// Packs bit witnesses into a digit: `d = Σ bits[i] * 2^i`.
pub(crate) fn pack_bits_helper(compiler: &mut NoirToR1CSCompiler, bits: &[usize]) -> usize {
    let terms: Vec<SumTerm> = bits
        .iter()
        .enumerate()
        .map(|(i, &bit)| SumTerm(Some(FieldElement::from(1u128 << i)), bit))
        .collect();
    compiler.add_sum(terms)
}

/// Computes `a OR b` for two boolean witnesses: `1 - (1 - a)(1 - b)`.
/// Does NOT constrain a or b to be boolean — caller must ensure that.
///
/// Uses a single witness + single R1CS constraint:
///   (1 - a) * (1 - b) = 1 - result
pub(crate) fn compute_boolean_or(compiler: &mut NoirToR1CSCompiler, a: usize, b: usize) -> usize {
    let one = compiler.witness_one();
    let result = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::BooleanOr {
        output: result,
        a,
        b,
    });
    // (1 - a) * (1 - b) = 1 - result
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, one), (-FieldElement::ONE, a)],
        &[(FieldElement::ONE, one), (-FieldElement::ONE, b)],
        &[(FieldElement::ONE, one), (-FieldElement::ONE, result)],
    );
    result
}

/// Creates a constant witness with the given value, pinned by an R1CS
/// constraint so that a malicious prover cannot set it to an arbitrary value.
pub(crate) fn add_constant_witness(
    compiler: &mut NoirToR1CSCompiler,
    value: FieldElement,
) -> usize {
    let w = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::Constant(ConstantTerm(w, value)));
    // Pin: 1 * w = value * 1 (embeds the constant into the constraint matrix)
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, w)],
        &[(value, compiler.witness_one())],
    );
    w
}

/// Constrains a witness to equal a known constant value.
/// Uses the constant as an R1CS coefficient — no witness needed for the
/// expected value. Use this for identity checks where the witness must equal
/// a compile-time-known value.
pub(crate) fn constrain_to_constant(
    compiler: &mut NoirToR1CSCompiler,
    witness: usize,
    value: FieldElement,
) {
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, witness)],
        &[(value, compiler.witness_one())],
    );
}

/// Constrains two witnesses to be equal: `a - b = 0`.
pub(crate) fn constrain_equal(compiler: &mut NoirToR1CSCompiler, a: usize, b: usize) {
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, a), (-FieldElement::ONE, b)],
        &[(FieldElement::ZERO, compiler.witness_one())],
    );
}

/// Constrains a witness to be zero: `w = 0`.
pub(crate) fn constrain_zero(compiler: &mut NoirToR1CSCompiler, w: usize) {
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, w)],
        &[(FieldElement::ZERO, compiler.witness_one())],
    );
}
