use {
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField},
    provekit_common::{
        witness::{SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::collections::BTreeMap,
};

/// Reduce the value to given modulus
pub fn reduce_mod_p(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    value: usize,
    modulus: FieldElement,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> usize {
    // Reduce mod algorithm :
    // v = k * m + result, where 0 <= result < m
    // k = floor(v / m)    (integer division)
    // result = v - k * m

    // Computing k = floor(v / m)
    // -----------------------------------------------------------
    // computing m (constant witness for use in constraints)
    let m = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Constant(
        provekit_common::witness::ConstantTerm(m, modulus),
    ));
    // computing k via integer division
    let k = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::IntegerQuotient(k, value, modulus));

    // Computing result = v - k * m
    // -----------------------------------------------------------
    // computing k * m
    let k_mul_m = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Product(k_mul_m, k, m));
    // constraint: k * m = k_mul_m
    r1cs_compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, k)], &[(FieldElement::ONE, m)], &[(
            FieldElement::ONE,
            k_mul_m,
        )]);
    // computing result = v - k * m
    let result = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(result, vec![
        SumTerm(Some(FieldElement::ONE), value),
        SumTerm(Some(-FieldElement::ONE), k_mul_m),
    ]));
    // constraint: 1 * (k_mul_m + result) = value
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
        &[(FieldElement::ONE, k_mul_m), (FieldElement::ONE, result)],
        &[(FieldElement::ONE, value)],
    );
    // range check to prove 0 <= result < m
    let modulus_bits = modulus.into_bigint().num_bits();
    range_checks
        .entry(modulus_bits)
        .or_insert_with(Vec::new)
        .push(result);

    result
}

/// a + b mod p
pub fn add_mod_p(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    a: usize,
    b: usize,
    modulus: FieldElement,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> usize {
    let a_add_b = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(a_add_b, vec![
        SumTerm(Some(FieldElement::ONE), a),
        SumTerm(Some(FieldElement::ONE), b),
    ]));
    // constraint: a + b = a_add_b
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, a), (FieldElement::ONE, b)],
        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
        &[(FieldElement::ONE, a_add_b)],
    );
    reduce_mod_p(r1cs_compiler, a_add_b, modulus, range_checks)
}

/// a * b mod p
pub fn mul_mod_p(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    a: usize,
    b: usize,
    modulus: FieldElement,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> usize {
    let a_mul_b = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Product(a_mul_b, a, b));
    // constraint: a * b = a_mul_b
    r1cs_compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, a)], &[(FieldElement::ONE, b)], &[(
            FieldElement::ONE,
            a_mul_b,
        )]);
    reduce_mod_p(r1cs_compiler, a_mul_b, modulus, range_checks)
}

/// (a - b) mod p
pub fn sub_mod_p(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    a: usize,
    b: usize,
    modulus: FieldElement,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> usize {
    let a_sub_b = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(a_sub_b, vec![
        SumTerm(Some(FieldElement::ONE), a),
        SumTerm(Some(-FieldElement::ONE), b),
    ]));
    // constraint: 1 * (a - b) = a_sub_b
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
        &[(FieldElement::ONE, a), (-FieldElement::ONE, b)],
        &[(FieldElement::ONE, a_sub_b)],
    );
    reduce_mod_p(r1cs_compiler, a_sub_b, modulus, range_checks)
}

/// a^(-1) mod p
pub fn inv_mod_p(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    a: usize,
    modulus: FieldElement,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> usize {
    // Computing a^(-1) mod m
    // -----------------------------------------------------------
    // computing a_inv (the F_m inverse of a) via Fermat's little theorem
    let a_inv = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::ModularInverse(a_inv, a, modulus));

    // Verifying a * a_inv mod m = 1
    // -----------------------------------------------------------
    // computing a * a_inv mod m
    let reduced = mul_mod_p(r1cs_compiler, a, a_inv, modulus, range_checks);

    // constraint: reduced = 1
    // (reduced - 1) * 1 = 0
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
        &[
            (FieldElement::ONE, reduced),
            (-FieldElement::ONE, r1cs_compiler.witness_one()),
        ],
        &[(FieldElement::ZERO, r1cs_compiler.witness_one())],
    );

    // range check: a_inv in [0, 2^bits(m))
    let mod_bits = modulus.into_bigint().num_bits();
    range_checks
        .entry(mod_bits)
        .or_insert_with(Vec::new)
        .push(a_inv);

    a_inv
}

/// checks if value is zero or not
pub fn compute_is_zero(r1cs_compiler: &mut NoirToR1CSCompiler, value: usize) -> usize {
    // calculating v^(-1)
    let value_inv = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Inverse(value_inv, value));
    // calculating v * v^(-1)
    let value_mul_value_inv = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Product(
        value_mul_value_inv,
        value,
        value_inv,
    ));
    // calculate is_zero = 1 - (v * v^(-1))
    let is_zero = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        is_zero,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::ONE), r1cs_compiler.witness_one()),
            provekit_common::witness::SumTerm(Some(-FieldElement::ONE), value_mul_value_inv),
        ],
    ));
    // constraint: v × v^(-1) = 1 - is_zero
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, value)],
        &[(FieldElement::ONE, value_inv)],
        &[
            (FieldElement::ONE, r1cs_compiler.witness_one()),
            (-FieldElement::ONE, is_zero),
        ],
    );
    // constraint: v × is_zero = 0
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, value)],
        &[(FieldElement::ONE, is_zero)],
        &[(FieldElement::ZERO, r1cs_compiler.witness_one())],
    );
    is_zero
}
