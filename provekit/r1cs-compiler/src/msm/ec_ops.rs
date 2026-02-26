use {
    crate::{msm::curve::CurveParams, noir_to_r1cs::NoirToR1CSCompiler},
    ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField},
    provekit_common::{
        witness::{SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::collections::BTreeMap,
};

/// Reduce the value to given modulus
pub fn reduce_mod(
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

/// a * b mod m
pub fn compute_field_mul(
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
    reduce_mod(r1cs_compiler, a_mul_b, modulus, range_checks)
}

/// (a - b) mod m
pub fn compute_field_sub(
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
    reduce_mod(r1cs_compiler, a_sub_b, modulus, range_checks)
}

/// a^(-1) mod m
///
/// CRITICAL: secp256r1's field_modulus_p (~2^256) > BN254 scalar field
/// (~2^254). Coordinates and the modulus do not fit in a single
/// FieldElement. Either use multi-limb representation or target a
/// curve that fits (e.g. Grumpkin, BabyJubJub).
pub fn compute_field_inv(
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
    // computing a * a_inv
    let product_raw = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Product(product_raw, a, a_inv));
    // constraint: a * a_inv = product_raw
    r1cs_compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, a)], &[(FieldElement::ONE, a_inv)], &[
            (FieldElement::ONE, product_raw),
        ]);
    // reducing a * a_inv mod m — should give 1 if a_inv is correct
    let reduced = reduce_mod(r1cs_compiler, product_raw, modulus, range_checks);

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

/// Point doubling on y^2 = x^3 + ax + b (mod p) using affine lambda formula.
///
/// Given P = (x1, y1), computes 2P = (x3, y3):
///   lambda = (3 * x1^2 + a) / (2 * y1)   (mod p)
///   x3     = lambda^2 - 2 * x1            (mod p)
///   y3     = lambda * (x1 - x3) - y1      (mod p)
///
/// Edge case — y1 = 0 (point of order 2):
///   When y1 = 0, the denominator 2*y1 = 0 and the inverse does not exist.
///   The result should be the point at infinity (identity element).
///   This function does NOT handle that case — the constraint system will
///   be unsatisfiable if y1 = 0 (compute_field_inv will fail to verify
///   0 * inv = 1 mod p). The caller must check y1 = 0 using
///   compute_is_zero and conditionally select the point-at-infinity
///   result before calling this function.
pub fn point_double(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    x1: usize,
    y1: usize,
    curve_params: &CurveParams,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> (usize, usize) {
    let p = curve_params.field_modulus_p;

    // Computing numerator = 3 * x1^2 + a  (mod p)
    // -----------------------------------------------------------
    // computing x1^2 mod p
    let x1_sq = compute_field_mul(r1cs_compiler, x1, x1, p, range_checks);
    // computing 3 * x1_sq + a
    let a_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Constant(
        provekit_common::witness::ConstantTerm(a_witness, curve_params.curve_a),
    ));
    let num_raw = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(num_raw, vec![
        SumTerm(Some(FieldElement::from(3u64)), x1_sq),
        SumTerm(Some(FieldElement::ONE), a_witness),
    ]));
    // constraint: 1 * (3 * x1_sq + a) = num_raw
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
        &[
            (FieldElement::from(3u64), x1_sq),
            (FieldElement::ONE, a_witness),
        ],
        &[(FieldElement::ONE, num_raw)],
    );
    let numerator = reduce_mod(r1cs_compiler, num_raw, p, range_checks);

    // Computing denominator = 2 * y1  (mod p)
    // -----------------------------------------------------------
    // computing 2 * y1
    let denom_raw = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(denom_raw, vec![SumTerm(
        Some(FieldElement::from(2u64)),
        y1,
    )]));
    // constraint: 1 * (2 * y1) = denom_raw
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
        &[(FieldElement::from(2u64), y1)],
        &[(FieldElement::ONE, denom_raw)],
    );
    let denominator = reduce_mod(r1cs_compiler, denom_raw, p, range_checks);

    // Computing lambda = numerator * denominator^(-1)  (mod p)
    // -----------------------------------------------------------
    // computing denominator^(-1) mod p
    let denom_inv = compute_field_inv(r1cs_compiler, denominator, p, range_checks);
    // computing lambda = numerator * denom_inv mod p
    let lambda = compute_field_mul(r1cs_compiler, numerator, denom_inv, p, range_checks);

    // Computing x3 = lambda^2 - 2 * x1  (mod p)
    // -----------------------------------------------------------
    // computing lambda^2 mod p
    let lambda_sq = compute_field_mul(r1cs_compiler, lambda, lambda, p, range_checks);
    // computing lambda^2 - 2 * x1
    let x3_raw = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(x3_raw, vec![
        SumTerm(Some(FieldElement::ONE), lambda_sq),
        SumTerm(Some(-FieldElement::from(2u64)), x1),
    ]));
    // constraint: 1 * (lambda^2 - 2 * x1) = x3_raw
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
        &[
            (FieldElement::ONE, lambda_sq),
            (-FieldElement::from(2u64), x1),
        ],
        &[(FieldElement::ONE, x3_raw)],
    );
    let x3 = reduce_mod(r1cs_compiler, x3_raw, p, range_checks);

    // Computing y3 = lambda * (x1 - x3) - y1  (mod p)
    // -----------------------------------------------------------
    // computing x1 - x3 mod p
    let x1_minus_x3 = compute_field_sub(r1cs_compiler, x1, x3, p, range_checks);
    // computing lambda * (x1 - x3) mod p
    let lambda_dx = compute_field_mul(r1cs_compiler, lambda, x1_minus_x3, p, range_checks);
    // computing lambda * (x1 - x3) - y1 mod p
    let y3 = compute_field_sub(r1cs_compiler, lambda_dx, y1, p, range_checks);

    (x3, y3)
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
