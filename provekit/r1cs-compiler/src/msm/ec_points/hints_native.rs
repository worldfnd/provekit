//! Native-field hint-verified EC operations.
//!
//! These operate on single native field element witnesses (no multi-limb).
//! Each EC op allocates a hint for (lambda, x3, y3) and verifies via raw
//! R1CS constraints, eliminating expensive field inversions from the circuit.

use {
    crate::{msm::multi_limb_ops::MultiLimbParams, noir_to_r1cs::NoirToR1CSCompiler},
    ark_ff::{Field, PrimeField},
    provekit_common::{witness::WitnessBuilder, FieldElement},
};

/// Hint-verified point doubling for native field.
///
/// Allocates 3W hint (lambda, x3, y3) + 1W product.
/// Total: 4W + 4C.
pub fn point_double_verified_native(
    compiler: &mut NoirToR1CSCompiler,
    px: usize,
    py: usize,
    params: &MultiLimbParams,
) -> (usize, usize) {
    // Allocate hint witnesses
    let hint_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::EcDoubleHint {
        output_start: hint_start,
        px,
        py,
        curve_a: params.curve_a_raw,
        field_modulus_p: params.modulus_raw,
    });
    let lambda = hint_start;
    let x3 = hint_start + 1;
    let y3 = hint_start + 2;

    // x_sq = px * px (1W + 1C)
    let x_sq = compiler.add_product(px, px);

    // Constraint: lambda * (2 * py) = 3 * x_sq + a
    // A = [lambda], B = [2*py], C = [3*x_sq + a_const]
    let a_fe = FieldElement::from_bigint(ark_ff::BigInt(params.curve_a_raw)).unwrap();
    let three = FieldElement::from(3u64);
    let two = FieldElement::from(2u64);
    compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, lambda)], &[(two, py)], &[
            (three, x_sq),
            (a_fe, compiler.witness_one()),
        ]);

    // Constraint: lambda^2 = x3 + 2*px
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, lambda)],
        &[(FieldElement::ONE, lambda)],
        &[(FieldElement::ONE, x3), (two, px)],
    );

    // Constraint: lambda * (px - x3) = y3 + py
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, lambda)],
        &[(FieldElement::ONE, px), (-FieldElement::ONE, x3)],
        &[(FieldElement::ONE, y3), (FieldElement::ONE, py)],
    );

    (x3, y3)
}

/// Hint-verified point addition for native field.
///
/// Allocates 3W hint (lambda, x3, y3).
/// Total: 3W + 3C.
pub fn point_add_verified_native(
    compiler: &mut NoirToR1CSCompiler,
    x1: usize,
    y1: usize,
    x2: usize,
    y2: usize,
    params: &MultiLimbParams,
) -> (usize, usize) {
    // Allocate hint witnesses
    let hint_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::EcAddHint {
        output_start: hint_start,
        x1,
        y1,
        x2,
        y2,
        field_modulus_p: params.modulus_raw,
    });
    let lambda = hint_start;
    let x3 = hint_start + 1;
    let y3 = hint_start + 2;

    // Constraint: lambda * (x2 - x1) = y2 - y1
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, lambda)],
        &[(FieldElement::ONE, x2), (-FieldElement::ONE, x1)],
        &[(FieldElement::ONE, y2), (-FieldElement::ONE, y1)],
    );

    // Constraint: lambda^2 = x3 + x1 + x2
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, lambda)],
        &[(FieldElement::ONE, lambda)],
        &[
            (FieldElement::ONE, x3),
            (FieldElement::ONE, x1),
            (FieldElement::ONE, x2),
        ],
    );

    // Constraint: lambda * (x1 - x3) = y3 + y1
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, lambda)],
        &[(FieldElement::ONE, x1), (-FieldElement::ONE, x3)],
        &[(FieldElement::ONE, y3), (FieldElement::ONE, y1)],
    );

    (x3, y3)
}

/// On-curve check for native field: y² = x³ + a·x + b.
///
/// Total: 2W (two products) + 3C.
pub fn verify_on_curve_native(
    compiler: &mut NoirToR1CSCompiler,
    x: usize,
    y: usize,
    params: &MultiLimbParams,
) {
    let x_sq = compiler.add_product(x, x);
    let x_cu = compiler.add_product(x_sq, x);

    let a_fe = FieldElement::from_bigint(ark_ff::BigInt(params.curve_a_raw)).unwrap();
    let b_fe = FieldElement::from_bigint(ark_ff::BigInt(params.curve_b_raw)).unwrap();

    // y * y = x_cu + a*x + b
    compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, y)], &[(FieldElement::ONE, y)], &[
            (FieldElement::ONE, x_cu),
            (a_fe, x),
            (b_fe, compiler.witness_one()),
        ]);
}
