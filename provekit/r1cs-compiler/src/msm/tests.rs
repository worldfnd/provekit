use {
    super::*, crate::noir_to_r1cs::NoirToR1CSCompiler,
    provekit_common::witness::ConstantOrR1CSWitness, std::collections::BTreeMap,
};

/// Helper: compute num_limbs for a curve given the cost model.
fn num_limbs_for(curve: &impl curve::Curve) -> usize {
    let native_bits = provekit_common::FieldElement::MODULUS_BIT_SIZE;
    let curve_bits = curve.modulus_bits();
    let is_native = curve.is_native_field();
    let scalar_bits = curve.curve_order_bits() as usize;
    let (_limb_bits, _window_size, num_limbs) =
        cost_model::get_optimal_msm_params(native_bits, curve_bits, 1, scalar_bits, is_native);
    num_limbs
}

/// Verify that the SECP256R1 single-point MSM path generates constraints
/// without panicking. This exercises multi-limb arithmetic, range checks,
/// and FakeGLV verification through the unified pipeline.
#[test]
fn test_secp256r1_single_point_msm_generates_constraints() {
    let mut compiler = NoirToR1CSCompiler::new();
    let curve = curve::Secp256r1;
    let mut range_checks: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    let num_limbs = num_limbs_for(&curve);
    let stride = 2 * num_limbs + 1;

    // Allocate witness slots: point limbs + inf, s_lo, s_hi, out limbs + out_inf
    let base = compiler.num_witnesses();
    let total = stride + 2 + stride; // point + scalars + output
    compiler.r1cs.add_witnesses(total);

    let points: Vec<ConstantOrR1CSWitness> = (0..stride)
        .map(|j| ConstantOrR1CSWitness::Witness(base + j))
        .collect();
    let scalars = vec![
        ConstantOrR1CSWitness::Witness(base + stride),
        ConstantOrR1CSWitness::Witness(base + stride + 1),
    ];
    let out_base = base + stride + 2;
    let outputs = MsmLimbedOutputs {
        out_x_limbs: (0..num_limbs).map(|j| out_base + j).collect(),
        out_y_limbs: (0..num_limbs).map(|j| out_base + num_limbs + j).collect(),
        out_inf:     out_base + 2 * num_limbs,
    };
    let msm_ops = vec![(points, scalars, outputs)];

    add_msm_with_curve(&mut compiler, msm_ops, &mut range_checks, &curve);

    let n_constraints = compiler.r1cs.num_constraints();
    let n_witnesses = compiler.num_witnesses();

    assert!(
        n_constraints > 100,
        "expected substantial constraints for non-native MSM, got {n_constraints}"
    );
    assert!(
        n_witnesses > 100,
        "expected substantial witnesses for non-native MSM, got {n_witnesses}"
    );
    assert!(
        !range_checks.is_empty(),
        "non-native MSM should produce range checks"
    );
}

/// Verify that the multi-point MSM path (2 points, SECP256R1) generates
/// constraints. Exercises multi-point accumulation and offset subtraction.
#[test]
fn test_secp256r1_multi_point_msm_generates_constraints() {
    let mut compiler = NoirToR1CSCompiler::new();
    let curve = curve::Secp256r1;
    let mut range_checks: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    let num_limbs = num_limbs_for(&curve);
    let stride = 2 * num_limbs + 1;

    // 2 points + scalars + outputs
    let base = compiler.num_witnesses();
    let total = 2 * stride + 4 + stride; // 2 points + 4 scalar halves + output
    compiler.r1cs.add_witnesses(total);

    let points: Vec<ConstantOrR1CSWitness> = (0..2 * stride)
        .map(|j| ConstantOrR1CSWitness::Witness(base + j))
        .collect();
    let scalar_base = base + 2 * stride;
    let scalars = vec![
        ConstantOrR1CSWitness::Witness(scalar_base),
        ConstantOrR1CSWitness::Witness(scalar_base + 1),
        ConstantOrR1CSWitness::Witness(scalar_base + 2),
        ConstantOrR1CSWitness::Witness(scalar_base + 3),
    ];
    let out_base = scalar_base + 4;
    let outputs = MsmLimbedOutputs {
        out_x_limbs: (0..num_limbs).map(|j| out_base + j).collect(),
        out_y_limbs: (0..num_limbs).map(|j| out_base + num_limbs + j).collect(),
        out_inf:     out_base + 2 * num_limbs,
    };
    let msm_ops = vec![(points, scalars, outputs)];

    add_msm_with_curve(&mut compiler, msm_ops, &mut range_checks, &curve);

    let n_constraints = compiler.r1cs.num_constraints();
    let n_witnesses = compiler.num_witnesses();

    // Multi-point should produce more constraints than single-point
    assert!(
        n_constraints > 200,
        "expected substantial constraints for 2-point non-native MSM, got {n_constraints}"
    );
    assert!(
        n_witnesses > 200,
        "expected substantial witnesses for 2-point non-native MSM, got {n_witnesses}"
    );
}
