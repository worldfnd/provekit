use {
    super::*, crate::noir_to_r1cs::NoirToR1CSCompiler,
    provekit_common::witness::ConstantOrR1CSWitness, std::collections::BTreeMap,
};

/// Verify that the non-native (SECP256R1) single-point MSM path generates
/// constraints without panicking. This does multi-limb arithmetic,
/// range checks, and FakeGLV verification — the entire non-native code path
/// that has no Noir e2e coverage for now : )
#[test]
fn test_secp256r1_single_point_msm_generates_constraints() {
    let mut compiler = NoirToR1CSCompiler::new();
    let curve = curve::secp256r1_params();
    let mut range_checks: BTreeMap<u32, Vec<usize>> = BTreeMap::new();

    // Allocate witness slots for: px, py, inf, s_lo, s_hi, out_x, out_y, out_inf
    // (witness 0 is the constant-one witness)
    let base = compiler.num_witnesses();
    compiler.r1cs.add_witnesses(8);
    let px = base;
    let py = base + 1;
    let inf = base + 2;
    let s_lo = base + 3;
    let s_hi = base + 4;
    let out_x = base + 5;
    let out_y = base + 6;
    let out_inf = base + 7;

    let points = vec![
        ConstantOrR1CSWitness::Witness(px),
        ConstantOrR1CSWitness::Witness(py),
        ConstantOrR1CSWitness::Witness(inf),
    ];
    let scalars = vec![
        ConstantOrR1CSWitness::Witness(s_lo),
        ConstantOrR1CSWitness::Witness(s_hi),
    ];
    let msm_ops = vec![(points, scalars, (out_x, out_y, out_inf))];

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

/// Verify that the non-native multi-point MSM path (2 points, SECP256R1)
/// generates constraints. does the multi-point accumulation and offset
/// subtraction logic for the non-native path.
#[test]
fn test_secp256r1_multi_point_msm_generates_constraints() {
    let mut compiler = NoirToR1CSCompiler::new();
    let curve = curve::secp256r1_params();
    let mut range_checks: BTreeMap<u32, Vec<usize>> = BTreeMap::new();

    // 2 points: px1, py1, inf1, px2, py2, inf2, s1_lo, s1_hi, s2_lo, s2_hi,
    //           out_x, out_y, out_inf
    let base = compiler.num_witnesses();
    compiler.r1cs.add_witnesses(13);

    let points = vec![
        ConstantOrR1CSWitness::Witness(base),     // px1
        ConstantOrR1CSWitness::Witness(base + 1), // py1
        ConstantOrR1CSWitness::Witness(base + 2), // inf1
        ConstantOrR1CSWitness::Witness(base + 3), // px2
        ConstantOrR1CSWitness::Witness(base + 4), // py2
        ConstantOrR1CSWitness::Witness(base + 5), // inf2
    ];
    let scalars = vec![
        ConstantOrR1CSWitness::Witness(base + 6), // s1_lo
        ConstantOrR1CSWitness::Witness(base + 7), // s1_hi
        ConstantOrR1CSWitness::Witness(base + 8), // s2_lo
        ConstantOrR1CSWitness::Witness(base + 9), // s2_hi
    ];
    let out_x = base + 10;
    let out_y = base + 11;
    let out_inf = base + 12;

    let msm_ops = vec![(points, scalars, (out_x, out_y, out_inf))];

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
