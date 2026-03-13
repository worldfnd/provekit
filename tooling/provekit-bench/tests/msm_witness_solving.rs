//! End-to-end MSM witness solving tests for non-native curves (secp256r1).
//!
//! These tests verify that the full pipeline works correctly:
//! 1. Compile MSM circuit (R1CS + witness builders)
//! 2. Set initial witness values (point coordinates as limbs + scalar)
//! 3. Solve all derived witnesses via the witness builder layer scheduler
//! 4. Check R1CS satisfaction: A·w ⊙ B·w = C·w for all constraints
//!
//! All tests use the **limbed API** (`add_msm_with_curve_limbed`) where
//! point coordinates are multi-limb witnesses, supporting arbitrary
//! secp256r1 coordinates (including those exceeding BN254 Fr).

use {
    acir::native_types::WitnessMap,
    ark_ff::{PrimeField, Zero},
    provekit_common::{
        witness::{ConstantOrR1CSWitness, LayerScheduler, WitnessBuilder},
        FieldElement, NoirElement, TranscriptSponge,
    },
    provekit_prover::{bigint_mod::ec_scalar_mul, r1cs::solve_witness_vec},
    provekit_r1cs_compiler::{
        msm::{
            add_msm_with_curve_limbed,
            cost_model::get_optimal_msm_params,
            curve::{decompose_to_limbs, secp256r1_params},
            MsmLimbedOutputs,
        },
        noir_to_r1cs::NoirToR1CSCompiler,
        range_check::add_range_checks,
    },
    std::collections::BTreeMap,
    whir::transcript::{codecs::Empty, DomainSeparator, ProverState},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a [u64; 4] to a FieldElement. Panics if value exceeds BN254 Fr.
/// Only used for scalars (128-bit halves that always fit).
fn u256_to_fe(v: &[u64; 4]) -> FieldElement {
    FieldElement::from_bigint(ark_ff::BigInt(*v))
        .unwrap_or_else(|| panic!("Value exceeds BN254 Fr: {v:?}"))
}

/// Split a 256-bit scalar into (lo_128, hi_128) as [u64; 4] values.
fn split_scalar(s: &[u64; 4]) -> ([u64; 4], [u64; 4]) {
    let lo = [s[0], s[1], 0, 0];
    let hi = [s[2], s[3], 0, 0];
    (lo, hi)
}

/// Verify R1CS satisfaction: for each constraint row, A·w * B·w == C·w.
fn check_r1cs_satisfaction(
    r1cs: &provekit_common::R1CS,
    witness: &[FieldElement],
) -> anyhow::Result<()> {
    use anyhow::ensure;

    ensure!(
        witness.len() == r1cs.num_witnesses(),
        "witness size {} != expected {}",
        witness.len(),
        r1cs.num_witnesses()
    );

    let a = r1cs.a() * witness;
    let b = r1cs.b() * witness;
    let c = r1cs.c() * witness;
    for (row, ((a_val, b_val), c_val)) in a.into_iter().zip(b).zip(c).enumerate() {
        ensure!(
            a_val * b_val == c_val,
            "Constraint {row} failed: a={a_val:?}, b={b_val:?}, a*b={:?}, c={c_val:?}",
            a_val * b_val
        );
    }
    Ok(())
}

/// Create a dummy transcript for witness solving (no challenges needed).
fn dummy_transcript() -> ProverState<TranscriptSponge> {
    let ds = DomainSeparator::protocol(&()).instance(&Empty);
    ProverState::new(&ds, TranscriptSponge::default())
}

/// Solve all witness builders given initial witness values.
fn solve_witnesses(
    builders: &[WitnessBuilder],
    num_witnesses: usize,
    initial_values: &[(usize, FieldElement)],
) -> Vec<FieldElement> {
    let layers = LayerScheduler::new(builders).build_layers();
    let mut witness: Vec<Option<FieldElement>> = vec![None; num_witnesses];

    for &(idx, val) in initial_values {
        witness[idx] = Some(val);
    }

    let acir_map = WitnessMap::<NoirElement>::new();
    let mut transcript = dummy_transcript();
    solve_witness_vec(&mut witness, layers, &acir_map, &mut transcript);

    witness
        .into_iter()
        .enumerate()
        .map(|(i, w)| w.unwrap_or_else(|| panic!("Witness {i} was not solved")))
        .collect()
}

/// Compute the (num_limbs, limb_bits) that the compiler will use for this
/// curve, so the test can decompose coordinates the same way.
fn msm_params_for_curve(
    curve: &provekit_r1cs_compiler::msm::curve::CurveParams,
    n_points: usize,
) -> (usize, u32) {
    let native_bits = FieldElement::MODULUS_BIT_SIZE;
    let curve_bits = curve.modulus_bits();
    let (limb_bits, _window_size) =
        get_optimal_msm_params(native_bits, curve_bits, n_points, 256, false);
    let num_limbs = (curve_bits as usize + limb_bits as usize - 1) / limb_bits as usize;
    (num_limbs, limb_bits)
}

/// Decompose a [u64; 4] value into field-element limbs.
fn u256_to_limb_fes(v: &[u64; 4], limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
    decompose_to_limbs(v, limb_bits, num_limbs)
}

// ---------------------------------------------------------------------------
// Single-point limbed MSM test runner
// ---------------------------------------------------------------------------

/// Compile and solve a single-point MSM circuit using the limbed API.
///
/// When `expected_inf` is true, the expected output is point at infinity
/// (all output limbs zero, out_inf = 1).
fn run_single_point_msm_test_limbed(
    px: &[u64; 4],
    py: &[u64; 4],
    inf: bool,
    scalar: &[u64; 4],
    expected_x: &[u64; 4],
    expected_y: &[u64; 4],
    expected_inf: bool,
) {
    let curve = secp256r1_params();
    let (num_limbs, limb_bits) = msm_params_for_curve(&curve, 1);
    let (s_lo, s_hi) = split_scalar(scalar);
    let stride = 2 * num_limbs + 1;

    let px_fes = u256_to_limb_fes(px, limb_bits, num_limbs);
    let py_fes = u256_to_limb_fes(py, limb_bits, num_limbs);
    let ex_fes = u256_to_limb_fes(expected_x, limb_bits, num_limbs);
    let ey_fes = u256_to_limb_fes(expected_y, limb_bits, num_limbs);

    let mut compiler = NoirToR1CSCompiler::new();
    let mut range_checks: BTreeMap<u32, Vec<usize>> = BTreeMap::new();

    let base = compiler.num_witnesses();
    let total_input_wits = stride + 2 + stride;
    compiler.r1cs.add_witnesses(total_input_wits);

    let points: Vec<ConstantOrR1CSWitness> = (0..stride)
        .map(|j| ConstantOrR1CSWitness::Witness(base + j))
        .collect();
    let slo_w = base + stride;
    let shi_w = base + stride + 1;
    let scalars = vec![
        ConstantOrR1CSWitness::Witness(slo_w),
        ConstantOrR1CSWitness::Witness(shi_w),
    ];

    let out_base = base + stride + 2;
    let out_x_limbs: Vec<usize> = (0..num_limbs).map(|j| out_base + j).collect();
    let out_y_limbs: Vec<usize> = (0..num_limbs).map(|j| out_base + num_limbs + j).collect();
    let out_inf = out_base + 2 * num_limbs;

    let outputs = MsmLimbedOutputs {
        out_x_limbs: out_x_limbs.clone(),
        out_y_limbs: out_y_limbs.clone(),
        out_inf,
    };
    let msm_ops = vec![(points, scalars, outputs)];
    add_msm_with_curve_limbed(&mut compiler, msm_ops, &mut range_checks, &curve, num_limbs);
    add_range_checks(&mut compiler, range_checks);

    let num_witnesses = compiler.num_witnesses();

    // Set initial witness values
    let mut initial_values = vec![(0, FieldElement::from(1u64))];
    for (j, fe) in px_fes.iter().enumerate() {
        initial_values.push((base + j, *fe));
    }
    for (j, fe) in py_fes.iter().enumerate() {
        initial_values.push((base + num_limbs + j, *fe));
    }
    let inf_fe = if inf {
        FieldElement::from(1u64)
    } else {
        FieldElement::zero()
    };
    initial_values.push((base + 2 * num_limbs, inf_fe));
    initial_values.push((slo_w, u256_to_fe(&s_lo)));
    initial_values.push((shi_w, u256_to_fe(&s_hi)));
    for (j, fe) in ex_fes.iter().enumerate() {
        initial_values.push((out_x_limbs[j], *fe));
    }
    for (j, fe) in ey_fes.iter().enumerate() {
        initial_values.push((out_y_limbs[j], *fe));
    }
    let out_inf_fe = if expected_inf {
        FieldElement::from(1u64)
    } else {
        FieldElement::zero()
    };
    initial_values.push((out_inf, out_inf_fe));

    let witness = solve_witnesses(&compiler.witness_builders, num_witnesses, &initial_values);

    check_r1cs_satisfaction(&compiler.r1cs, &witness)
        .expect("R1CS satisfaction check failed (limbed)");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Single-point MSM using the secp256r1 generator directly.
/// The generator's x-coordinate exceeds BN254 Fr.
#[test]
fn test_single_point_generator() {
    let curve = secp256r1_params();
    let gx = curve.generator.0;
    let gy = curve.generator.1;
    let scalar: [u64; 4] = [7, 0, 0, 0];
    let (ex, ey) = ec_scalar_mul(&gx, &gy, &scalar, &curve.curve_a, &curve.field_modulus_p);

    run_single_point_msm_test_limbed(&gx, &gy, false, &scalar, &ex, &ey, false);
}

/// Scalar = 1: result should equal the input point.
#[test]
fn test_scalar_one() {
    let curve = secp256r1_params();
    let gx = curve.generator.0;
    let gy = curve.generator.1;
    let scalar: [u64; 4] = [1, 0, 0, 0];

    // 1·G = G
    run_single_point_msm_test_limbed(&gx, &gy, false, &scalar, &gx, &gy, false);
}

/// Large scalar spanning both lo and hi halves of the 256-bit representation.
#[test]
fn test_large_scalar() {
    let curve = secp256r1_params();
    let gx = curve.generator.0;
    let gy = curve.generator.1;
    let scalar: [u64; 4] = [0xcafebabe, 0x12345678, 0x42, 0];
    let (ex, ey) = ec_scalar_mul(&gx, &gy, &scalar, &curve.curve_a, &curve.field_modulus_p);

    run_single_point_msm_test_limbed(&gx, &gy, false, &scalar, &ex, &ey, false);
}

/// Zero scalar: result should be point at infinity.
#[test]
fn test_zero_scalar() {
    let curve = secp256r1_params();
    let gx = curve.generator.0;
    let gy = curve.generator.1;
    let zero_scalar: [u64; 4] = [0, 0, 0, 0];
    let zero_point: [u64; 4] = [0, 0, 0, 0];

    run_single_point_msm_test_limbed(
        &gx,
        &gy,
        false,
        &zero_scalar,
        &zero_point,
        &zero_point,
        true,
    );
}

/// Point at infinity as input: result should be point at infinity regardless
/// of scalar.
#[test]
fn test_point_at_infinity_input() {
    let curve = secp256r1_params();
    // Use generator coords as placeholder (they're ignored due to inf=1 select)
    let gx = curve.generator.0;
    let gy = curve.generator.1;
    let scalar: [u64; 4] = [42, 0, 0, 0];
    let zero_point: [u64; 4] = [0, 0, 0, 0];

    run_single_point_msm_test_limbed(&gx, &gy, true, &scalar, &zero_point, &zero_point, true);
}

/// Non-trivial point (2·G) with a moderate scalar, verifying the full
/// wNAF + FakeGLV pipeline.
#[test]
fn test_arbitrary_point_and_scalar() {
    let curve = secp256r1_params();
    let gx = curve.generator.0;
    let gy = curve.generator.1;
    let a = &curve.curve_a;
    let p = &curve.field_modulus_p;

    // P = 2·G
    let (px, py) = ec_scalar_mul(&gx, &gy, &[2, 0, 0, 0], a, p);
    let scalar: [u64; 4] = [17, 0, 0, 0];
    // Expected: 17·(2G) = 34G
    let (ex, ey) = ec_scalar_mul(&gx, &gy, &[34, 0, 0, 0], a, p);

    run_single_point_msm_test_limbed(&px, &py, false, &scalar, &ex, &ey, false);
}

/// Two-point MSM: s1·P1 + s2·P2 with arbitrary coordinates.
#[test]
fn test_two_point_msm() {
    let curve = secp256r1_params();
    let gx = curve.generator.0;
    let gy = curve.generator.1;
    let a = &curve.curve_a;
    let p = &curve.field_modulus_p;
    let (num_limbs, limb_bits) = msm_params_for_curve(&curve, 2);
    let stride = 2 * num_limbs + 1;

    // P1 = 3·G, P2 = 5·G
    let (p1x, p1y) = ec_scalar_mul(&gx, &gy, &[3, 0, 0, 0], a, p);
    let (p2x, p2y) = ec_scalar_mul(&gx, &gy, &[5, 0, 0, 0], a, p);
    let s1: [u64; 4] = [2, 0, 0, 0];
    let s2: [u64; 4] = [3, 0, 0, 0];
    // Expected: 2·(3G) + 3·(5G) = 6G + 15G = 21G
    let (ex, ey) = ec_scalar_mul(&gx, &gy, &[21, 0, 0, 0], a, p);

    let (s1_lo, s1_hi) = split_scalar(&s1);
    let (s2_lo, s2_hi) = split_scalar(&s2);

    let p1x_fes = u256_to_limb_fes(&p1x, limb_bits, num_limbs);
    let p1y_fes = u256_to_limb_fes(&p1y, limb_bits, num_limbs);
    let p2x_fes = u256_to_limb_fes(&p2x, limb_bits, num_limbs);
    let p2y_fes = u256_to_limb_fes(&p2y, limb_bits, num_limbs);
    let ex_fes = u256_to_limb_fes(&ex, limb_bits, num_limbs);
    let ey_fes = u256_to_limb_fes(&ey, limb_bits, num_limbs);

    let mut compiler = NoirToR1CSCompiler::new();
    let mut range_checks: BTreeMap<u32, Vec<usize>> = BTreeMap::new();

    let base = compiler.num_witnesses();
    let total = 2 * stride + 4 + stride;
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
    let out_x_limbs: Vec<usize> = (0..num_limbs).map(|j| out_base + j).collect();
    let out_y_limbs: Vec<usize> = (0..num_limbs).map(|j| out_base + num_limbs + j).collect();
    let out_inf = out_base + 2 * num_limbs;

    let outputs = MsmLimbedOutputs {
        out_x_limbs: out_x_limbs.clone(),
        out_y_limbs: out_y_limbs.clone(),
        out_inf,
    };
    let msm_ops = vec![(points, scalars, outputs)];
    add_msm_with_curve_limbed(&mut compiler, msm_ops, &mut range_checks, &curve, num_limbs);
    add_range_checks(&mut compiler, range_checks);

    let num_witnesses = compiler.num_witnesses();

    let mut initial_values = vec![(0, FieldElement::from(1u64))];
    for (j, fe) in p1x_fes.iter().enumerate() {
        initial_values.push((base + j, *fe));
    }
    for (j, fe) in p1y_fes.iter().enumerate() {
        initial_values.push((base + num_limbs + j, *fe));
    }
    initial_values.push((base + 2 * num_limbs, FieldElement::zero()));
    let p2_base = base + stride;
    for (j, fe) in p2x_fes.iter().enumerate() {
        initial_values.push((p2_base + j, *fe));
    }
    for (j, fe) in p2y_fes.iter().enumerate() {
        initial_values.push((p2_base + num_limbs + j, *fe));
    }
    initial_values.push((p2_base + 2 * num_limbs, FieldElement::zero()));
    initial_values.push((scalar_base, u256_to_fe(&s1_lo)));
    initial_values.push((scalar_base + 1, u256_to_fe(&s1_hi)));
    initial_values.push((scalar_base + 2, u256_to_fe(&s2_lo)));
    initial_values.push((scalar_base + 3, u256_to_fe(&s2_hi)));
    for (j, fe) in ex_fes.iter().enumerate() {
        initial_values.push((out_x_limbs[j], *fe));
    }
    for (j, fe) in ey_fes.iter().enumerate() {
        initial_values.push((out_y_limbs[j], *fe));
    }
    initial_values.push((out_inf, FieldElement::zero()));

    let witness = solve_witnesses(&compiler.witness_builders, num_witnesses, &initial_values);

    check_r1cs_satisfaction(&compiler.r1cs, &witness)
        .expect("R1CS satisfaction check failed for two-point MSM");
}

/// Two-point MSM where one scalar is zero — only the non-zero point
/// should contribute.
#[test]
fn test_two_point_one_zero_scalar() {
    let curve = secp256r1_params();
    let gx = curve.generator.0;
    let gy = curve.generator.1;
    let a = &curve.curve_a;
    let p = &curve.field_modulus_p;
    let (num_limbs, limb_bits) = msm_params_for_curve(&curve, 2);
    let stride = 2 * num_limbs + 1;

    // P1 = G (scalar=5), P2 = 2G (scalar=0)
    let (p2x, p2y) = ec_scalar_mul(&gx, &gy, &[2, 0, 0, 0], a, p);
    let s1: [u64; 4] = [5, 0, 0, 0];
    let s2: [u64; 4] = [0, 0, 0, 0];
    // Expected: 5·G + 0·(2G) = 5G
    let (ex, ey) = ec_scalar_mul(&gx, &gy, &[5, 0, 0, 0], a, p);

    let (s1_lo, s1_hi) = split_scalar(&s1);
    let (s2_lo, s2_hi) = split_scalar(&s2);

    let p1x_fes = u256_to_limb_fes(&gx, limb_bits, num_limbs);
    let p1y_fes = u256_to_limb_fes(&gy, limb_bits, num_limbs);
    let p2x_fes = u256_to_limb_fes(&p2x, limb_bits, num_limbs);
    let p2y_fes = u256_to_limb_fes(&p2y, limb_bits, num_limbs);
    let ex_fes = u256_to_limb_fes(&ex, limb_bits, num_limbs);
    let ey_fes = u256_to_limb_fes(&ey, limb_bits, num_limbs);

    let mut compiler = NoirToR1CSCompiler::new();
    let mut range_checks: BTreeMap<u32, Vec<usize>> = BTreeMap::new();

    let base = compiler.num_witnesses();
    let total = 2 * stride + 4 + stride;
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
    let out_x_limbs: Vec<usize> = (0..num_limbs).map(|j| out_base + j).collect();
    let out_y_limbs: Vec<usize> = (0..num_limbs).map(|j| out_base + num_limbs + j).collect();
    let out_inf = out_base + 2 * num_limbs;

    let outputs = MsmLimbedOutputs {
        out_x_limbs: out_x_limbs.clone(),
        out_y_limbs: out_y_limbs.clone(),
        out_inf,
    };
    let msm_ops = vec![(points, scalars, outputs)];
    add_msm_with_curve_limbed(&mut compiler, msm_ops, &mut range_checks, &curve, num_limbs);
    add_range_checks(&mut compiler, range_checks);

    let num_witnesses = compiler.num_witnesses();

    let mut initial_values = vec![(0, FieldElement::from(1u64))];
    // P1 limbs (generator)
    for (j, fe) in p1x_fes.iter().enumerate() {
        initial_values.push((base + j, *fe));
    }
    for (j, fe) in p1y_fes.iter().enumerate() {
        initial_values.push((base + num_limbs + j, *fe));
    }
    initial_values.push((base + 2 * num_limbs, FieldElement::zero()));
    // P2 limbs
    let p2_base = base + stride;
    for (j, fe) in p2x_fes.iter().enumerate() {
        initial_values.push((p2_base + j, *fe));
    }
    for (j, fe) in p2y_fes.iter().enumerate() {
        initial_values.push((p2_base + num_limbs + j, *fe));
    }
    initial_values.push((p2_base + 2 * num_limbs, FieldElement::zero()));
    // Scalars
    initial_values.push((scalar_base, u256_to_fe(&s1_lo)));
    initial_values.push((scalar_base + 1, u256_to_fe(&s1_hi)));
    initial_values.push((scalar_base + 2, u256_to_fe(&s2_lo)));
    initial_values.push((scalar_base + 3, u256_to_fe(&s2_hi)));
    // Expected output limbs
    for (j, fe) in ex_fes.iter().enumerate() {
        initial_values.push((out_x_limbs[j], *fe));
    }
    for (j, fe) in ey_fes.iter().enumerate() {
        initial_values.push((out_y_limbs[j], *fe));
    }
    initial_values.push((out_inf, FieldElement::zero()));

    let witness = solve_witnesses(&compiler.witness_builders, num_witnesses, &initial_values);

    check_r1cs_satisfaction(&compiler.r1cs, &witness)
        .expect("R1CS satisfaction check failed for two-point MSM with one zero scalar");
}
