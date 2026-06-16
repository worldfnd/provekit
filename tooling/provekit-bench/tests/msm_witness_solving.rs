//! End-to-end MSM witness solving tests for non-native curves (secp256r1).
//!
//! These tests verify that the full pipeline works correctly:
//! 1. Compile MSM circuit (R1CS + witness builders)
//! 2. Set initial witness values (point coordinates as limbs + scalar)
//! 3. Solve all derived witnesses via the witness builder layer scheduler
//! 4. Check R1CS satisfaction: A·w ⊙ B·w = C·w for all constraints
//!
//! All tests use the **limbed API** (`add_msm_with_curve`) where
//! point coordinates are multi-limb witnesses, supporting arbitrary
//! secp256r1 coordinates (including those exceeding BN254 Fr).

use {
    acir::native_types::WitnessMap,
    ark_ff::{PrimeField, Zero},
    provekit_common::{
        witness::{ConstantOrR1CSWitness, LayerScheduler, WitnessBuilder},
        FieldElement, NoirElement, TranscriptSponge,
    },
    provekit_noir::{ec_scalar_mul, solve_witness_vec},
    provekit_r1cs_compiler::{
        msm::{
            add_msm_with_curve,
            cost_model::get_optimal_msm_params,
            curve::{decompose_to_limbs, Curve, Secp256r1},
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
    // The default sponge is field-native (Skyscraper), so the bn254 backend
    // must be registered before constructing it.
    provekit_field_bn254::register();
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
    solve_witness_vec(&mut witness, layers, &acir_map, &mut transcript)
        .expect("witness solving failed");

    witness
        .into_iter()
        .enumerate()
        .map(|(i, w)| w.unwrap_or_else(|| panic!("Witness {i} was not solved")))
        .collect()
}

/// Compute the (num_limbs, limb_bits) that the compiler will use for this
/// curve, so the test can decompose coordinates the same way.
fn msm_params_for_curve(curve: &impl Curve, n_points: usize) -> (usize, u32) {
    let native_bits = FieldElement::MODULUS_BIT_SIZE;
    let curve_bits = curve.modulus_bits();
    let is_native = curve.is_native_field();
    let scalar_bits = curve.curve_order_bits() as usize;
    let (limb_bits, _window_size, num_limbs) =
        get_optimal_msm_params(native_bits, curve_bits, n_points, scalar_bits, is_native);
    (num_limbs, limb_bits)
}

/// Decompose a [u64; 4] value into field-element limbs.
fn u256_to_limb_fes(v: &[u64; 4], limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
    decompose_to_limbs(v, limb_bits, num_limbs)
}

/// Increment a 256-bit little-endian integer by one.
fn increment_u256(v: &[u64; 4]) -> [u64; 4] {
    let mut out = *v;
    for limb in &mut out {
        let (next, carry) = limb.overflowing_add(1);
        *limb = next;
        if !carry {
            break;
        }
    }
    out
}

/// Return a field element guaranteed to differ from `value`.
fn corrupt_field_element(value: FieldElement) -> FieldElement {
    value + FieldElement::from(1u64)
}

/// Flip a boolean field element between 0 and 1.
fn flip_boolean_field_element(value: FieldElement) -> FieldElement {
    if value == FieldElement::zero() {
        FieldElement::from(1u64)
    } else if value == FieldElement::from(1u64) {
        FieldElement::zero()
    } else {
        panic!("expected boolean field element");
    }
}

/// Overwrite specific witness slots with the supplied values.
fn overwrite_witness_values(
    witness: &mut [FieldElement],
    indices: &[usize],
    values: &[FieldElement],
) {
    assert_eq!(
        indices.len(),
        values.len(),
        "indices and values must have the same length"
    );
    for (&idx, &value) in indices.iter().zip(values.iter()) {
        witness[idx] = value;
    }
}

#[derive(Clone, Copy, Debug)]
struct FakeGlvWitnessIndices {
    s1:   usize,
    s2:   usize,
    neg1: usize,
    neg2: usize,
}

#[derive(Clone, Debug)]
struct SinglePointMsmLayout {
    point_x_limbs: Vec<usize>,
    point_y_limbs: Vec<usize>,
    point_inf:     usize,
    scalar_lo:     usize,
    scalar_hi:     usize,
    out_x_limbs:   Vec<usize>,
    out_y_limbs:   Vec<usize>,
    out_inf:       usize,
    fake_glv:      FakeGlvWitnessIndices,
}

struct SinglePointMsmFixture {
    compiler:       NoirToR1CSCompiler,
    num_witnesses:  usize,
    initial_values: Vec<(usize, FieldElement)>,
    layout:         SinglePointMsmLayout,
}

/// Return the secp256r1 generator coordinates.
fn secp256r1_generator() -> ([u64; 4], [u64; 4]) {
    let curve = Secp256r1;
    (curve.generator().0, curve.generator().1)
}

/// Return the secp256r1 generator together with curve parameters used by
/// the local scalar-multiplication helpers in this test file.
fn secp256r1_generator_params() -> ([u64; 4], [u64; 4], [u64; 4], [u64; 4]) {
    let curve = Secp256r1;
    let (gx, gy) = secp256r1_generator();
    (gx, gy, curve.curve_a(), curve.field_modulus_p())
}

#[derive(Clone, Copy, Debug)]
struct SinglePointGeneratorCase {
    point_x:    [u64; 4],
    point_y:    [u64; 4],
    scalar:     [u64; 4],
    expected_x: [u64; 4],
    expected_y: [u64; 4],
}

/// Build a single-point secp256r1 generator case for the given scalar.
fn secp256r1_generator_case(scalar: [u64; 4]) -> SinglePointGeneratorCase {
    let (point_x, point_y, curve_a, field_modulus_p) = secp256r1_generator_params();
    let (expected_x, expected_y) =
        ec_scalar_mul(&point_x, &point_y, &scalar, &curve_a, &field_modulus_p);

    SinglePointGeneratorCase {
        point_x,
        point_y,
        scalar,
        expected_x,
        expected_y,
    }
}

/// Build the single-point generator fixture for a precomputed test case.
fn build_generator_single_point_fixture(case: SinglePointGeneratorCase) -> SinglePointMsmFixture {
    build_single_point_msm_fixture(
        &case.point_x,
        &case.point_y,
        false,
        &case.scalar,
        &case.expected_x,
        &case.expected_y,
        false,
    )
}

/// Build the single-point generator fixture directly from the scalar.
fn generator_fixture(scalar: [u64; 4]) -> SinglePointMsmFixture {
    build_generator_single_point_fixture(secp256r1_generator_case(scalar))
}

struct TwoPointMsmFixture {
    compiler:    NoirToR1CSCompiler,
    witness:     Vec<FieldElement>,
    out_x_limbs: Vec<usize>,
}

/// Build the shared two-point generator-based MSM witness used by the
/// positive and negative two-point tests.
fn build_default_two_point_msm_fixture() -> TwoPointMsmFixture {
    let (gx, gy, curve_a, field_modulus_p) = secp256r1_generator_params();
    let curve = Secp256r1;
    let (num_limbs, limb_bits) = msm_params_for_curve(&curve, 2);
    let stride = 2 * num_limbs + 1;

    // P1 = 3·G, P2 = 5·G
    let (p1x, p1y) = ec_scalar_mul(&gx, &gy, &[3, 0, 0, 0], &curve_a, &field_modulus_p);
    let (p2x, p2y) = ec_scalar_mul(&gx, &gy, &[5, 0, 0, 0], &curve_a, &field_modulus_p);
    let s1: [u64; 4] = [2, 0, 0, 0];
    let s2: [u64; 4] = [3, 0, 0, 0];
    // Expected: 2·(3G) + 3·(5G) = 6G + 15G = 21G
    let (ex, ey) = ec_scalar_mul(&gx, &gy, &[21, 0, 0, 0], &curve_a, &field_modulus_p);

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
    add_msm_with_curve(&mut compiler, msm_ops, &mut range_checks, &curve);
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

    TwoPointMsmFixture {
        compiler,
        witness,
        out_x_limbs,
    }
}

/// Locate the single FakeGLV hint used by the single-point MSM circuit.
fn locate_single_point_fake_glv(builders: &[WitnessBuilder]) -> FakeGlvWitnessIndices {
    let mut iter = builders.iter().filter_map(|builder| match builder {
        WitnessBuilder::FakeGLVHint { output_start, .. } => Some(FakeGlvWitnessIndices {
            s1:   *output_start,
            s2:   *output_start + 1,
            neg1: *output_start + 2,
            neg2: *output_start + 3,
        }),
        _ => None,
    });

    let result = iter.next().expect("should have at least one FakeGLV hint");
    assert!(
        iter.next().is_none(),
        "should have exactly one FakeGLV hint"
    );
    result
}

/// Build the single-point secp256r1 MSM circuit together with stable witness
/// metadata used by the negative tests.
fn build_single_point_msm_fixture(
    px: &[u64; 4],
    py: &[u64; 4],
    inf: bool,
    scalar: &[u64; 4],
    expected_x: &[u64; 4],
    expected_y: &[u64; 4],
    expected_inf: bool,
) -> SinglePointMsmFixture {
    let curve = Secp256r1;
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

    let point_x_limbs: Vec<usize> = (0..num_limbs).map(|j| base + j).collect();
    let point_y_limbs: Vec<usize> = (0..num_limbs).map(|j| base + num_limbs + j).collect();
    let point_inf = base + 2 * num_limbs;

    let points: Vec<ConstantOrR1CSWitness> = (0..stride)
        .map(|j| ConstantOrR1CSWitness::Witness(base + j))
        .collect();
    let scalar_lo = base + stride;
    let scalar_hi = base + stride + 1;
    let scalars = vec![
        ConstantOrR1CSWitness::Witness(scalar_lo),
        ConstantOrR1CSWitness::Witness(scalar_hi),
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
    add_msm_with_curve(&mut compiler, msm_ops, &mut range_checks, &curve);
    add_range_checks(&mut compiler, range_checks);

    let layout = SinglePointMsmLayout {
        point_x_limbs,
        point_y_limbs,
        point_inf,
        scalar_lo,
        scalar_hi,
        out_x_limbs,
        out_y_limbs,
        out_inf,
        fake_glv: locate_single_point_fake_glv(&compiler.witness_builders),
    };

    // Set initial witness values
    let mut initial_values = vec![(0, FieldElement::from(1u64))];
    for (j, fe) in px_fes.iter().enumerate() {
        initial_values.push((layout.point_x_limbs[j], *fe));
    }
    for (j, fe) in py_fes.iter().enumerate() {
        initial_values.push((layout.point_y_limbs[j], *fe));
    }
    let inf_fe = if inf {
        FieldElement::from(1u64)
    } else {
        FieldElement::zero()
    };
    initial_values.push((layout.point_inf, inf_fe));
    initial_values.push((layout.scalar_lo, u256_to_fe(&s_lo)));
    initial_values.push((layout.scalar_hi, u256_to_fe(&s_hi)));
    for (j, fe) in ex_fes.iter().enumerate() {
        initial_values.push((layout.out_x_limbs[j], *fe));
    }
    for (j, fe) in ey_fes.iter().enumerate() {
        initial_values.push((layout.out_y_limbs[j], *fe));
    }
    let out_inf_fe = if expected_inf {
        FieldElement::from(1u64)
    } else {
        FieldElement::zero()
    };
    initial_values.push((layout.out_inf, out_inf_fe));

    let num_witnesses = compiler.num_witnesses();

    SinglePointMsmFixture {
        compiler,
        num_witnesses,
        initial_values,
        layout,
    }
}

/// Solve the valid witness, then verify that a targeted corruption is rejected.
fn assert_single_point_corruption_is_rejected(
    fixture: SinglePointMsmFixture,
    scenario: &str,
    mutate: impl FnOnce(&SinglePointMsmLayout, &mut Vec<FieldElement>),
) {
    let witness = solve_witnesses(
        &fixture.compiler.witness_builders,
        fixture.num_witnesses,
        &fixture.initial_values,
    );
    check_r1cs_satisfaction(&fixture.compiler.r1cs, &witness)
        .unwrap_or_else(|err| panic!("valid witness should satisfy R1CS for {scenario}: {err}"));

    let mut corrupted = witness.clone();
    mutate(&fixture.layout, &mut corrupted);

    assert!(
        check_r1cs_satisfaction(&fixture.compiler.r1cs, &corrupted).is_err(),
        "corrupted witness should fail R1CS satisfaction for {scenario}"
    );
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
    let fixture =
        build_single_point_msm_fixture(px, py, inf, scalar, expected_x, expected_y, expected_inf);
    let witness = solve_witnesses(
        &fixture.compiler.witness_builders,
        fixture.num_witnesses,
        &fixture.initial_values,
    );

    check_r1cs_satisfaction(&fixture.compiler.r1cs, &witness)
        .expect("R1CS satisfaction check failed (limbed)");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Single-point MSM using the secp256r1 generator directly.
/// The generator's x-coordinate exceeds BN254 Fr.
#[test]
fn test_single_point_generator() {
    let (gx, gy, curve_a, field_modulus_p) = secp256r1_generator_params();
    let scalar: [u64; 4] = [7, 0, 0, 0];
    let (ex, ey) = ec_scalar_mul(&gx, &gy, &scalar, &curve_a, &field_modulus_p);

    run_single_point_msm_test_limbed(&gx, &gy, false, &scalar, &ex, &ey, false);
}

/// Scalar = 1: result should equal the input point.
#[test]
fn test_scalar_one() {
    let (gx, gy) = secp256r1_generator();
    let scalar: [u64; 4] = [1, 0, 0, 0];

    // 1·G = G
    run_single_point_msm_test_limbed(&gx, &gy, false, &scalar, &gx, &gy, false);
}

/// Large scalar spanning both lo and hi halves of the 256-bit representation.
#[test]
fn test_large_scalar() {
    let (gx, gy, curve_a, field_modulus_p) = secp256r1_generator_params();
    let scalar: [u64; 4] = [0xcafebabe, 0x12345678, 0x42, 0];
    let (ex, ey) = ec_scalar_mul(&gx, &gy, &scalar, &curve_a, &field_modulus_p);

    run_single_point_msm_test_limbed(&gx, &gy, false, &scalar, &ex, &ey, false);
}

/// Zero scalar: result should be point at infinity.
#[test]
fn test_zero_scalar() {
    let (gx, gy) = secp256r1_generator();
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
    // Use generator coords as placeholder (they're ignored due to inf=1 select)
    let (gx, gy) = secp256r1_generator();
    let scalar: [u64; 4] = [42, 0, 0, 0];
    let zero_point: [u64; 4] = [0, 0, 0, 0];

    run_single_point_msm_test_limbed(&gx, &gy, true, &scalar, &zero_point, &zero_point, true);
}

/// Non-trivial point (2·G) with a moderate scalar, verifying the full
/// wNAF + FakeGLV pipeline.
#[test]
fn test_arbitrary_point_and_scalar() {
    let (gx, gy, curve_a, field_modulus_p) = secp256r1_generator_params();

    // P = 2·G
    let (px, py) = ec_scalar_mul(&gx, &gy, &[2, 0, 0, 0], &curve_a, &field_modulus_p);
    let scalar: [u64; 4] = [17, 0, 0, 0];
    // Expected: 17·(2G) = 34G
    let (ex, ey) = ec_scalar_mul(&gx, &gy, &[34, 0, 0, 0], &curve_a, &field_modulus_p);

    run_single_point_msm_test_limbed(&px, &py, false, &scalar, &ex, &ey, false);
}

/// Corrupting an expected output x-limb or y-limb must violate the output
/// equality constraints.
#[test]
fn test_single_point_rejects_wrong_output_coordinates() {
    let get_x: fn(&SinglePointMsmLayout) -> usize = |l| l.out_x_limbs[0];
    let get_y: fn(&SinglePointMsmLayout) -> usize = |l| l.out_y_limbs[0];
    for (label, get_idx) in [("out_x", get_x), ("out_y", get_y)] {
        let fixture = generator_fixture([7, 0, 0, 0]);
        assert_single_point_corruption_is_rejected(
            fixture,
            &format!("wrong output coordinate ({label})"),
            |layout, corrupted| {
                let idx = get_idx(layout);
                corrupted[idx] = corrupt_field_element(corrupted[idx]);
            },
        );
    }
}

/// Corrupting the output infinity flag must violate the output constraints.
#[test]
fn test_single_point_rejects_wrong_output_inf() {
    let fixture = generator_fixture([7, 0, 0, 0]);

    assert_single_point_corruption_is_rejected(
        fixture,
        "wrong output inf flag",
        |layout, corrupted| {
            corrupted[layout.out_inf] = corrupt_field_element(corrupted[layout.out_inf]);
        },
    );
}

/// Corrupting the input y-coordinate must violate the curve-membership and
/// consistency constraints.
#[test]
fn test_single_point_rejects_off_curve_input() {
    let case = secp256r1_generator_case([7, 0, 0, 0]);
    let (num_limbs, limb_bits) = msm_params_for_curve(&Secp256r1, 1);
    let py_off_curve = increment_u256(&case.point_y);
    let py_off_curve_fes = u256_to_limb_fes(&py_off_curve, limb_bits, num_limbs);
    let fixture = build_generator_single_point_fixture(case);

    assert_single_point_corruption_is_rejected(fixture, "off-curve input", |layout, corrupted| {
        overwrite_witness_values(corrupted, &layout.point_y_limbs, &py_off_curve_fes);
    });
}

/// Replacing the expected output with a different scalar multiple must fail.
#[test]
fn test_single_point_rejects_wrong_scalar_output_pairing() {
    let case = secp256r1_generator_case([7, 0, 0, 0]);
    let wrong_case = secp256r1_generator_case([5, 0, 0, 0]);
    let (num_limbs, limb_bits) = msm_params_for_curve(&Secp256r1, 1);
    let wrong_ex_fes = u256_to_limb_fes(&wrong_case.expected_x, limb_bits, num_limbs);
    let wrong_ey_fes = u256_to_limb_fes(&wrong_case.expected_y, limb_bits, num_limbs);
    let fixture = build_generator_single_point_fixture(case);

    assert_single_point_corruption_is_rejected(
        fixture,
        "wrong scalar/output pairing",
        |layout, corrupted| {
            overwrite_witness_values(corrupted, &layout.out_x_limbs, &wrong_ex_fes);
            overwrite_witness_values(corrupted, &layout.out_y_limbs, &wrong_ey_fes);
        },
    );
}

/// Replacing the scalar input while keeping the original output must fail.
#[test]
fn test_single_point_rejects_scalar_corruption() {
    let wrong_scalar: [u64; 4] = [5, 0, 0, 0];
    let (wrong_lo, wrong_hi) = split_scalar(&wrong_scalar);
    let fixture = generator_fixture([7, 0, 0, 0]);

    assert_single_point_corruption_is_rejected(
        fixture,
        "scalar corruption",
        |layout, corrupted| {
            corrupted[layout.scalar_lo] = u256_to_fe(&wrong_lo);
            corrupted[layout.scalar_hi] = u256_to_fe(&wrong_hi);
        },
    );
}

/// Zeroing s2 must violate the explicit s2 != 0 soundness check.
#[test]
fn test_single_point_rejects_zero_s2_forgery() {
    let fixture = generator_fixture([17, 0, 0, 0]);

    assert_single_point_corruption_is_rejected(fixture, "s2 forgery", |layout, corrupted| {
        assert_ne!(
            corrupted[layout.fake_glv.s1],
            FieldElement::zero(),
            "valid witness should produce a non-zero s1"
        );
        assert_ne!(
            corrupted[layout.fake_glv.s2],
            FieldElement::zero(),
            "valid witness should produce a non-zero s2"
        );
        corrupted[layout.fake_glv.s2] = FieldElement::zero();
    });
}

/// Flipping neg1 or neg2 must violate the scalar relation tying the GLV
/// decomposition back to the original scalar.
#[test]
fn test_single_point_rejects_flipped_neg_bits() {
    let get_neg1: fn(&FakeGlvWitnessIndices) -> usize = |g| g.neg1;
    let get_neg2: fn(&FakeGlvWitnessIndices) -> usize = |g| g.neg2;
    for (label, get_idx) in [("neg1", get_neg1), ("neg2", get_neg2)] {
        let fixture = generator_fixture([17, 0, 0, 0]);
        assert_single_point_corruption_is_rejected(
            fixture,
            &format!("flipped {label} bit"),
            |layout, corrupted| {
                let idx = get_idx(&layout.fake_glv);
                corrupted[idx] = flip_boolean_field_element(corrupted[idx]);
            },
        );
    }
}

/// Two-point MSM: s1·P1 + s2·P2 with arbitrary coordinates.
#[test]
fn test_two_point_msm() {
    let fixture = build_default_two_point_msm_fixture();

    check_r1cs_satisfaction(&fixture.compiler.r1cs, &fixture.witness)
        .expect("R1CS satisfaction check failed for two-point MSM");
}

/// Two-point MSM where one scalar is zero — only the non-zero point
/// should contribute.
#[test]
fn test_two_point_one_zero_scalar() {
    let (gx, gy, curve_a, field_modulus_p) = secp256r1_generator_params();
    let curve = Secp256r1;
    let (num_limbs, limb_bits) = msm_params_for_curve(&curve, 2);
    let stride = 2 * num_limbs + 1;

    // P1 = G (scalar=5), P2 = 2G (scalar=0)
    let (p2x, p2y) = ec_scalar_mul(&gx, &gy, &[2, 0, 0, 0], &curve_a, &field_modulus_p);
    let s1: [u64; 4] = [5, 0, 0, 0];
    let s2: [u64; 4] = [0, 0, 0, 0];
    // Expected: 5·G + 0·(2G) = 5G
    let (ex, ey) = ec_scalar_mul(&gx, &gy, &[5, 0, 0, 0], &curve_a, &field_modulus_p);

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
    add_msm_with_curve(&mut compiler, msm_ops, &mut range_checks, &curve);
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

/// Two-point MSM: corrupting the output must be rejected, exercising the
/// multi-point accumulation and output-constraining path.
#[test]
fn test_two_point_msm_rejects_wrong_output() {
    let fixture = build_default_two_point_msm_fixture();
    check_r1cs_satisfaction(&fixture.compiler.r1cs, &fixture.witness)
        .expect("valid two-point MSM witness should satisfy R1CS");

    // Corrupt the output x-limb
    let mut corrupted = fixture.witness;
    corrupted[fixture.out_x_limbs[0]] = corrupt_field_element(corrupted[fixture.out_x_limbs[0]]);

    assert!(
        check_r1cs_satisfaction(&fixture.compiler.r1cs, &corrupted).is_err(),
        "corrupted two-point MSM output should fail R1CS satisfaction"
    );
}
