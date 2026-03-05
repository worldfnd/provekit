pub mod cost_model;
pub mod curve;
pub mod ec_points;
pub mod multi_limb_arith;
pub mod multi_limb_ops;

use {
    crate::{
        digits::{add_digital_decomposition, DigitalDecompositionWitnessesBuilder},
        msm::multi_limb_arith::compute_is_zero,
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::{AdditiveGroup, Field, PrimeField},
    curve::{decompose_to_limbs as decompose_to_limbs_pub, CurveParams},
    multi_limb_ops::{MultiLimbOps, MultiLimbParams},
    provekit_common::{
        witness::{ConstantOrR1CSWitness, ConstantTerm, SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::collections::BTreeMap,
};

// ---------------------------------------------------------------------------
// Limbs: fixed-capacity, Copy array of witness indices
// ---------------------------------------------------------------------------

/// Maximum number of limbs supported. Covers all practical field sizes
/// (e.g. a 512-bit modulus with 16-bit limbs = 32 limbs).
pub const MAX_LIMBS: usize = 32;

/// A fixed-capacity array of witness indices, indexed by limb position.
///
/// This type is `Copy`, so it can be used as `FieldOps::Elem` without
/// requiring const generics or dispatch macros. The runtime `len` field
/// tracks how many limbs are actually in use.
#[derive(Clone, Copy)]
pub struct Limbs {
    data: [usize; MAX_LIMBS],
    len:  usize,
}

impl Limbs {
    /// Sentinel value for uninitialized limb slots. Using `usize::MAX`
    /// ensures accidental use of an unfilled slot indexes an absurdly
    /// large witness, causing an immediate out-of-bounds panic.
    const UNINIT: usize = usize::MAX;

    /// Create a new `Limbs` with `len` limbs, all initialized to `UNINIT`.
    pub fn new(len: usize) -> Self {
        assert!(
            len > 0 && len <= MAX_LIMBS,
            "limb count must be 1..={MAX_LIMBS}, got {len}"
        );
        Self {
            data: [Self::UNINIT; MAX_LIMBS],
            len,
        }
    }

    /// Create a single-limb `Limbs` wrapping one witness index.
    pub fn single(value: usize) -> Self {
        let mut l = Self {
            data: [Self::UNINIT; MAX_LIMBS],
            len:  1,
        };
        l.data[0] = value;
        l
    }

    /// View the active limbs as a slice.
    pub fn as_slice(&self) -> &[usize] {
        &self.data[..self.len]
    }

    /// Number of active limbs.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len
    }
}

impl std::fmt::Debug for Limbs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.as_slice().iter()).finish()
    }
}

impl PartialEq for Limbs {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.data[..self.len] == other.data[..other.len]
    }
}
impl Eq for Limbs {}

impl std::ops::Index<usize> for Limbs {
    type Output = usize;
    fn index(&self, i: usize) -> &usize {
        debug_assert!(
            i < self.len,
            "Limbs index {i} out of bounds (len={})",
            self.len
        );
        &self.data[i]
    }
}

impl std::ops::IndexMut<usize> for Limbs {
    fn index_mut(&mut self, i: usize) -> &mut usize {
        debug_assert!(
            i < self.len,
            "Limbs index {i} out of bounds (len={})",
            self.len
        );
        &mut self.data[i]
    }
}

// ---------------------------------------------------------------------------
// FieldOps trait
// ---------------------------------------------------------------------------

pub trait FieldOps {
    type Elem: Copy;

    fn add(&mut self, a: Self::Elem, b: Self::Elem) -> Self::Elem;
    fn sub(&mut self, a: Self::Elem, b: Self::Elem) -> Self::Elem;
    fn mul(&mut self, a: Self::Elem, b: Self::Elem) -> Self::Elem;
    fn inv(&mut self, a: Self::Elem) -> Self::Elem;
    fn curve_a(&mut self) -> Self::Elem;

    /// Constrains `flag` to be boolean (`flag * flag = flag`).
    fn constrain_flag(&mut self, flag: usize);

    /// Conditional select without boolean constraint on `flag`.
    /// Caller must ensure `flag` is already constrained boolean.
    fn select_unchecked(
        &mut self,
        flag: usize,
        on_false: Self::Elem,
        on_true: Self::Elem,
    ) -> Self::Elem;

    /// Conditional select: returns `on_true` if `flag` is 1, `on_false` if
    /// `flag` is 0. Constrains `flag` to be boolean (`flag * flag = flag`).
    fn select(&mut self, flag: usize, on_false: Self::Elem, on_true: Self::Elem) -> Self::Elem {
        self.constrain_flag(flag);
        self.select_unchecked(flag, on_false, on_true)
    }

    /// Checks if a native witness value is zero.
    /// Returns a boolean witness: 1 if zero, 0 if non-zero.
    fn is_zero(&mut self, value: usize) -> usize;

    /// Packs bit witnesses into a single digit witness: `d = Σ bits[i] * 2^i`.
    /// Does NOT constrain bits to be boolean — caller must ensure that.
    fn pack_bits(&mut self, bits: &[usize]) -> usize;

    /// Returns a constant field element from its limb decomposition.
    fn constant_limbs(&mut self, limbs: &[FieldElement]) -> Self::Elem;
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

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
pub(crate) fn select_witness(
    compiler: &mut NoirToR1CSCompiler,
    flag: usize,
    on_false: usize,
    on_true: usize,
) -> usize {
    // When both branches are the same witness, result is trivially that witness.
    // Avoids duplicate column indices in R1CS from `on_true - on_false` when
    // both share the same witness index.
    if on_false == on_true {
        return on_false;
    }
    let diff = compiler.add_sum(vec![
        SumTerm(None, on_true),
        SumTerm(Some(-FieldElement::ONE), on_false),
    ]);
    let flag_diff = compiler.add_product(flag, diff);
    compiler.add_sum(vec![SumTerm(None, on_false), SumTerm(None, flag_diff)])
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
fn compute_boolean_or(compiler: &mut NoirToR1CSCompiler, a: usize, b: usize) -> usize {
    let one = compiler.witness_one();
    let one_minus_a = compiler.add_sum(vec![
        SumTerm(None, one),
        SumTerm(Some(-FieldElement::ONE), a),
    ]);
    let one_minus_b = compiler.add_sum(vec![
        SumTerm(None, one),
        SumTerm(Some(-FieldElement::ONE), b),
    ]);
    let product = compiler.add_product(one_minus_a, one_minus_b);
    compiler.add_sum(vec![
        SumTerm(None, one),
        SumTerm(Some(-FieldElement::ONE), product),
    ])
}

/// Detects whether a point-scalar pair is degenerate (scalar=0 or point at
/// infinity). Constrains `inf_flag` to boolean. Returns `is_skip` (1 if
/// degenerate).
fn detect_skip(
    compiler: &mut NoirToR1CSCompiler,
    s_lo: usize,
    s_hi: usize,
    inf_flag: usize,
) -> usize {
    constrain_boolean(compiler, inf_flag);
    let is_zero_s_lo = compute_is_zero(compiler, s_lo);
    let is_zero_s_hi = compute_is_zero(compiler, s_hi);
    let s_is_zero = compiler.add_product(is_zero_s_lo, is_zero_s_hi);
    compute_boolean_or(compiler, s_is_zero, inf_flag)
}

/// Constrains `a * b = 0`.
fn constrain_product_zero(compiler: &mut NoirToR1CSCompiler, a: usize, b: usize) {
    compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, a)], &[(FieldElement::ONE, b)], &[(
            FieldElement::ZERO,
            compiler.witness_one(),
        )]);
}

// ---------------------------------------------------------------------------
// Params builder (runtime num_limbs, no const generics)
// ---------------------------------------------------------------------------

/// Build `MultiLimbParams` for a given runtime `num_limbs`.
fn build_params(num_limbs: usize, limb_bits: u32, curve: &CurveParams) -> MultiLimbParams {
    let is_native = curve.is_native_field();
    let two_pow_w = FieldElement::from(2u64).pow([limb_bits as u64]);
    let modulus_fe = if !is_native {
        Some(curve.p_native_fe())
    } else {
        None
    };
    MultiLimbParams {
        num_limbs,
        limb_bits,
        p_limbs: curve.p_limbs(limb_bits, num_limbs),
        p_minus_1_limbs: curve.p_minus_1_limbs(limb_bits, num_limbs),
        two_pow_w,
        modulus_raw: curve.field_modulus_p,
        curve_a_limbs: curve.curve_a_limbs(limb_bits, num_limbs),
        is_native,
        modulus_fe,
    }
}

// ---------------------------------------------------------------------------
// MSM entry point
// ---------------------------------------------------------------------------

/// Processes all deferred MSM operations.
///
/// Internally selects the optimal (limb_bits, window_size) via cost model
/// and uses Grumpkin curve parameters.
///
/// Each entry is `(points, scalars, (out_x, out_y, out_inf))` where:
/// - `points` has layout `[x1, y1, inf1, x2, y2, inf2, ...]` (3 per point)
/// - `scalars` has layout `[s1_lo, s1_hi, s2_lo, s2_hi, ...]` (2 per scalar)
/// - outputs are the R1CS witness indices for the result point
/// Grumpkin-specific MSM entry point (used by the Noir `MultiScalarMul` black
/// box).
pub fn add_msm(
    compiler: &mut NoirToR1CSCompiler,
    msm_ops: Vec<(
        Vec<ConstantOrR1CSWitness>,
        Vec<ConstantOrR1CSWitness>,
        (usize, usize, usize),
    )>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) {
    let curve = curve::grumpkin_params();
    add_msm_with_curve(compiler, msm_ops, range_checks, &curve);
}

/// Curve-agnostic MSM: compiles MSM operations for any curve described by
/// `curve`.
pub fn add_msm_with_curve(
    compiler: &mut NoirToR1CSCompiler,
    msm_ops: Vec<(
        Vec<ConstantOrR1CSWitness>,
        Vec<ConstantOrR1CSWitness>,
        (usize, usize, usize),
    )>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    curve: &CurveParams,
) {
    if msm_ops.is_empty() {
        return;
    }

    let native_bits = FieldElement::MODULUS_BIT_SIZE;
    let curve_bits = curve.modulus_bits();
    let n_points: usize = msm_ops.iter().map(|(pts, ..)| pts.len() / 3).sum();
    let (limb_bits, window_size) =
        cost_model::get_optimal_msm_params(native_bits, curve_bits, n_points, 256);

    for (points, scalars, outputs) in msm_ops {
        add_single_msm(
            compiler,
            &points,
            &scalars,
            outputs,
            limb_bits,
            window_size,
            range_checks,
            curve,
        );
    }
}

/// Processes a single MSM operation.
fn add_single_msm(
    compiler: &mut NoirToR1CSCompiler,
    points: &[ConstantOrR1CSWitness],
    scalars: &[ConstantOrR1CSWitness],
    outputs: (usize, usize, usize),
    limb_bits: u32,
    window_size: usize,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    curve: &CurveParams,
) {
    assert!(
        points.len() % 3 == 0,
        "points length must be a multiple of 3"
    );
    let n = points.len() / 3;
    assert_eq!(
        scalars.len(),
        2 * n,
        "scalars length must be 2x the number of points"
    );

    // Resolve all inputs to witness indices
    let point_wits: Vec<usize> = points.iter().map(|p| resolve_input(compiler, p)).collect();
    let scalar_wits: Vec<usize> = scalars.iter().map(|s| resolve_input(compiler, s)).collect();

    let is_native = curve.is_native_field();
    let num_limbs = if is_native {
        1
    } else {
        (curve.modulus_bits() as usize + limb_bits as usize - 1) / limb_bits as usize
    };

    process_single_msm(
        compiler,
        &point_wits,
        &scalar_wits,
        outputs,
        num_limbs,
        limb_bits,
        window_size,
        range_checks,
        curve,
    );
}

/// Process a full single-MSM with runtime `num_limbs`.
///
/// Uses FakeGLV for ALL points: each point P_i with scalar s_i is verified
/// using scalar decomposition and half-width interleaved scalar mul.
///
/// For `n_points == 1`, R = (out_x, out_y) is the ACIR output.
/// For `n_points > 1`, R_i = EcScalarMulHint witnesses, accumulated via
/// point_add and constrained against the ACIR output.
fn process_single_msm<'a>(
    mut compiler: &'a mut NoirToR1CSCompiler,
    point_wits: &[usize],
    scalar_wits: &[usize],
    outputs: (usize, usize, usize),
    num_limbs: usize,
    limb_bits: u32,
    window_size: usize,
    mut range_checks: &'a mut BTreeMap<u32, Vec<usize>>,
    curve: &CurveParams,
) {
    let n_points = point_wits.len() / 3;
    let (out_x, out_y, out_inf) = outputs;

    if n_points == 1 {
        // Single-point: R is the ACIR output directly
        let px_witness = point_wits[0];
        let py_witness = point_wits[1];
        let inf_flag = point_wits[2];
        let s_lo = scalar_wits[0];
        let s_hi = scalar_wits[1];

        // --- Detect degenerate case: is_skip = (scalar == 0) OR (point is infinity)
        let is_skip = detect_skip(compiler, s_lo, s_hi, inf_flag);

        // --- Sanitize inputs: swap in generator G and scalar=1 when is_skip ---
        let one = compiler.witness_one();
        let gen_x_witness =
            add_constant_witness(compiler, curve::curve_native_point_fe(&curve.generator.0));
        let gen_y_witness =
            add_constant_witness(compiler, curve::curve_native_point_fe(&curve.generator.1));

        let sanitized_px = select_witness(compiler, is_skip, px_witness, gen_x_witness);
        let sanitized_py = select_witness(compiler, is_skip, py_witness, gen_y_witness);

        // When is_skip=1, use scalar=(1, 0) so FakeGLV computes [1]*G = G
        let zero_witness = add_constant_witness(compiler, FieldElement::ZERO);
        let sanitized_s_lo = select_witness(compiler, is_skip, s_lo, one);
        let sanitized_s_hi = select_witness(compiler, is_skip, s_hi, zero_witness);

        // Sanitize R (output point): when is_skip=1, R must be G (since [1]*G = G)
        let sanitized_rx = select_witness(compiler, is_skip, out_x, gen_x_witness);
        let sanitized_ry = select_witness(compiler, is_skip, out_y, gen_y_witness);

        // Decompose sanitized P into limbs
        let (px, py) = decompose_point_to_limbs(
            compiler,
            sanitized_px,
            sanitized_py,
            num_limbs,
            limb_bits,
            range_checks,
        );
        // Decompose sanitized R into limbs
        let (rx, ry) = decompose_point_to_limbs(
            compiler,
            sanitized_rx,
            sanitized_ry,
            num_limbs,
            limb_bits,
            range_checks,
        );

        // Run FakeGLV on sanitized values (always satisfiable)
        (compiler, range_checks) = verify_point_fakeglv(
            compiler,
            range_checks,
            px,
            py,
            rx,
            ry,
            sanitized_s_lo,
            sanitized_s_hi,
            num_limbs,
            limb_bits,
            window_size,
            curve,
        );

        // --- Mask output: when is_skip, output must be (0, 0, 1) ---
        constrain_equal(compiler, out_inf, is_skip);
        constrain_product_zero(compiler, is_skip, out_x);
        constrain_product_zero(compiler, is_skip, out_y);
    } else {
        // Multi-point: compute R_i = [s_i]P_i via hints, verify each with FakeGLV,
        // then accumulate R_i's with offset-based accumulation and skip handling.
        let one = compiler.witness_one();

        // Generator constants for sanitization
        let gen_x_fe = curve::curve_native_point_fe(&curve.generator.0);
        let gen_y_fe = curve::curve_native_point_fe(&curve.generator.1);
        let gen_x_witness = add_constant_witness(compiler, gen_x_fe);
        let gen_y_witness = add_constant_witness(compiler, gen_y_fe);
        let zero_witness = add_constant_witness(compiler, FieldElement::ZERO);

        // Build params once for all multi-limb ops in the multi-point path
        let params = build_params(num_limbs, limb_bits, curve);

        // Offset point as limbs for accumulation
        let offset_x_values = curve.offset_x_limbs(limb_bits, num_limbs);
        let offset_y_values = curve.offset_y_limbs(limb_bits, num_limbs);

        // Start accumulator at offset_point
        let mut ops = MultiLimbOps {
            compiler,
            range_checks,
            params: &params,
        };
        let mut acc_x = ops.constant_limbs(&offset_x_values);
        let mut acc_y = ops.constant_limbs(&offset_y_values);
        compiler = ops.compiler;
        range_checks = ops.range_checks;

        // Track all_skipped = product of all is_skip flags
        let mut all_skipped: Option<usize> = None;

        for i in 0..n_points {
            let px_witness = point_wits[3 * i];
            let py_witness = point_wits[3 * i + 1];
            let inf_flag = point_wits[3 * i + 2];
            let s_lo = scalar_wits[2 * i];
            let s_hi = scalar_wits[2 * i + 1];

            // --- Detect degenerate case ---
            let is_skip = detect_skip(compiler, s_lo, s_hi, inf_flag);

            // Track all_skipped
            all_skipped = Some(match all_skipped {
                None => is_skip,
                Some(prev) => compiler.add_product(prev, is_skip),
            });

            // --- Sanitize inputs ---
            let sanitized_px = select_witness(compiler, is_skip, px_witness, gen_x_witness);
            let sanitized_py = select_witness(compiler, is_skip, py_witness, gen_y_witness);
            let sanitized_s_lo = select_witness(compiler, is_skip, s_lo, one);
            let sanitized_s_hi = select_witness(compiler, is_skip, s_hi, zero_witness);

            // EcScalarMulHint uses sanitized inputs
            let hint_start = compiler.num_witnesses();
            compiler.add_witness_builder(WitnessBuilder::EcScalarMulHint {
                output_start:    hint_start,
                px:              sanitized_px,
                py:              sanitized_py,
                s_lo:            sanitized_s_lo,
                s_hi:            sanitized_s_hi,
                curve_a:         curve.curve_a,
                field_modulus_p: curve.field_modulus_p,
            });
            let rx_witness = hint_start;
            let ry_witness = hint_start + 1;

            // When is_skip=1, R should be G (since [1]*G = G)
            let sanitized_rx = select_witness(compiler, is_skip, rx_witness, gen_x_witness);
            let sanitized_ry = select_witness(compiler, is_skip, ry_witness, gen_y_witness);

            // Decompose sanitized P_i into limbs
            let (px, py) = decompose_point_to_limbs(
                compiler,
                sanitized_px,
                sanitized_py,
                num_limbs,
                limb_bits,
                range_checks,
            );
            // Decompose sanitized R_i into limbs
            let (rx, ry) = decompose_point_to_limbs(
                compiler,
                sanitized_rx,
                sanitized_ry,
                num_limbs,
                limb_bits,
                range_checks,
            );

            // Verify R_i = [s_i]P_i using FakeGLV (on sanitized values)
            (compiler, range_checks) = verify_point_fakeglv(
                compiler,
                range_checks,
                px,
                py,
                rx,
                ry,
                sanitized_s_lo,
                sanitized_s_hi,
                num_limbs,
                limb_bits,
                window_size,
                curve,
            );

            // --- Offset-based accumulation with conditional select ---
            // Compute candidate = point_add(acc, R_i)
            // Then select: if is_skip, keep acc unchanged; else use candidate
            let mut ops = MultiLimbOps {
                compiler,
                range_checks,
                params: &params,
            };
            let (cand_x, cand_y) = ec_points::point_add(&mut ops, acc_x, acc_y, rx, ry);
            let (new_acc_x, new_acc_y) =
                ec_points::point_select(&mut ops, is_skip, (cand_x, cand_y), (acc_x, acc_y));
            acc_x = new_acc_x;
            acc_y = new_acc_y;
            compiler = ops.compiler;
            range_checks = ops.range_checks;
        }

        let all_skipped = all_skipped.expect("MSM must have at least one point");

        // Subtract offset: result = point_add(acc, -offset)
        // Negated offset = (offset_x, -offset_y)
        let neg_offset_y_raw =
            curve::negate_field_element(&curve.offset_point.1, &curve.field_modulus_p);
        let neg_offset_y_values =
            curve::decompose_to_limbs(&neg_offset_y_raw, limb_bits, num_limbs);

        // When all_skipped, acc == offset_point, so subtracting offset would be
        // point_add(O, -O) which fails (x1 == x2). Use generator G as the
        // subtraction target instead; the result won't matter since we'll mask it.
        let gen_x_limb_values = curve.generator_x_limbs(limb_bits, num_limbs);
        let neg_gen_y_raw = curve::negate_field_element(&curve.generator.1, &curve.field_modulus_p);
        let neg_gen_y_values = curve::decompose_to_limbs(&neg_gen_y_raw, limb_bits, num_limbs);

        let mut ops = MultiLimbOps {
            compiler,
            range_checks,
            params: &params,
        };

        // Select subtraction point: if all_skipped, use -G; else use -offset
        let sub_x = {
            let off_x = ops.constant_limbs(&offset_x_values);
            let g_x = ops.constant_limbs(&gen_x_limb_values);
            ops.select(all_skipped, off_x, g_x)
        };
        let sub_y = {
            let neg_off_y = ops.constant_limbs(&neg_offset_y_values);
            let neg_g_y = ops.constant_limbs(&neg_gen_y_values);
            ops.select(all_skipped, neg_off_y, neg_g_y)
        };

        let (result_x, result_y) = ec_points::point_add(&mut ops, acc_x, acc_y, sub_x, sub_y);
        compiler = ops.compiler;
        range_checks = ops.range_checks;

        // --- Constrain output ---
        // When all_skipped: output is (0, 0, 1)
        // Otherwise: output matches the computed result with inf=0
        if num_limbs == 1 {
            // Mask result with all_skipped: when all_skipped=1, out must be 0
            let masked_result_x = select_witness(compiler, all_skipped, result_x[0], zero_witness);
            let masked_result_y = select_witness(compiler, all_skipped, result_y[0], zero_witness);
            constrain_equal(compiler, out_x, masked_result_x);
            constrain_equal(compiler, out_y, masked_result_y);
        } else {
            let recomposed_x = recompose_limbs(compiler, result_x.as_slice(), limb_bits);
            let recomposed_y = recompose_limbs(compiler, result_y.as_slice(), limb_bits);
            let masked_result_x = select_witness(compiler, all_skipped, recomposed_x, zero_witness);
            let masked_result_y = select_witness(compiler, all_skipped, recomposed_y, zero_witness);
            constrain_equal(compiler, out_x, masked_result_x);
            constrain_equal(compiler, out_y, masked_result_y);
        }
        constrain_equal(compiler, out_inf, all_skipped);
    }
}

/// Decompose a point (px_witness, py_witness) into Limbs.
fn decompose_point_to_limbs(
    compiler: &mut NoirToR1CSCompiler,
    px_witness: usize,
    py_witness: usize,
    num_limbs: usize,
    limb_bits: u32,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> (Limbs, Limbs) {
    if num_limbs == 1 {
        (Limbs::single(px_witness), Limbs::single(py_witness))
    } else {
        let px_limbs =
            decompose_witness_to_limbs(compiler, px_witness, limb_bits, num_limbs, range_checks);
        let py_limbs =
            decompose_witness_to_limbs(compiler, py_witness, limb_bits, num_limbs, range_checks);
        (px_limbs, py_limbs)
    }
}

/// FakeGLV verification for a single point: verifies R = [s]P.
///
/// Decomposes s via half-GCD into sub-scalars (s1, s2) and verifies
/// [s1]P + [s2]R = O using interleaved windowed scalar mul with
/// half-width scalars.
///
/// Returns the mutable references back to the caller for continued use.
fn verify_point_fakeglv<'a>(
    mut compiler: &'a mut NoirToR1CSCompiler,
    mut range_checks: &'a mut BTreeMap<u32, Vec<usize>>,
    px: Limbs,
    py: Limbs,
    rx: Limbs,
    ry: Limbs,
    s_lo: usize,
    s_hi: usize,
    num_limbs: usize,
    limb_bits: u32,
    window_size: usize,
    curve: &CurveParams,
) -> (
    &'a mut NoirToR1CSCompiler,
    &'a mut BTreeMap<u32, Vec<usize>>,
) {
    // --- Steps 1-4: On-curve checks, FakeGLV decomposition, and GLV scalar mul
    // ---
    let s1_witness;
    let s2_witness;
    let neg1_witness;
    let neg2_witness;
    {
        let params = build_params(num_limbs, limb_bits, curve);
        let mut ops = MultiLimbOps {
            compiler,
            range_checks,
            params: &params,
        };

        // Step 1: On-curve checks for P and R
        let b_limb_values = curve::decompose_to_limbs(&curve.curve_b, limb_bits, num_limbs);
        verify_on_curve(&mut ops, px, py, &b_limb_values, num_limbs);
        verify_on_curve(&mut ops, rx, ry, &b_limb_values, num_limbs);

        // Step 2: FakeGLVHint → |s1|, |s2|, neg1, neg2
        let glv_start = ops.compiler.num_witnesses();
        ops.compiler
            .add_witness_builder(WitnessBuilder::FakeGLVHint {
                output_start: glv_start,
                s_lo,
                s_hi,
                curve_order: curve.curve_order_n,
            });
        s1_witness = glv_start;
        s2_witness = glv_start + 1;
        neg1_witness = glv_start + 2;
        neg2_witness = glv_start + 3;

        // Step 3: Decompose |s1|, |s2| into half_bits bits each
        let half_bits = curve.glv_half_bits() as usize;
        let s1_bits = decompose_half_scalar_bits(ops.compiler, s1_witness, half_bits);
        let s2_bits = decompose_half_scalar_bits(ops.compiler, s2_witness, half_bits);

        // Step 4: Conditionally negate P.y and R.y + GLV scalar mul + identity
        // check

        // Compute negated y-coordinates: neg_y = 0 - y (mod p)
        let neg_py = ops.negate(py);
        let neg_ry = ops.negate(ry);

        // Select: if neg1=1, use neg_py; else use py
        // neg1 and neg2 are constrained to be boolean by ops.select internally.
        let py_effective = ops.select(neg1_witness, py, neg_py);
        // Select: if neg2=1, use neg_ry; else use ry
        let ry_effective = ops.select(neg2_witness, ry, neg_ry);

        // GLV scalar mul
        let offset_x_values = curve.offset_x_limbs(limb_bits, num_limbs);
        let offset_y_values = curve.offset_y_limbs(limb_bits, num_limbs);
        let offset_x = ops.constant_limbs(&offset_x_values);
        let offset_y = ops.constant_limbs(&offset_y_values);

        let glv_acc = ec_points::scalar_mul_glv(
            &mut ops,
            px,
            py_effective,
            &s1_bits,
            rx,
            ry_effective,
            &s2_bits,
            window_size,
            offset_x,
            offset_y,
        );

        // Identity check: acc should equal [2^(num_windows * window_size)] *
        // offset_point
        let glv_num_windows = (half_bits + window_size - 1) / window_size;
        let glv_n_doublings = glv_num_windows * window_size;
        let (acc_off_x_raw, acc_off_y_raw) = curve.accumulated_offset(glv_n_doublings);

        let acc_off_x_values = decompose_to_limbs_pub(&acc_off_x_raw, limb_bits, num_limbs);
        let acc_off_y_values = decompose_to_limbs_pub(&acc_off_y_raw, limb_bits, num_limbs);
        let expected_x = ops.constant_limbs(&acc_off_x_values);
        let expected_y = ops.constant_limbs(&acc_off_y_values);

        for i in 0..num_limbs {
            constrain_equal(ops.compiler, glv_acc.0[i], expected_x[i]);
            constrain_equal(ops.compiler, glv_acc.1[i], expected_y[i]);
        }

        compiler = ops.compiler;
        range_checks = ops.range_checks;
    }

    // --- Step 5: Scalar relation verification ---
    verify_scalar_relation(
        compiler,
        range_checks,
        s_lo,
        s_hi,
        s1_witness,
        s2_witness,
        neg1_witness,
        neg2_witness,
        curve,
    );

    (compiler, range_checks)
}

/// On-curve check: verifies y^2 = x^3 + a*x + b for a single point.
fn verify_on_curve(
    ops: &mut MultiLimbOps,
    x: Limbs,
    y: Limbs,
    b_limb_values: &[FieldElement],
    num_limbs: usize,
) {
    let y_sq = ops.mul(y, y);
    let x_sq = ops.mul(x, x);
    let x_cubed = ops.mul(x_sq, x);
    let a = ops.curve_a();
    let ax = ops.mul(a, x);
    let x3_plus_ax = ops.add(x_cubed, ax);
    let b = ops.constant_limbs(b_limb_values);
    let rhs = ops.add(x3_plus_ax, b);
    for i in 0..num_limbs {
        constrain_equal(ops.compiler, y_sq[i], rhs[i]);
    }
}

/// Decompose a single witness into `num_limbs` limbs using digital
/// decomposition.
fn decompose_witness_to_limbs(
    compiler: &mut NoirToR1CSCompiler,
    witness: usize,
    limb_bits: u32,
    num_limbs: usize,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> Limbs {
    let log_bases = vec![limb_bits as usize; num_limbs];
    let dd = add_digital_decomposition(compiler, log_bases, vec![witness]);
    let mut limbs = Limbs::new(num_limbs);
    for i in 0..num_limbs {
        limbs[i] = dd.get_digit_witness_index(i, 0);
        // Range-check each decomposed limb to [0, 2^limb_bits).
        // add_digital_decomposition constrains the recomposition but does
        // NOT range-check individual digits.
        range_checks.entry(limb_bits).or_default().push(limbs[i]);
    }
    limbs
}

/// Recompose limbs back into a single witness: val = Σ limb[i] *
/// 2^(i*limb_bits)
fn recompose_limbs(compiler: &mut NoirToR1CSCompiler, limbs: &[usize], limb_bits: u32) -> usize {
    let terms: Vec<SumTerm> = limbs
        .iter()
        .enumerate()
        .map(|(i, &limb)| {
            let coeff = FieldElement::from(2u64).pow([(i as u64) * (limb_bits as u64)]);
            SumTerm(Some(coeff), limb)
        })
        .collect();
    compiler.add_sum(terms)
}

/// Resolves a `ConstantOrR1CSWitness` to a witness index.
fn resolve_input(compiler: &mut NoirToR1CSCompiler, input: &ConstantOrR1CSWitness) -> usize {
    match input {
        ConstantOrR1CSWitness::Witness(idx) => *idx,
        ConstantOrR1CSWitness::Constant(value) => {
            let w = compiler.num_witnesses();
            compiler.add_witness_builder(WitnessBuilder::Constant(ConstantTerm(w, *value)));
            w
        }
    }
}

/// Decomposes a half-scalar witness into `half_bits` bit witnesses (LSB first).
fn decompose_half_scalar_bits(
    compiler: &mut NoirToR1CSCompiler,
    scalar: usize,
    half_bits: usize,
) -> Vec<usize> {
    let log_bases = vec![1usize; half_bits];
    let dd = add_digital_decomposition(compiler, log_bases, vec![scalar]);
    let mut bits = Vec::with_capacity(half_bits);
    for bit_idx in 0..half_bits {
        bits.push(dd.get_digit_witness_index(bit_idx, 0));
    }
    bits
}

/// Builds `MultiLimbParams` for scalar relation verification (mod
/// curve_order_n).
fn build_scalar_relation_params(
    num_limbs: usize,
    limb_bits: u32,
    curve: &CurveParams,
) -> MultiLimbParams {
    // Scalar relation uses curve_order_n as the modulus.
    // This is always non-native (curve_order_n ≠ BN254 scalar field modulus,
    // except for Grumpkin where they're very close but still different).
    let two_pow_w = FieldElement::from(2u64).pow([limb_bits as u64]);
    let n_limbs = curve.curve_order_n_limbs(limb_bits, num_limbs);
    let n_minus_1_limbs = curve.curve_order_n_minus_1_limbs(limb_bits, num_limbs);

    // For N=1 non-native, we need the modulus as a FieldElement
    let modulus_fe = if num_limbs == 1 {
        Some(curve::curve_native_point_fe(&curve.curve_order_n))
    } else {
        None
    };

    MultiLimbParams {
        num_limbs,
        limb_bits,
        p_limbs: n_limbs,
        p_minus_1_limbs: n_minus_1_limbs,
        two_pow_w,
        modulus_raw: curve.curve_order_n,
        curve_a_limbs: vec![FieldElement::from(0u64); num_limbs], // unused
        is_native: false,                                         // always non-native
        modulus_fe,
    }
}

/// Picks the largest limb size for the scalar-relation multi-limb arithmetic
/// that fits inside the native field without overflow.
///
/// The schoolbook multiplication column equations require:
///   `2 * limb_bits + ceil(log2(num_limbs)) + 3 < native_field_bits`
///
/// We start at 64 bits (the ideal case — inputs are 128-bit half-scalars) and
/// search downward until the soundness check passes. For BN254 (254-bit native
/// field) this resolves to 64; smaller fields like M31 (31 bits) will get a
/// proportionally smaller limb size.
///
/// Panics if the native field is too small (< ~12 bits) to support any valid
/// limb decomposition.
fn scalar_relation_limb_bits(order_bits: usize) -> u32 {
    let native_bits = FieldElement::MODULUS_BIT_SIZE;
    let mut limb_bits: u32 = 64.min((native_bits.saturating_sub(4)) / 2);
    loop {
        let num_limbs = (order_bits + limb_bits as usize - 1) / limb_bits as usize;
        if cost_model::column_equation_fits_native_field(native_bits, limb_bits, num_limbs) {
            break;
        }
        limb_bits -= 1;
        assert!(
            limb_bits >= 4,
            "native field too small for scalar relation verification"
        );
    }
    limb_bits
}

/// Verifies the scalar relation: (-1)^neg1 * |s1| + (-1)^neg2 * |s2| * s ≡ 0
/// (mod n).
///
/// Uses multi-limb arithmetic with curve_order_n as the modulus.
/// The sub-scalars s1, s2 have `half_bits = ceil(order_bits/2)` bits;
/// the full scalar s has up to `order_bits` bits.
fn verify_scalar_relation(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    s_lo: usize,
    s_hi: usize,
    s1_witness: usize,
    s2_witness: usize,
    neg1_witness: usize,
    neg2_witness: usize,
    curve: &CurveParams,
) {
    let order_bits = curve.curve_order_bits() as usize;
    let sr_limb_bits = scalar_relation_limb_bits(order_bits);
    let sr_num_limbs = (order_bits + sr_limb_bits as usize - 1) / sr_limb_bits as usize;
    let half_bits = curve.glv_half_bits() as usize;
    // Number of limbs the half-scalar occupies
    let half_limbs = (half_bits + sr_limb_bits as usize - 1) / sr_limb_bits as usize;

    let params = build_scalar_relation_params(sr_num_limbs, sr_limb_bits, curve);
    let mut ops = MultiLimbOps {
        compiler,
        range_checks,
        params: &params,
    };

    // Decompose s into sr_num_limbs limbs from (s_lo, s_hi).
    // s_lo contains bits [0..128), s_hi contains bits [128..256).
    let s_limbs = {
        let limbs_per_half = (128 + sr_limb_bits as usize - 1) / sr_limb_bits as usize;
        let dd_bases_128: Vec<usize> = (0..limbs_per_half)
            .map(|i| {
                let remaining = 128u32 - (i as u32 * sr_limb_bits);
                remaining.min(sr_limb_bits) as usize
            })
            .collect();
        let dd_lo = add_digital_decomposition(ops.compiler, dd_bases_128.clone(), vec![s_lo]);
        let dd_hi = add_digital_decomposition(ops.compiler, dd_bases_128, vec![s_hi]);
        let mut limbs = Limbs::new(sr_num_limbs);
        let lo_n = limbs_per_half.min(sr_num_limbs);
        for i in 0..lo_n {
            limbs[i] = dd_lo.get_digit_witness_index(i, 0);
            let remaining = 128u32 - (i as u32 * sr_limb_bits);
            ops.range_checks
                .entry(remaining.min(sr_limb_bits))
                .or_default()
                .push(limbs[i]);
        }
        let hi_n = sr_num_limbs - lo_n;
        for i in 0..hi_n {
            limbs[lo_n + i] = dd_hi.get_digit_witness_index(i, 0);
            let remaining = 128u32 - (i as u32 * sr_limb_bits);
            ops.range_checks
                .entry(remaining.min(sr_limb_bits))
                .or_default()
                .push(limbs[lo_n + i]);
        }
        limbs
    };

    // Helper: decompose a half-scalar witness into sr_num_limbs limbs.
    // The half-scalar has `half_bits` bits → occupies `half_limbs` limbs.
    // Upper limbs (half_limbs..sr_num_limbs) are zero-padded.
    let decompose_half_scalar = |ops: &mut MultiLimbOps, witness: usize| -> Limbs {
        let dd_bases: Vec<usize> = (0..half_limbs)
            .map(|i| {
                let remaining = half_bits as u32 - (i as u32 * sr_limb_bits);
                remaining.min(sr_limb_bits) as usize
            })
            .collect();
        let dd = add_digital_decomposition(ops.compiler, dd_bases, vec![witness]);
        let mut limbs = Limbs::new(sr_num_limbs);
        for i in 0..half_limbs {
            limbs[i] = dd.get_digit_witness_index(i, 0);
            let remaining_bits = (half_bits as u32) - (i as u32 * sr_limb_bits);
            let this_limb_bits = remaining_bits.min(sr_limb_bits);
            ops.range_checks
                .entry(this_limb_bits)
                .or_default()
                .push(limbs[i]);
        }
        // Zero-pad upper limbs
        for i in half_limbs..sr_num_limbs {
            let w = ops.compiler.num_witnesses();
            ops.compiler
                .add_witness_builder(WitnessBuilder::Constant(ConstantTerm(
                    w,
                    FieldElement::from(0u64),
                )));
            limbs[i] = w;
            constrain_zero(ops.compiler, limbs[i]);
        }
        limbs
    };

    let s1_limbs = decompose_half_scalar(&mut ops, s1_witness);
    let s2_limbs = decompose_half_scalar(&mut ops, s2_witness);

    // Compute product = s2 * s (mod n)
    let product = ops.mul(s2_limbs, s_limbs);

    // Handle signs: compute effective values
    // If neg2 is set: neg_product = n - product (mod n), i.e. 0 - product
    let neg_product = ops.negate(product);
    // neg2 already constrained boolean in verify_point_fakeglv
    let effective_product = ops.select_unchecked(neg2_witness, product, neg_product);

    // If neg1 is set: neg_s1 = n - s1 (mod n), i.e. 0 - s1
    let neg_s1 = ops.negate(s1_limbs);
    // neg1 already constrained boolean in verify_point_fakeglv
    let effective_s1 = ops.select_unchecked(neg1_witness, s1_limbs, neg_s1);

    // Sum: effective_s1 + effective_product (mod n) should be 0
    let sum = ops.add(effective_s1, effective_product);

    // Constrain sum == 0: all limbs must be zero
    for i in 0..sr_num_limbs {
        constrain_zero(ops.compiler, sum[i]);
    }
}

/// Creates a constant witness with the given value.
fn add_constant_witness(compiler: &mut NoirToR1CSCompiler, value: FieldElement) -> usize {
    let w = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::Constant(ConstantTerm(w, value)));
    w
}

/// Constrains two witnesses to be equal: `a - b = 0`.
fn constrain_equal(compiler: &mut NoirToR1CSCompiler, a: usize, b: usize) {
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, a), (-FieldElement::ONE, b)],
        &[(FieldElement::ZERO, compiler.witness_one())],
    );
}

/// Constrains a witness to be zero: `w = 0`.
fn constrain_zero(compiler: &mut NoirToR1CSCompiler, w: usize) {
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, w)],
        &[(FieldElement::ZERO, compiler.witness_one())],
    );
}
