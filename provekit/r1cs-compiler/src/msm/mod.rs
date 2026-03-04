pub mod cost_model;
pub mod curve;
pub mod ec_points;
pub mod multi_limb_arith;
pub mod multi_limb_ops;

use {
    crate::{
        digits::{add_digital_decomposition, DigitalDecompositionWitnessesBuilder},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::{AdditiveGroup, Field},
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

    /// Create `Limbs` from a slice of witness indices.
    pub fn from_slice(s: &[usize]) -> Self {
        assert!(
            !s.is_empty() && s.len() <= MAX_LIMBS,
            "slice length must be 1..={MAX_LIMBS}, got {}",
            s.len()
        );
        let mut data = [Self::UNINIT; MAX_LIMBS];
        data[..s.len()].copy_from_slice(s);
        Self { data, len: s.len() }
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

    /// Conditional select: returns `on_true` if `flag` is 1, `on_false` if
    /// `flag` is 0. Constrains `flag` to be boolean (`flag * flag = flag`).
    fn select(&mut self, flag: usize, on_false: Self::Elem, on_true: Self::Elem) -> Self::Elem;

    /// Checks if a BN254 native witness value is zero.
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
        modulus_bits: curve.modulus_bits(),
        is_native,
        modulus_fe,
    }
}

// ---------------------------------------------------------------------------
// MSM entry point
// ---------------------------------------------------------------------------

/// Processes all deferred MSM operations.
///
/// Each entry is `(points, scalars, (out_x, out_y, out_inf))` where:
/// - `points` has layout `[x1, y1, inf1, x2, y2, inf2, ...]` (3 per point)
/// - `scalars` has layout `[s1_lo, s1_hi, s2_lo, s2_hi, ...]` (2 per scalar)
/// - outputs are the R1CS witness indices for the result point
pub fn add_msm(
    compiler: &mut NoirToR1CSCompiler,
    msm_ops: Vec<(
        Vec<ConstantOrR1CSWitness>,
        Vec<ConstantOrR1CSWitness>,
        (usize, usize, usize),
    )>,
    limb_bits: u32,
    window_size: usize,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    curve: &CurveParams,
) {
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
        // Constrain input infinity flag to 0 (affine coordinates cannot represent infinity)
        constrain_zero(compiler, point_wits[2]);
        let s_lo = scalar_wits[0];
        let s_hi = scalar_wits[1];

        // Decompose P into limbs
        let (px, py) = decompose_point_to_limbs(
            compiler,
            px_witness,
            py_witness,
            num_limbs,
            limb_bits,
            range_checks,
        );
        // R = ACIR output, decompose into limbs
        let (rx, ry) = decompose_point_to_limbs(
            compiler, out_x, out_y, num_limbs, limb_bits, range_checks,
        );

        (compiler, range_checks) = verify_point_fakeglv(
            compiler,
            range_checks,
            px,
            py,
            rx,
            ry,
            s_lo,
            s_hi,
            num_limbs,
            limb_bits,
            window_size,
            curve,
        );

        constrain_zero(compiler, out_inf);
    } else {
        // Multi-point: compute R_i = [s_i]P_i via hints, verify each with FakeGLV,
        // then accumulate R_i's and constrain against ACIR output.
        let mut acc: Option<(Limbs, Limbs)> = None;

        for i in 0..n_points {
            let px_witness = point_wits[3 * i];
            let py_witness = point_wits[3 * i + 1];
            // Constrain input infinity flag to 0 (affine coordinates cannot represent infinity)
            constrain_zero(compiler, point_wits[3 * i + 2]);
            let s_lo = scalar_wits[2 * i];
            let s_hi = scalar_wits[2 * i + 1];

            // Add EcScalarMulHint → R_i = [s_i]P_i
            let hint_start = compiler.num_witnesses();
            compiler.add_witness_builder(WitnessBuilder::EcScalarMulHint {
                output_start:    hint_start,
                px:              px_witness,
                py:              py_witness,
                s_lo,
                s_hi,
                curve_a:         curve.curve_a,
                field_modulus_p: curve.field_modulus_p,
            });
            let rx_witness = hint_start;
            let ry_witness = hint_start + 1;

            // Decompose P_i into limbs
            let (px, py) = decompose_point_to_limbs(
                compiler,
                px_witness,
                py_witness,
                num_limbs,
                limb_bits,
                range_checks,
            );
            // Decompose R_i into limbs
            let (rx, ry) = decompose_point_to_limbs(
                compiler,
                rx_witness,
                ry_witness,
                num_limbs,
                limb_bits,
                range_checks,
            );

            // Verify R_i = [s_i]P_i using FakeGLV
            (compiler, range_checks) = verify_point_fakeglv(
                compiler,
                range_checks,
                px,
                py,
                rx,
                ry,
                s_lo,
                s_hi,
                num_limbs,
                limb_bits,
                window_size,
                curve,
            );

            // Accumulate R_i via point_add
            acc = Some(match acc {
                None => (rx, ry),
                Some((ax, ay)) => {
                    let params = build_params(num_limbs, limb_bits, curve);
                    let mut ops = MultiLimbOps {
                        compiler,
                        range_checks,
                        params,
                    };
                    let sum = ec_points::point_add(&mut ops, ax, ay, rx, ry);
                    compiler = ops.compiler;
                    range_checks = ops.range_checks;
                    sum
                }
            });
        }

        let (computed_x, computed_y) = acc.expect("MSM must have at least one point");

        if num_limbs == 1 {
            constrain_equal(compiler, out_x, computed_x[0]);
            constrain_equal(compiler, out_y, computed_y[0]);
        } else {
            let recomposed_x = recompose_limbs(compiler, computed_x.as_slice(), limb_bits);
            let recomposed_y = recompose_limbs(compiler, computed_y.as_slice(), limb_bits);
            constrain_equal(compiler, out_x, recomposed_x);
            constrain_equal(compiler, out_y, recomposed_y);
        }
        constrain_zero(compiler, out_inf);
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
    // --- Step 1: On-curve checks for P and R ---
    {
        let params = build_params(num_limbs, limb_bits, curve);
        let mut ops = MultiLimbOps {
            compiler,
            range_checks,
            params,
        };

        let b_limb_values = curve::decompose_to_limbs(&curve.curve_b, limb_bits, num_limbs);

        verify_on_curve(&mut ops, px, py, &b_limb_values, num_limbs);
        verify_on_curve(&mut ops, rx, ry, &b_limb_values, num_limbs);

        compiler = ops.compiler;
        range_checks = ops.range_checks;
    }

    // --- Step 2: FakeGLVHint → |s1|, |s2|, neg1, neg2 ---
    let glv_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::FakeGLVHint {
        output_start: glv_start,
        s_lo,
        s_hi,
        curve_order: curve.curve_order_n,
    });
    let s1_witness = glv_start;
    let s2_witness = glv_start + 1;
    let neg1_witness = glv_start + 2;
    let neg2_witness = glv_start + 3;

    // neg1 and neg2 are constrained to be boolean by the `select` calls
    // in Step 4 below (MultiLimbOps::select calls constrain_boolean internally).

    // --- Step 3: Decompose |s1|, |s2| into half_bits bits each ---
    let half_bits = curve.glv_half_bits() as usize;
    let s1_bits = decompose_half_scalar_bits(compiler, s1_witness, half_bits);
    let s2_bits = decompose_half_scalar_bits(compiler, s2_witness, half_bits);

    // --- Step 4: Conditionally negate P.y and R.y + GLV scalar mul + identity check ---
    {
        let params = build_params(num_limbs, limb_bits, curve);
        let mut ops = MultiLimbOps {
            compiler,
            range_checks,
            params,
        };

        // Compute negated y-coordinates: neg_y = 0 - y (mod p)
        let zero_limbs = vec![FieldElement::from(0u64); num_limbs];
        let zero = ops.constant_limbs(&zero_limbs);

        let neg_py = ops.sub(zero, py);
        let neg_ry = ops.sub(zero, ry);

        // Select: if neg1=1, use neg_py; else use py
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

        // Identity check: acc should equal [2^(num_windows * window_size)] * offset_point
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
        modulus_bits: curve.curve_order_bits(),
        is_native: false, // always non-native
        modulus_fe,
    }
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
    // Use 64-bit limbs. Number of limbs covers the full curve order.
    let sr_limb_bits: u32 = 64;
    let order_bits = curve.curve_order_bits() as usize;
    let sr_num_limbs = (order_bits + sr_limb_bits as usize - 1) / sr_limb_bits as usize;
    let half_bits = curve.glv_half_bits() as usize;
    // Number of 64-bit limbs the half-scalar occupies
    let half_limbs = (half_bits + sr_limb_bits as usize - 1) / sr_limb_bits as usize;

    let params = build_scalar_relation_params(sr_num_limbs, sr_limb_bits, curve);
    let mut ops = MultiLimbOps {
        compiler,
        range_checks,
        params,
    };

    // Decompose s into sr_num_limbs × 64-bit limbs from (s_lo, s_hi)
    // s_lo contains bits [0..128), s_hi contains bits [128..256)
    let s_limbs = {
        let dd_lo = add_digital_decomposition(ops.compiler, vec![64, 64], vec![s_lo]);
        let dd_hi = add_digital_decomposition(ops.compiler, vec![64, 64], vec![s_hi]);
        let mut limbs = Limbs::new(sr_num_limbs);
        // s_lo provides limbs 0,1; s_hi provides limbs 2,3 (for sr_num_limbs=4)
        let lo_n = 2.min(sr_num_limbs);
        for i in 0..lo_n {
            limbs[i] = dd_lo.get_digit_witness_index(i, 0);
            ops.range_checks.entry(64).or_default().push(limbs[i]);
        }
        let hi_n = sr_num_limbs - lo_n;
        for i in 0..hi_n {
            limbs[lo_n + i] = dd_hi.get_digit_witness_index(i, 0);
            ops.range_checks
                .entry(64)
                .or_default()
                .push(limbs[lo_n + i]);
        }
        limbs
    };

    // Helper: decompose a half-scalar witness into sr_num_limbs × 64-bit limbs.
    // The half-scalar has `half_bits` bits → occupies `half_limbs` 64-bit limbs.
    // Upper limbs (half_limbs..sr_num_limbs) are zero-padded.
    let decompose_half_scalar = |ops: &mut MultiLimbOps, witness: usize| -> Limbs {
        let dd_bases: Vec<usize> = (0..half_limbs)
            .map(|i| {
                let remaining = half_bits as u32 - (i as u32 * 64);
                remaining.min(64) as usize
            })
            .collect();
        let dd = add_digital_decomposition(ops.compiler, dd_bases, vec![witness]);
        let mut limbs = Limbs::new(sr_num_limbs);
        for i in 0..half_limbs {
            limbs[i] = dd.get_digit_witness_index(i, 0);
            let remaining_bits = (half_bits as u32) - (i as u32 * 64);
            let this_limb_bits = remaining_bits.min(64);
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
    let zero_limbs_vals = vec![FieldElement::from(0u64); sr_num_limbs];
    let zero = ops.constant_limbs(&zero_limbs_vals);
    let neg_product = ops.sub(zero, product);
    // Select: if neg2=1, use neg_product; else use product
    let effective_product = ops.select(neg2_witness, product, neg_product);

    // If neg1 is set: neg_s1 = n - s1 (mod n), i.e. 0 - s1
    let neg_s1 = ops.sub(zero, s1_limbs);
    let effective_s1 = ops.select(neg1_witness, s1_limbs, neg_s1);

    // Sum: effective_s1 + effective_product (mod n) should be 0
    let sum = ops.add(effective_s1, effective_product);

    // Constrain sum == 0: all limbs must be zero
    for i in 0..sr_num_limbs {
        constrain_zero(ops.compiler, sum[i]);
    }
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
