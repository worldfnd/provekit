pub mod cost_model;
pub mod curve;
pub mod ec_points;
pub mod multi_limb_arith;
pub mod multi_limb_ops;
mod native;
mod non_native;
mod scalar_relation;

use {
    crate::{msm::multi_limb_arith::compute_is_zero, noir_to_r1cs::NoirToR1CSCompiler},
    ark_ff::{AdditiveGroup, Field, PrimeField},
    curve::CurveParams,
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
fn compute_boolean_or(compiler: &mut NoirToR1CSCompiler, a: usize, b: usize) -> usize {
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

/// Sanitized point-scalar inputs after degenerate-case detection.
struct SanitizedInputs {
    px:      usize,
    py:      usize,
    s_lo:    usize,
    s_hi:    usize,
    is_skip: usize,
}

/// Detects degenerate cases (scalar=0 or point at infinity) and replaces
/// the point with the generator G and scalar with 1 when degenerate.
fn sanitize_point_scalar(
    compiler: &mut NoirToR1CSCompiler,
    px: usize,
    py: usize,
    s_lo: usize,
    s_hi: usize,
    inf_flag: usize,
    gen_x: usize,
    gen_y: usize,
    zero: usize,
    one: usize,
) -> SanitizedInputs {
    let is_skip = detect_skip(compiler, s_lo, s_hi, inf_flag);
    SanitizedInputs {
        px: select_witness(compiler, is_skip, px, gen_x),
        py: select_witness(compiler, is_skip, py, gen_y),
        s_lo: select_witness(compiler, is_skip, s_lo, one),
        s_hi: select_witness(compiler, is_skip, s_hi, zero),
        is_skip,
    }
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

/// Negate a y-coordinate and conditionally select based on a sign flag.
/// Returns `(y_eff, neg_y_eff)` where:
///   - if `neg_flag=0`: `y_eff = y`,     `neg_y_eff = -y`
///   - if `neg_flag=1`: `y_eff = -y`,    `neg_y_eff = y`
fn negate_y_signed_native(
    compiler: &mut NoirToR1CSCompiler,
    neg_flag: usize,
    y: usize,
) -> (usize, usize) {
    constrain_boolean(compiler, neg_flag);
    let neg_y = compiler.add_sum(vec![SumTerm(Some(-FieldElement::ONE), y)]);
    let y_eff = select_witness(compiler, neg_flag, y, neg_y);
    let neg_y_eff = select_witness(compiler, neg_flag, neg_y, y);
    (y_eff, neg_y_eff)
}

/// Emit an `EcScalarMulHint` and sanitize the result point.
/// When `is_skip=1`, the result is swapped to the generator point.
fn emit_ec_scalar_mul_hint_and_sanitize(
    compiler: &mut NoirToR1CSCompiler,
    san: &SanitizedInputs,
    gen_x_witness: usize,
    gen_y_witness: usize,
    curve: &CurveParams,
) -> (usize, usize) {
    let hint_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::EcScalarMulHint {
        output_start:    hint_start,
        px:              san.px,
        py:              san.py,
        s_lo:            san.s_lo,
        s_hi:            san.s_hi,
        curve_a:         curve.curve_a,
        field_modulus_p: curve.field_modulus_p,
    });
    let rx = select_witness(compiler, san.is_skip, hint_start, gen_x_witness);
    let ry = select_witness(compiler, san.is_skip, hint_start + 1, gen_y_witness);
    (rx, ry)
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
    let is_native = curve.is_native_field();
    let n_points: usize = msm_ops.iter().map(|(pts, ..)| pts.len() / 3).sum();
    let (limb_bits, window_size) =
        cost_model::get_optimal_msm_params(native_bits, curve_bits, n_points, 256, is_native);

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
/// Dispatches to single-point or multi-point path based on the number of
/// input points.
fn process_single_msm(
    compiler: &mut NoirToR1CSCompiler,
    point_wits: &[usize],
    scalar_wits: &[usize],
    outputs: (usize, usize, usize),
    num_limbs: usize,
    limb_bits: u32,
    window_size: usize,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    curve: &CurveParams,
) {
    let n_points = point_wits.len() / 3;
    if n_points == 1 {
        process_single_point_msm(
            compiler,
            point_wits,
            scalar_wits,
            outputs,
            num_limbs,
            limb_bits,
            window_size,
            range_checks,
            curve,
        );
    } else {
        process_multi_point_msm(
            compiler,
            point_wits,
            scalar_wits,
            outputs,
            n_points,
            num_limbs,
            limb_bits,
            window_size,
            range_checks,
            curve,
        );
    }
}

/// Single-point MSM: R = [s]P with degenerate-case handling.
///
/// The ACIR output (out_x, out_y) is the result directly. Sanitizes inputs
/// to handle scalar=0 and point-at-infinity, then verifies via FakeGLV.
fn process_single_point_msm<'a>(
    mut compiler: &'a mut NoirToR1CSCompiler,
    point_wits: &[usize],
    scalar_wits: &[usize],
    outputs: (usize, usize, usize),
    num_limbs: usize,
    limb_bits: u32,
    window_size: usize,
    range_checks: &'a mut BTreeMap<u32, Vec<usize>>,
    curve: &CurveParams,
) {
    let (out_x, out_y, out_inf) = outputs;

    // Allocate constants
    let one = compiler.witness_one();
    let gen_x_witness =
        add_constant_witness(compiler, curve::curve_native_point_fe(&curve.generator.0));
    let gen_y_witness =
        add_constant_witness(compiler, curve::curve_native_point_fe(&curve.generator.1));
    let zero_witness = add_constant_witness(compiler, FieldElement::ZERO);

    // Sanitize inputs: swap in generator G and scalar=1 when degenerate
    let san = sanitize_point_scalar(
        compiler,
        point_wits[0],
        point_wits[1],
        scalar_wits[0],
        scalar_wits[1],
        point_wits[2],
        gen_x_witness,
        gen_y_witness,
        zero_witness,
        one,
    );

    // Sanitize R (output point): when is_skip=1, R must be G (since [1]*G = G)
    let sanitized_rx = select_witness(compiler, san.is_skip, out_x, gen_x_witness);
    let sanitized_ry = select_witness(compiler, san.is_skip, out_y, gen_y_witness);

    if curve.is_native_field() {
        // Native-field optimized path: hint-verified EC + wNAF
        native::verify_point_fakeglv_native(
            compiler,
            range_checks,
            san.px,
            san.py,
            sanitized_rx,
            sanitized_ry,
            san.s_lo,
            san.s_hi,
            curve,
        );
    } else {
        // Generic multi-limb path
        let (px, py) = non_native::decompose_point_to_limbs(
            compiler,
            san.px,
            san.py,
            num_limbs,
            limb_bits,
            range_checks,
        );
        let (rx, ry) = non_native::decompose_point_to_limbs(
            compiler,
            sanitized_rx,
            sanitized_ry,
            num_limbs,
            limb_bits,
            range_checks,
        );
        (compiler, _) = non_native::verify_point_fakeglv(
            compiler,
            range_checks,
            px,
            py,
            rx,
            ry,
            san.s_lo,
            san.s_hi,
            num_limbs,
            limb_bits,
            window_size,
            curve,
        );
    }

    // Mask output: when is_skip, output must be (0, 0, 1)
    constrain_equal(compiler, out_inf, san.is_skip);
    constrain_product_zero(compiler, san.is_skip, out_x);
    constrain_product_zero(compiler, san.is_skip, out_y);
}

/// Multi-point MSM: computes R_i = [s_i]P_i via hints, verifies each with
/// FakeGLV, then accumulates R_i's with offset-based accumulation and skip
/// handling.
///
/// When `curve.is_native_field()`, uses a merged-loop optimization: all
/// points share a single doubling per bit, saving 4*(n-1) constraints per
/// bit of the half-scalar (≈512 for 2 points on Grumpkin).
fn process_multi_point_msm(
    compiler: &mut NoirToR1CSCompiler,
    point_wits: &[usize],
    scalar_wits: &[usize],
    outputs: (usize, usize, usize),
    n_points: usize,
    num_limbs: usize,
    limb_bits: u32,
    window_size: usize,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    curve: &CurveParams,
) {
    if curve.is_native_field() {
        native::process_multi_point_native(
            compiler,
            point_wits,
            scalar_wits,
            outputs,
            n_points,
            range_checks,
            curve,
        );
        return;
    }

    non_native::process_multi_point_non_native(
        compiler,
        point_wits,
        scalar_wits,
        outputs,
        n_points,
        num_limbs,
        limb_bits,
        window_size,
        range_checks,
        curve,
    );
}

/// Allocates a FakeGLV hint and returns `(s1, s2, neg1, neg2)` witness indices.
fn emit_fakeglv_hint(
    compiler: &mut NoirToR1CSCompiler,
    s_lo: usize,
    s_hi: usize,
    curve: &CurveParams,
) -> (usize, usize, usize, usize) {
    let glv_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::FakeGLVHint {
        output_start: glv_start,
        s_lo,
        s_hi,
        curve_order: curve.curve_order_n,
    });
    (glv_start, glv_start + 1, glv_start + 2, glv_start + 3)
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

/// Creates a constant witness with the given value, pinned by an R1CS
/// constraint so that a malicious prover cannot set it to an arbitrary value.
fn add_constant_witness(compiler: &mut NoirToR1CSCompiler, value: FieldElement) -> usize {
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
fn constrain_to_constant(compiler: &mut NoirToR1CSCompiler, witness: usize, value: FieldElement) {
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, witness)],
        &[(value, compiler.witness_one())],
    );
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
