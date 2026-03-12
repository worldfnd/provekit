pub(crate) mod cost_model;
pub(crate) mod curve;
pub(crate) mod ec_points;
pub(crate) mod multi_limb_arith;
pub(crate) mod multi_limb_ops;
mod native;
mod non_native;
mod scalar_relation;

use {
    crate::{
        constraint_helpers::{
            add_constant_witness, compute_boolean_or, constrain_boolean, select_witness,
        },
        msm::multi_limb_arith::compute_is_zero,
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::{AdditiveGroup, Field, PrimeField},
    curve::CurveParams,
    provekit_common::{
        witness::{ConstantOrR1CSWitness, SumTerm, WitnessBuilder},
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
/// This type is `Copy`, so it can be passed by value without requiring
/// const generics or dispatch macros. The runtime `len` field tracks how
/// many limbs are actually in use.
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
// Private helpers (MSM-specific)
// ---------------------------------------------------------------------------

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

    let n_points = point_wits.len() / 3;
    if curve.is_native_field() {
        native::process_multi_point_native(
            compiler,
            &point_wits,
            &scalar_wits,
            outputs,
            n_points,
            range_checks,
            curve,
        );
    } else {
        non_native::process_multi_point_non_native(
            compiler,
            &point_wits,
            &scalar_wits,
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

/// Signed-bit decomposition for wNAF scalar multiplication.
///
/// Decomposes `scalar` into `num_bits` sign-bits b_i ∈ {0,1} and a skew ∈ {0,1}
/// such that the signed digits d_i = 2*b_i - 1 ∈ {-1, +1} satisfy:
///   scalar = Σ d_i * 2^i - skew
///
/// Reconstruction constraint (1 linear R1CS):
///   scalar + skew + (2^n - 1) = Σ b_i * 2^{i+1}
///
/// All bits and skew are boolean-constrained.
///
/// # Limitation
/// The prover's `SignedBitHint` solver reads the scalar as a `u128` (lower
/// 128 bits of the field element). This is correct for FakeGLV half-scalars
/// (≤128 bits for 256-bit curves) but would silently truncate if `num_bits`
/// exceeds 128. The R1CS reconstruction constraint would then fail.
pub(super) fn decompose_signed_bits(
    compiler: &mut NoirToR1CSCompiler,
    scalar: usize,
    num_bits: usize,
) -> (Vec<usize>, usize) {
    let start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::SignedBitHint {
        output_start: start,
        scalar,
        num_bits,
    });
    let bits: Vec<usize> = (start..start + num_bits).collect();
    let skew = start + num_bits;

    // Boolean-constrain each bit and skew
    for &b in &bits {
        constrain_boolean(compiler, b);
    }
    constrain_boolean(compiler, skew);

    // Reconstruction: scalar + skew + (2^n - 1) = Σ b_i * 2^{i+1}
    // Rearranged as: scalar + skew + (2^n - 1) - Σ b_i * 2^{i+1} = 0
    let one = compiler.witness_one();
    let two = FieldElement::from(2u64);
    let constant = two.pow([num_bits as u64]) - FieldElement::ONE;
    let mut b_terms: Vec<(FieldElement, usize)> = bits
        .iter()
        .enumerate()
        .map(|(i, &b)| (-two.pow([(i + 1) as u64]), b))
        .collect();
    b_terms.push((FieldElement::ONE, scalar));
    b_terms.push((FieldElement::ONE, skew));
    b_terms.push((constant, one));
    compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, one)], &b_terms, &[(
            FieldElement::ZERO,
            one,
        )]);

    (bits, skew)
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

#[cfg(test)]
mod tests {
    use {super::*, crate::noir_to_r1cs::NoirToR1CSCompiler};

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
}
