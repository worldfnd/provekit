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
    curve::CurveParams,
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

    /// Checks if a field element (in the curve's base field) is zero.
    /// Returns a boolean witness: 1 if zero, 0 if non-zero.
    fn elem_is_zero(&mut self, value: Self::Elem) -> usize;

    /// Returns the constant field element 1.
    fn constant_one(&mut self) -> Self::Elem;

    /// Computes a * b for two boolean (0/1) native witnesses.
    /// Used for boolean AND on flags in scalar_mul.
    fn bool_and(&mut self, a: usize, b: usize) -> usize;
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
/// Handles coordinate decomposition, scalar_mul, accumulation, and
/// output constraining.
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
    let mut acc: Option<(Limbs, Limbs)> = None;

    for i in 0..n_points {
        let px_witness = point_wits[3 * i];
        let py_witness = point_wits[3 * i + 1];

        let s_lo = scalar_wits[2 * i];
        let s_hi = scalar_wits[2 * i + 1];
        let scalar_bits = decompose_scalar_bits(compiler, s_lo, s_hi);

        // Build coordinates as Limbs
        let (px, py) = if num_limbs == 1 {
            // Single-limb: wrap witness directly
            (Limbs::single(px_witness), Limbs::single(py_witness))
        } else {
            // Multi-limb: decompose single witness into num_limbs limbs
            let px_limbs = decompose_witness_to_limbs(
                compiler,
                px_witness,
                limb_bits,
                num_limbs,
                range_checks,
            );
            let py_limbs = decompose_witness_to_limbs(
                compiler,
                py_witness,
                limb_bits,
                num_limbs,
                range_checks,
            );
            (px_limbs, py_limbs)
        };

        let params = build_params(num_limbs, limb_bits, curve);
        let mut ops = MultiLimbOps {
            compiler,
            range_checks,
            params,
        };
        let result = ec_points::scalar_mul(&mut ops, px, py, &scalar_bits, window_size);
        compiler = ops.compiler;
        range_checks = ops.range_checks;

        acc = Some(match acc {
            None => result,
            Some((ax, ay)) => {
                let params = build_params(num_limbs, limb_bits, curve);
                let mut ops = MultiLimbOps {
                    compiler,
                    range_checks,
                    params,
                };
                let sum = ec_points::point_add(&mut ops, ax, ay, result.0, result.1);
                compiler = ops.compiler;
                range_checks = ops.range_checks;
                sum
            }
        });
    }

    let (computed_x, computed_y) = acc.expect("MSM must have at least one point");
    let (out_x, out_y, out_inf) = outputs;

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

/// Decomposes a scalar given as two 128-bit limbs into 256 bit witnesses (LSB
/// first).
fn decompose_scalar_bits(
    compiler: &mut NoirToR1CSCompiler,
    s_lo: usize,
    s_hi: usize,
) -> Vec<usize> {
    let log_bases_128 = vec![1usize; 128];

    let dd_lo = add_digital_decomposition(compiler, log_bases_128.clone(), vec![s_lo]);
    let dd_hi = add_digital_decomposition(compiler, log_bases_128, vec![s_hi]);

    let mut bits = Vec::with_capacity(256);
    for bit_idx in 0..128 {
        bits.push(dd_lo.get_digit_witness_index(bit_idx, 0));
    }
    for bit_idx in 0..128 {
        bits.push(dd_hi.get_digit_witness_index(bit_idx, 0));
    }
    bits
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
