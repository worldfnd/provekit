pub(crate) mod cost_model;
pub(crate) mod curve;
pub(crate) mod ec_points;
pub(crate) mod multi_limb_arith;
pub(crate) mod multi_limb_ops;
mod native;
mod non_native;
mod sanitize;
mod scalar_relation;
#[cfg(test)]
mod tests;

// Re-export sanitize helpers so submodules (native, non_native) can use
// `super::sanitize_point_scalar` etc.
use {
    crate::{constraint_helpers::add_constant_witness, noir_to_r1cs::NoirToR1CSCompiler},
    ark_ff::PrimeField,
    curve::CurveParams,
    provekit_common::witness::ConstantOrR1CSWitness,
    sanitize::{
        decompose_signed_bits, emit_ec_scalar_mul_hint_and_sanitize, emit_fakeglv_hint,
        negate_y_signed_native, sanitize_point_scalar,
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

    let native_bits = provekit_common::FieldElement::MODULUS_BIT_SIZE;
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
