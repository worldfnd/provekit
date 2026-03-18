//! `MultiLimbOps` — field and EC arithmetic parameterized by runtime limb
//! count.

use {
    super::{ec_points::EcOps, multi_limb_arith, EcPoint, Limbs},
    crate::{
        constraint_helpers::{constrain_boolean, select_witness},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::{AdditiveGroup, Field},
    provekit_common::{
        witness::{ConstantTerm, SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::{collections::BTreeMap, marker::PhantomData},
};

/// Shared modulus parameters for multi-limb field arithmetic.
///
/// Used by both EC operations (mod field_modulus_p) and scalar relations
/// (mod curve_order_n).
pub struct ModulusParams {
    pub num_limbs:       usize,
    pub limb_bits:       u32,
    pub p_limbs:         Vec<FieldElement>,
    pub p_minus_1_limbs: Vec<FieldElement>,
    pub two_pow_w:       FieldElement,
    pub modulus_raw:     [u64; 4],
}

/// EC-specific curve constants — only needed by EC point operations.
pub struct CurveEcParams {
    pub curve_a_limbs:     Vec<FieldElement>,
    pub curve_a_raw:       [u64; 4],
    pub curve_b_limbs:     Vec<FieldElement>,
    pub curve_b_raw:       [u64; 4],
    /// Pinned witness indices for curve_a constant limbs (allocated once).
    pub curve_a_witnesses: Vec<usize>,
    /// Pinned witness indices for curve_b constant limbs (allocated once).
    pub curve_b_witnesses: Vec<usize>,
}

/// Full parameters for EC field operations (modulus + curve constants).
///
/// Derefs to `ModulusParams` so modulus fields are accessible directly.
pub struct EcFieldParams {
    pub modulus: ModulusParams,
    pub ec:      CurveEcParams,
}

impl std::ops::Deref for EcFieldParams {
    type Target = ModulusParams;
    fn deref(&self) -> &ModulusParams {
        &self.modulus
    }
}

impl AsRef<ModulusParams> for ModulusParams {
    fn as_ref(&self) -> &ModulusParams {
        self
    }
}

impl AsRef<ModulusParams> for EcFieldParams {
    fn as_ref(&self) -> &ModulusParams {
        &self.modulus
    }
}

// ---------------------------------------------------------------------------
// FieldArith trait — strategy interface for field arithmetic dispatch
// ---------------------------------------------------------------------------

/// Strategy for constraining field arithmetic operations in the circuit.
pub trait FieldArith {
    fn field_add(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &ModulusParams,
        a: Limbs,
        b: Limbs,
    ) -> Limbs;

    fn field_sub(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &ModulusParams,
        a: Limbs,
        b: Limbs,
    ) -> Limbs;

    fn field_mul(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &ModulusParams,
        a: Limbs,
        b: Limbs,
    ) -> Limbs;

    fn field_negate(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &ModulusParams,
        value: Limbs,
    ) -> Limbs;
}

// ---------------------------------------------------------------------------
// NativeSingleField — native R1CS arithmetic (num_limbs=1)
// ---------------------------------------------------------------------------

/// Native-field arithmetic: single-limb R1CS add/sub/mul/negate.
pub struct NativeSingleField;

impl FieldArith for NativeSingleField {
    fn field_add(
        compiler: &mut NoirToR1CSCompiler,
        _range_checks: &mut BTreeMap<u32, Vec<usize>>,
        _params: &ModulusParams,
        a: Limbs,
        b: Limbs,
    ) -> Limbs {
        let r = if a[0] == b[0] {
            compiler.add_sum(vec![SumTerm(Some(FieldElement::from(2u64)), a[0])])
        } else {
            compiler.add_sum(vec![SumTerm(None, a[0]), SumTerm(None, b[0])])
        };
        Limbs::single(r)
    }

    fn field_sub(
        compiler: &mut NoirToR1CSCompiler,
        _range_checks: &mut BTreeMap<u32, Vec<usize>>,
        _params: &ModulusParams,
        a: Limbs,
        b: Limbs,
    ) -> Limbs {
        let r = if a[0] == b[0] {
            compiler.add_sum(vec![SumTerm(Some(FieldElement::ZERO), a[0])])
        } else {
            compiler.add_sum(vec![
                SumTerm(None, a[0]),
                SumTerm(Some(-FieldElement::ONE), b[0]),
            ])
        };
        Limbs::single(r)
    }

    fn field_mul(
        compiler: &mut NoirToR1CSCompiler,
        _range_checks: &mut BTreeMap<u32, Vec<usize>>,
        _params: &ModulusParams,
        a: Limbs,
        b: Limbs,
    ) -> Limbs {
        let r = compiler.add_product(a[0], b[0]);
        Limbs::single(r)
    }

    fn field_negate(
        compiler: &mut NoirToR1CSCompiler,
        _range_checks: &mut BTreeMap<u32, Vec<usize>>,
        _params: &ModulusParams,
        value: Limbs,
    ) -> Limbs {
        let r = compiler.add_sum(vec![SumTerm(Some(-FieldElement::ONE), value[0])]);
        Limbs::single(r)
    }
}

// ---------------------------------------------------------------------------
// MultiLimbField — schoolbook multi-limb arithmetic (num_limbs≥2)
// ---------------------------------------------------------------------------

/// Multi-limb field arithmetic: schoolbook add/sub/mul/negate with carry
/// chains.
pub struct MultiLimbField;

impl FieldArith for MultiLimbField {
    fn field_add(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &ModulusParams,
        a: Limbs,
        b: Limbs,
    ) -> Limbs {
        multi_limb_arith::add_mod_p_multi(compiler, range_checks, a, b, params)
    }

    fn field_sub(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &ModulusParams,
        a: Limbs,
        b: Limbs,
    ) -> Limbs {
        multi_limb_arith::sub_mod_p_multi(compiler, range_checks, a, b, params)
    }

    fn field_mul(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &ModulusParams,
        a: Limbs,
        b: Limbs,
    ) -> Limbs {
        multi_limb_arith::mul_mod_p_multi(compiler, range_checks, a, b, params)
    }

    fn field_negate(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &ModulusParams,
        value: Limbs,
    ) -> Limbs {
        multi_limb_arith::negate_mod_p_multi(compiler, range_checks, value, params)
    }
}

impl ModulusParams {
    /// Build params for scalar relation verification (mod curve_order_n).
    pub fn for_curve_order<C: super::curve::Curve>(
        num_limbs: usize,
        limb_bits: u32,
        curve: &C,
    ) -> Self {
        let two_pow_w = FieldElement::from(2u64).pow([limb_bits as u64]);
        Self {
            num_limbs,
            limb_bits,
            p_limbs: curve.curve_order_n_limbs(limb_bits, num_limbs),
            p_minus_1_limbs: curve.curve_order_n_minus_1_limbs(limb_bits, num_limbs),
            two_pow_w,
            modulus_raw: curve.curve_order_n(),
        }
    }
}

impl EcFieldParams {
    /// Build params for EC field operations (mod field_modulus_p).
    pub fn for_field_modulus<C: super::curve::Curve>(
        num_limbs: usize,
        limb_bits: u32,
        curve: &C,
    ) -> Self {
        let two_pow_w = FieldElement::from(2u64).pow([limb_bits as u64]);
        Self {
            modulus: ModulusParams {
                num_limbs,
                limb_bits,
                p_limbs: curve.p_limbs(limb_bits, num_limbs),
                p_minus_1_limbs: curve.p_minus_1_limbs(limb_bits, num_limbs),
                two_pow_w,
                modulus_raw: curve.field_modulus_p(),
            },
            ec:      CurveEcParams {
                curve_a_limbs:     curve.curve_a_limbs(limb_bits, num_limbs),
                curve_a_raw:       curve.curve_a(),
                curve_b_limbs:     curve.curve_b_limbs(limb_bits, num_limbs),
                curve_b_raw:       curve.curve_b(),
                curve_a_witnesses: Vec::new(),
                curve_b_witnesses: Vec::new(),
            },
        }
    }

    /// Allocate pinned constant witnesses for curve_a and curve_b limbs.
    ///
    /// Must be called once before any EC operations.
    pub fn allocate_curve_constant_witnesses(&mut self, compiler: &mut NoirToR1CSCompiler) {
        self.ec.curve_a_witnesses =
            allocate_pinned_constant_limbs(compiler, &self.ec.curve_a_limbs);
        self.ec.curve_b_witnesses =
            allocate_pinned_constant_limbs(compiler, &self.ec.curve_b_limbs);
    }
}

/// Allocate a pinned constant witness embedded in the constraint matrix.
#[must_use]
pub fn allocate_pinned_constant(compiler: &mut NoirToR1CSCompiler, value: FieldElement) -> usize {
    let w = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::Constant(ConstantTerm(w, value)));
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, w)],
        &[(value, compiler.witness_one())],
    );
    w
}

/// Allocate pinned constant witnesses from pre-decomposed `FieldElement` limbs.
pub fn allocate_pinned_constant_limbs(
    compiler: &mut NoirToR1CSCompiler,
    limb_values: &[FieldElement],
) -> Vec<usize> {
    limb_values
        .iter()
        .map(|&val| allocate_pinned_constant(compiler, val))
        .collect()
}

/// Unified field + EC operations struct, parameterized by:
/// - `F`: field arithmetic strategy (`FieldArith`)
/// - `E`: EC point arithmetic strategy (`EcOps`) — `()` when EC ops not needed
/// - `P`: params type — `ModulusParams` for field-only, `EcFieldParams` for EC
pub struct MultiLimbOps<'a, 'p, F, E = (), P: AsRef<ModulusParams> = ModulusParams> {
    pub(in crate::msm) compiler: &'a mut NoirToR1CSCompiler,
    pub(in crate::msm) range_checks: &'a mut BTreeMap<u32, Vec<usize>>,
    pub params: &'p P,
    _field: PhantomData<(F, E)>,
}

// -----------------------------------------------------------------
// Helper methods — available for any F (no trait bound required)
// -----------------------------------------------------------------

impl<'a, 'p, F, E, P: AsRef<ModulusParams>> MultiLimbOps<'a, 'p, F, E, P> {
    /// Construct a new `MultiLimbOps`.
    pub fn new(
        compiler: &'a mut NoirToR1CSCompiler,
        range_checks: &'a mut BTreeMap<u32, Vec<usize>>,
        params: &'p P,
    ) -> Self {
        Self {
            compiler,
            range_checks,
            params,
            _field: PhantomData,
        }
    }

    /// Access the modulus parameters.
    fn m(&self) -> &ModulusParams {
        self.params.as_ref()
    }

    fn n(&self) -> usize {
        self.m().num_limbs
    }

    /// Returns the witness index for the constant-one wire.
    #[must_use]
    pub fn witness_one(&self) -> usize {
        self.compiler.witness_one()
    }

    /// Returns the current number of allocated witnesses.
    #[must_use]
    pub fn num_witnesses(&self) -> usize {
        self.compiler.num_witnesses()
    }

    /// Allocates a product witness: `out = a * b`.
    #[must_use]
    pub fn product(&mut self, a: usize, b: usize) -> usize {
        self.compiler.add_product(a, b)
    }

    /// Allocates a linear combination witness: `out = Σ terms`.
    #[must_use]
    pub fn sum(&mut self, terms: Vec<SumTerm>) -> usize {
        self.compiler.add_sum(terms)
    }

    /// Registers a witness builder for deferred witness solving.
    pub fn add_witness_builder(&mut self, builder: WitnessBuilder) {
        self.compiler.add_witness_builder(builder);
    }

    /// Registers a range check: `witness` must fit in `bits` bits.
    pub fn register_range_check(&mut self, bits: u32, witness: usize) {
        self.range_checks.entry(bits).or_default().push(witness);
    }

    /// Constrains `flag` to be boolean (`flag * flag = flag`).
    pub fn constrain_flag(&mut self, flag: usize) {
        constrain_boolean(self.compiler, flag);
    }

    /// Conditional select without boolean constraint on `flag`.
    /// Caller must ensure `flag` is already constrained boolean.
    #[must_use]
    pub fn select_unchecked(&mut self, flag: usize, on_false: Limbs, on_true: Limbs) -> Limbs {
        let n = self.n();
        let mut out = Limbs::new();
        for i in 0..n {
            out.push(select_witness(self.compiler, flag, on_false[i], on_true[i]));
        }
        out
    }

    /// Conditional select: returns `on_true` if `flag` is 1, `on_false` if
    /// `flag` is 0. Constrains `flag` to be boolean.
    #[must_use]
    pub fn select(&mut self, flag: usize, on_false: Limbs, on_true: Limbs) -> Limbs {
        self.constrain_flag(flag);
        self.select_unchecked(flag, on_false, on_true)
    }

    /// Conditional point select without boolean constraint on `flag`.
    /// Returns `on_true` if `flag=1`, `on_false` if `flag=0`.
    /// Caller must ensure `flag` is already constrained boolean.
    #[must_use]
    pub fn point_select_unchecked(
        &mut self,
        flag: usize,
        on_false: EcPoint,
        on_true: EcPoint,
    ) -> EcPoint {
        EcPoint {
            x: self.select_unchecked(flag, on_false.x, on_true.x),
            y: self.select_unchecked(flag, on_false.y, on_true.y),
        }
    }

    /// Returns a constant field element from its limb decomposition.
    #[must_use]
    pub fn constant_limbs(&mut self, limbs: &[FieldElement]) -> Limbs {
        let n = self.n();
        assert_eq!(
            limbs.len(),
            n,
            "constant_limbs: expected {n} limbs, got {}",
            limbs.len()
        );
        Limbs::from(allocate_pinned_constant_limbs(self.compiler, limbs).as_slice())
    }
}

// -----------------------------------------------------------------
// Field arithmetic — available when F: FieldArith
// -----------------------------------------------------------------

impl<F: FieldArith, E, P: AsRef<ModulusParams>> MultiLimbOps<'_, '_, F, E, P> {
    /// Negate a multi-limb value: computes `p - value (mod p)`.
    #[must_use]
    pub fn negate(&mut self, value: Limbs) -> Limbs {
        F::field_negate(
            self.compiler,
            self.range_checks,
            self.params.as_ref(),
            value,
        )
    }

    #[must_use]
    pub fn add(&mut self, a: Limbs, b: Limbs) -> Limbs {
        assert_eq!(a.len(), self.n(), "add: a.len() != num_limbs");
        assert_eq!(b.len(), self.n(), "add: b.len() != num_limbs");
        F::field_add(self.compiler, self.range_checks, self.params.as_ref(), a, b)
    }

    #[must_use]
    pub fn sub(&mut self, a: Limbs, b: Limbs) -> Limbs {
        assert_eq!(a.len(), self.n(), "sub: a.len() != num_limbs");
        assert_eq!(b.len(), self.n(), "sub: b.len() != num_limbs");
        F::field_sub(self.compiler, self.range_checks, self.params.as_ref(), a, b)
    }

    #[must_use]
    pub fn mul(&mut self, a: Limbs, b: Limbs) -> Limbs {
        assert_eq!(a.len(), self.n(), "mul: a.len() != num_limbs");
        assert_eq!(b.len(), self.n(), "mul: b.len() != num_limbs");
        F::field_mul(self.compiler, self.range_checks, self.params.as_ref(), a, b)
    }
}

// -----------------------------------------------------------------
// EC point operations — available when E: EcOps, P = EcFieldParams
// -----------------------------------------------------------------

impl<F, E: EcOps> MultiLimbOps<'_, '_, F, E, EcFieldParams> {
    /// Point doubling: computes 2P.
    #[must_use]
    pub fn point_double(&mut self, p: EcPoint) -> EcPoint {
        E::point_double(self.compiler, self.range_checks, self.params, p)
    }

    /// Point addition: computes P1 + P2 (requires P1 ≠ ±P2).
    #[must_use]
    pub fn point_add(&mut self, p1: EcPoint, p2: EcPoint) -> EcPoint {
        E::point_add(self.compiler, self.range_checks, self.params, p1, p2)
    }

    /// On-curve verification: constrains y² = x³ + ax + b.
    pub fn verify_on_curve(&mut self, p: EcPoint) {
        E::verify_on_curve(self.compiler, self.range_checks, self.params, p);
    }
}
