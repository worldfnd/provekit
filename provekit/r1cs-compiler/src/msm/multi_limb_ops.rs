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

/// Parameters for multi-limb field arithmetic.
pub struct MultiLimbParams {
    pub num_limbs:       usize,
    pub limb_bits:       u32,
    pub p_limbs:         Vec<FieldElement>,
    pub p_minus_1_limbs: Vec<FieldElement>,
    pub two_pow_w:       FieldElement,
    pub modulus_raw:     [u64; 4],
    pub curve_a_limbs:   Vec<FieldElement>,
    /// Raw curve_a value as [u64; 4] for hint-verified EC ops
    pub curve_a_raw:     [u64; 4],
    pub curve_b_limbs:   Vec<FieldElement>,
    /// Raw curve_b value as [u64; 4] for hint-verified on-curve checks
    pub curve_b_raw:     [u64; 4],
    /// p = native field → skip mod reduction
    pub is_native:       bool,
    /// For N=1 non-native: the modulus as a single FieldElement
    pub modulus_fe:      Option<FieldElement>,
}

impl MultiLimbParams {
    /// Build params for EC field operations (mod field_modulus_p).
    pub fn for_field_modulus<C: super::curve::Curve>(
        num_limbs: usize,
        limb_bits: u32,
        curve: &C,
    ) -> Self {
        let is_native = curve.is_native_field();
        let two_pow_w = FieldElement::from(2u64).pow([limb_bits as u64]);
        let modulus_fe = if !is_native {
            Some(curve.p_native_fe())
        } else {
            None
        };
        Self {
            num_limbs,
            limb_bits,
            p_limbs: curve.p_limbs(limb_bits, num_limbs),
            p_minus_1_limbs: curve.p_minus_1_limbs(limb_bits, num_limbs),
            two_pow_w,
            modulus_raw: curve.field_modulus_p(),
            curve_a_limbs: curve.curve_a_limbs(limb_bits, num_limbs),
            curve_a_raw: curve.curve_a(),
            curve_b_limbs: curve.curve_b_limbs(limb_bits, num_limbs),
            curve_b_raw: curve.curve_b(),
            is_native,
            modulus_fe,
        }
    }

    /// Build params for scalar relation verification (mod curve_order_n).
    pub fn for_curve_order<C: super::curve::Curve>(
        num_limbs: usize,
        limb_bits: u32,
        curve: &C,
    ) -> Self {
        let two_pow_w = FieldElement::from(2u64).pow([limb_bits as u64]);
        let modulus_fe = if num_limbs == 1 {
            Some(super::curve::curve_native_point_fe(&curve.curve_order_n()))
        } else {
            None
        };
        Self {
            num_limbs,
            limb_bits,
            p_limbs: curve.curve_order_n_limbs(limb_bits, num_limbs),
            p_minus_1_limbs: curve.curve_order_n_minus_1_limbs(limb_bits, num_limbs),
            two_pow_w,
            modulus_raw: curve.curve_order_n(),
            curve_a_limbs: vec![FieldElement::ZERO; num_limbs], // unused
            curve_a_raw: [0u64; 4],                             // unused for scalar relation
            curve_b_limbs: vec![FieldElement::ZERO; num_limbs], // unused
            curve_b_raw: [0u64; 4],                             // unused for scalar relation
            is_native: false,                                   /* always non-native for
                                                                 * scalar relation */
            modulus_fe,
        }
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

/// Unified field + EC operations struct.
pub struct MultiLimbOps<'a, 'p, E> {
    pub(in crate::msm) compiler: &'a mut NoirToR1CSCompiler,
    pub(in crate::msm) range_checks: &'a mut BTreeMap<u32, Vec<usize>>,
    pub params: &'p MultiLimbParams,
    _ec: PhantomData<E>,
}

impl<'a, 'p, E> MultiLimbOps<'a, 'p, E> {
    /// Construct a new `MultiLimbOps`.
    pub fn new(
        compiler: &'a mut NoirToR1CSCompiler,
        range_checks: &'a mut BTreeMap<u32, Vec<usize>>,
        params: &'p MultiLimbParams,
    ) -> Self {
        Self {
            compiler,
            range_checks,
            params,
            _ec: PhantomData,
        }
    }

    fn is_native_single(&self) -> bool {
        self.params.num_limbs == 1 && self.params.is_native
    }

    fn is_non_native_single(&self) -> bool {
        self.params.num_limbs == 1 && !self.params.is_native
    }

    fn n(&self) -> usize {
        self.params.num_limbs
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

    /// Negate a multi-limb value: computes `p - value (mod p)`.
    #[must_use]
    pub fn negate(&mut self, value: Limbs) -> Limbs {
        if self.is_native_single() {
            // Native: single linear combination
            let r = self
                .compiler
                .add_sum(vec![SumTerm(Some(-FieldElement::ONE), value[0])]);
            Limbs::single(r)
        } else if self.params.num_limbs >= 2 && !self.params.is_native {
            multi_limb_arith::negate_mod_p_multi(
                self.compiler,
                self.range_checks,
                value,
                &self.params.p_limbs,
                self.params.two_pow_w,
                self.params.limb_bits,
            )
        } else {
            let zero_vals = vec![FieldElement::ZERO; self.params.num_limbs];
            let zero = self.constant_limbs(&zero_vals);
            self.sub(zero, value)
        }
    }

    #[must_use]
    pub fn add(&mut self, a: Limbs, b: Limbs) -> Limbs {
        assert_eq!(a.len(), self.n(), "add: a.len() != num_limbs");
        assert_eq!(b.len(), self.n(), "add: b.len() != num_limbs");
        if self.is_native_single() {
            // Merge duplicate witness into single term to avoid duplicate column indices.
            let r = if a[0] == b[0] {
                self.compiler
                    .add_sum(vec![SumTerm(Some(FieldElement::from(2u64)), a[0])])
            } else {
                self.compiler
                    .add_sum(vec![SumTerm(None, a[0]), SumTerm(None, b[0])])
            };
            Limbs::single(r)
        } else if self.is_non_native_single() {
            let modulus = self.params.modulus_fe.unwrap();
            let r = multi_limb_arith::add_mod_p_single(
                self.compiler,
                a[0],
                b[0],
                modulus,
                self.range_checks,
            );
            Limbs::single(r)
        } else {
            multi_limb_arith::add_mod_p_multi(
                self.compiler,
                self.range_checks,
                a,
                b,
                &self.params.p_limbs,
                &self.params.p_minus_1_limbs,
                self.params.two_pow_w,
                self.params.limb_bits,
                &self.params.modulus_raw,
            )
        }
    }

    #[must_use]
    pub fn sub(&mut self, a: Limbs, b: Limbs) -> Limbs {
        assert_eq!(a.len(), self.n(), "sub: a.len() != num_limbs");
        assert_eq!(b.len(), self.n(), "sub: b.len() != num_limbs");
        if self.is_native_single() {
            // Merge duplicate witness into single term to avoid duplicate column indices.
            let r = if a[0] == b[0] {
                self.compiler
                    .add_sum(vec![SumTerm(Some(FieldElement::ZERO), a[0])])
            } else {
                self.compiler.add_sum(vec![
                    SumTerm(None, a[0]),
                    SumTerm(Some(-FieldElement::ONE), b[0]),
                ])
            };
            Limbs::single(r)
        } else if self.is_non_native_single() {
            let modulus = self.params.modulus_fe.unwrap();
            let r = multi_limb_arith::sub_mod_p_single(
                self.compiler,
                a[0],
                b[0],
                modulus,
                self.range_checks,
            );
            Limbs::single(r)
        } else {
            multi_limb_arith::sub_mod_p_multi(
                self.compiler,
                self.range_checks,
                a,
                b,
                &self.params.p_limbs,
                &self.params.p_minus_1_limbs,
                self.params.two_pow_w,
                self.params.limb_bits,
                &self.params.modulus_raw,
            )
        }
    }

    #[must_use]
    pub fn mul(&mut self, a: Limbs, b: Limbs) -> Limbs {
        assert_eq!(a.len(), self.n(), "mul: a.len() != num_limbs");
        assert_eq!(b.len(), self.n(), "mul: b.len() != num_limbs");
        if self.is_native_single() {
            let r = self.compiler.add_product(a[0], b[0]);
            Limbs::single(r)
        } else if self.is_non_native_single() {
            let modulus = self.params.modulus_fe.unwrap();
            let r = multi_limb_arith::mul_mod_p_single(
                self.compiler,
                a[0],
                b[0],
                modulus,
                self.range_checks,
            );
            Limbs::single(r)
        } else {
            multi_limb_arith::mul_mod_p_multi(
                self.compiler,
                self.range_checks,
                a,
                b,
                &self.params.p_limbs,
                &self.params.p_minus_1_limbs,
                self.params.two_pow_w,
                self.params.limb_bits,
                &self.params.modulus_raw,
            )
        }
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
        let mut out = Limbs::new(n);
        for i in 0..n {
            out[i] = select_witness(self.compiler, flag, on_false[i], on_true[i]);
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
        let mut out = Limbs::new(n);
        for i in 0..n {
            out[i] = allocate_pinned_constant(self.compiler, limbs[i]);
        }
        out
    }
}

// -----------------------------------------------------------------
// EC point operations — only available when E: EcOps
// -----------------------------------------------------------------

impl<E: EcOps> MultiLimbOps<'_, '_, E> {
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
