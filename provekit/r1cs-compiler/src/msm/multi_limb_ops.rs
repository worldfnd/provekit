//! `MultiLimbOps` — field arithmetic parameterized by runtime limb count.
//!
//! Uses `Limbs` (a fixed-capacity Copy type) as the element representation,
//! enabling arbitrary limb counts without const generics or dispatch macros.

use {
    super::{multi_limb_arith, Limbs},
    crate::{
        constraint_helpers::{constrain_boolean, pack_bits_helper, select_witness},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::{AdditiveGroup, Field},
    provekit_common::{
        witness::{ConstantTerm, SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::collections::BTreeMap,
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
    /// p = native field → skip mod reduction
    pub is_native:       bool,
    /// For N=1 non-native: the modulus as a single FieldElement
    pub modulus_fe:      Option<FieldElement>,
}

impl MultiLimbParams {
    /// Build params for EC field operations (mod field_modulus_p).
    pub fn for_field_modulus(
        num_limbs: usize,
        limb_bits: u32,
        curve: &super::curve::CurveParams,
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
            modulus_raw: curve.field_modulus_p,
            curve_a_limbs: curve.curve_a_limbs(limb_bits, num_limbs),
            is_native,
            modulus_fe,
        }
    }

    /// Build params for scalar relation verification (mod curve_order_n).
    pub fn for_curve_order(
        num_limbs: usize,
        limb_bits: u32,
        curve: &super::curve::CurveParams,
    ) -> Self {
        let two_pow_w = FieldElement::from(2u64).pow([limb_bits as u64]);
        let modulus_fe = if num_limbs == 1 {
            Some(super::curve::curve_native_point_fe(&curve.curve_order_n))
        } else {
            None
        };
        Self {
            num_limbs,
            limb_bits,
            p_limbs: curve.curve_order_n_limbs(limb_bits, num_limbs),
            p_minus_1_limbs: curve.curve_order_n_minus_1_limbs(limb_bits, num_limbs),
            two_pow_w,
            modulus_raw: curve.curve_order_n,
            curve_a_limbs: vec![FieldElement::from(0u64); num_limbs], // unused
            is_native: false,                                         /* always non-native for
                                                                       * scalar relation */
            modulus_fe,
        }
    }
}

/// Unified field operations struct parameterized by runtime limb count.
pub struct MultiLimbOps<'a, 'p> {
    pub compiler:     &'a mut NoirToR1CSCompiler,
    pub range_checks: &'a mut BTreeMap<u32, Vec<usize>>,
    pub params:       &'p MultiLimbParams,
}

impl MultiLimbOps<'_, '_> {
    fn is_native_single(&self) -> bool {
        self.params.num_limbs == 1 && self.params.is_native
    }

    fn is_non_native_single(&self) -> bool {
        self.params.num_limbs == 1 && !self.params.is_native
    }

    fn n(&self) -> usize {
        self.params.num_limbs
    }

    /// Negate a multi-limb value: computes `0 - value (mod p)`.
    pub fn negate(&mut self, value: Limbs) -> Limbs {
        let zero_vals = vec![FieldElement::from(0u64); self.params.num_limbs];
        let zero = self.constant_limbs(&zero_vals);
        self.sub(zero, value)
    }

    pub fn add(&mut self, a: Limbs, b: Limbs) -> Limbs {
        debug_assert_eq!(a.len(), self.n(), "a.len() != num_limbs");
        debug_assert_eq!(b.len(), self.n(), "b.len() != num_limbs");
        if self.is_native_single() {
            // When both operands are the same witness, merge into a single
            // term with coefficient 2 to avoid duplicate column indices in
            // the R1CS sparse matrix (set overwrites on duplicate (row,col)).
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

    pub fn sub(&mut self, a: Limbs, b: Limbs) -> Limbs {
        debug_assert_eq!(a.len(), self.n(), "a.len() != num_limbs");
        debug_assert_eq!(b.len(), self.n(), "b.len() != num_limbs");
        if self.is_native_single() {
            // When both operands are the same witness, a - a = 0. Use a
            // single zero-coefficient term to avoid duplicate column indices.
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

    pub fn mul(&mut self, a: Limbs, b: Limbs) -> Limbs {
        debug_assert_eq!(a.len(), self.n(), "a.len() != num_limbs");
        debug_assert_eq!(b.len(), self.n(), "b.len() != num_limbs");
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

    pub fn inv(&mut self, a: Limbs) -> Limbs {
        debug_assert_eq!(a.len(), self.n(), "a.len() != num_limbs");
        if self.is_native_single() {
            let a_inv = self.compiler.num_witnesses();
            self.compiler
                .add_witness_builder(WitnessBuilder::Inverse(a_inv, a[0]));
            // a * a_inv = 1
            self.compiler.r1cs.add_constraint(
                &[(FieldElement::ONE, a[0])],
                &[(FieldElement::ONE, a_inv)],
                &[(FieldElement::ONE, self.compiler.witness_one())],
            );
            Limbs::single(a_inv)
        } else if self.is_non_native_single() {
            let modulus = self.params.modulus_fe.unwrap();
            let r =
                multi_limb_arith::inv_mod_p_single(self.compiler, a[0], modulus, self.range_checks);
            Limbs::single(r)
        } else {
            multi_limb_arith::inv_mod_p_multi(
                self.compiler,
                self.range_checks,
                a,
                &self.params.p_limbs,
                &self.params.p_minus_1_limbs,
                self.params.two_pow_w,
                self.params.limb_bits,
                &self.params.modulus_raw,
            )
        }
    }

    pub fn curve_a(&mut self) -> Limbs {
        let n = self.n();
        let mut out = Limbs::new(n);
        for i in 0..n {
            let w = self.compiler.num_witnesses();
            let value = self.params.curve_a_limbs[i];
            self.compiler
                .add_witness_builder(WitnessBuilder::Constant(ConstantTerm(w, value)));
            // Pin: prevent malicious prover from choosing a different curve_a
            self.compiler.r1cs.add_constraint(
                &[(FieldElement::ONE, self.compiler.witness_one())],
                &[(FieldElement::ONE, w)],
                &[(value, self.compiler.witness_one())],
            );
            out[i] = w;
        }
        out
    }

    /// Constrains `flag` to be boolean (`flag * flag = flag`).
    pub fn constrain_flag(&mut self, flag: usize) {
        constrain_boolean(self.compiler, flag);
    }

    /// Conditional select without boolean constraint on `flag`.
    /// Caller must ensure `flag` is already constrained boolean.
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
    pub fn select(&mut self, flag: usize, on_false: Limbs, on_true: Limbs) -> Limbs {
        self.constrain_flag(flag);
        self.select_unchecked(flag, on_false, on_true)
    }

    /// Checks if a native witness value is zero.
    /// Returns a boolean witness: 1 if zero, 0 if non-zero.
    pub fn is_zero(&mut self, value: usize) -> usize {
        multi_limb_arith::compute_is_zero(self.compiler, value)
    }

    /// Packs bit witnesses into a single digit witness: `d = Σ bits[i] * 2^i`.
    /// Does NOT constrain bits to be boolean — caller must ensure that.
    pub fn pack_bits(&mut self, bits: &[usize]) -> usize {
        pack_bits_helper(self.compiler, bits)
    }

    /// Returns a constant field element from its limb decomposition.
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
            let w = self.compiler.num_witnesses();
            self.compiler
                .add_witness_builder(WitnessBuilder::Constant(ConstantTerm(w, limbs[i])));
            // Pin: prevent malicious prover from altering constant values
            self.compiler.r1cs.add_constraint(
                &[(FieldElement::ONE, self.compiler.witness_one())],
                &[(FieldElement::ONE, w)],
                &[(limbs[i], self.compiler.witness_one())],
            );
            out[i] = w;
        }
        out
    }
}
