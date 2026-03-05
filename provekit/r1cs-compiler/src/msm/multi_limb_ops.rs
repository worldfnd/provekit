//! `MultiLimbOps` — unified FieldOps implementation parameterized by runtime
//! limb count.
//!
//! Uses `Limbs` (a fixed-capacity Copy type) as `FieldOps::Elem`, enabling
//! arbitrary limb counts without const generics or dispatch macros.

use {
    super::{multi_limb_arith, FieldOps, Limbs},
    crate::noir_to_r1cs::NoirToR1CSCompiler,
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
}

impl FieldOps for MultiLimbOps<'_, '_> {
    type Elem = Limbs;

    fn add(&mut self, a: Limbs, b: Limbs) -> Limbs {
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

    fn sub(&mut self, a: Limbs, b: Limbs) -> Limbs {
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

    fn mul(&mut self, a: Limbs, b: Limbs) -> Limbs {
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

    fn inv(&mut self, a: Limbs) -> Limbs {
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

    fn curve_a(&mut self) -> Limbs {
        let n = self.n();
        let mut out = Limbs::new(n);
        for i in 0..n {
            let w = self.compiler.num_witnesses();
            self.compiler
                .add_witness_builder(WitnessBuilder::Constant(ConstantTerm(
                    w,
                    self.params.curve_a_limbs[i],
                )));
            out[i] = w;
        }
        out
    }

    fn constrain_flag(&mut self, flag: usize) {
        super::constrain_boolean(self.compiler, flag);
    }

    fn select_unchecked(&mut self, flag: usize, on_false: Limbs, on_true: Limbs) -> Limbs {
        let n = self.n();
        let mut out = Limbs::new(n);
        for i in 0..n {
            out[i] = super::select_witness(self.compiler, flag, on_false[i], on_true[i]);
        }
        out
    }

    fn is_zero(&mut self, value: usize) -> usize {
        multi_limb_arith::compute_is_zero(self.compiler, value)
    }

    fn pack_bits(&mut self, bits: &[usize]) -> usize {
        super::pack_bits_helper(self.compiler, bits)
    }

    fn constant_limbs(&mut self, limbs: &[FieldElement]) -> Limbs {
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
            out[i] = w;
        }
        out
    }
}
