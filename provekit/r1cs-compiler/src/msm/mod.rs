pub mod curve;
pub mod ec_ops;
pub mod ec_points;
pub mod wide_ops;

use {
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    ark_ff::Field,
    curve::{curve_native_point_fe, limb2_constant, CurveParams, Limb2},
    provekit_common::{
        witness::{ConstantTerm, SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::collections::BTreeMap,
};

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
}

/// Narrow field operations for curves where p fits in BN254's scalar field.
/// Operates on single witness indices (`usize`).
pub struct NarrowOps<'a> {
    pub compiler:     &'a mut NoirToR1CSCompiler,
    pub range_checks: &'a mut BTreeMap<u32, Vec<usize>>,
    pub modulus:      FieldElement,
    pub params:       &'a CurveParams,
}

impl FieldOps for NarrowOps<'_> {
    type Elem = usize;

    fn add(&mut self, a: usize, b: usize) -> usize {
        ec_ops::add_mod_p(self.compiler, a, b, self.modulus, self.range_checks)
    }

    fn sub(&mut self, a: usize, b: usize) -> usize {
        ec_ops::sub_mod_p(self.compiler, a, b, self.modulus, self.range_checks)
    }

    fn mul(&mut self, a: usize, b: usize) -> usize {
        ec_ops::mul_mod_p(self.compiler, a, b, self.modulus, self.range_checks)
    }

    fn inv(&mut self, a: usize) -> usize {
        ec_ops::inv_mod_p(self.compiler, a, self.modulus, self.range_checks)
    }

    fn curve_a(&mut self) -> usize {
        let a_fe = curve_native_point_fe(&self.params.curve_a);
        let w = self.compiler.num_witnesses();
        self.compiler
            .add_witness_builder(WitnessBuilder::Constant(ConstantTerm(w, a_fe)));
        w
    }

    fn select(&mut self, flag: usize, on_false: usize, on_true: usize) -> usize {
        constrain_boolean(self.compiler, flag);
        select_witness(self.compiler, flag, on_false, on_true)
    }
}

/// Wide field operations for curves where p > BN254_r (e.g. secp256r1).
/// Operates on `Limb2` (two 128-bit limbs).
pub struct WideOps<'a> {
    pub compiler:     &'a mut NoirToR1CSCompiler,
    pub range_checks: &'a mut BTreeMap<u32, Vec<usize>>,
    pub params:       &'a CurveParams,
}

impl FieldOps for WideOps<'_> {
    type Elem = Limb2;

    fn add(&mut self, a: Limb2, b: Limb2) -> Limb2 {
        wide_ops::add_mod_p(self.compiler, self.range_checks, a, b, self.params)
    }

    fn sub(&mut self, a: Limb2, b: Limb2) -> Limb2 {
        wide_ops::sub_mod_p(self.compiler, self.range_checks, a, b, self.params)
    }

    fn mul(&mut self, a: Limb2, b: Limb2) -> Limb2 {
        wide_ops::mul_mod_p(self.compiler, self.range_checks, a, b, self.params)
    }

    fn inv(&mut self, a: Limb2) -> Limb2 {
        wide_ops::inv_mod_p(self.compiler, self.range_checks, a, self.params)
    }

    fn curve_a(&mut self) -> Limb2 {
        limb2_constant(self.compiler, self.params.curve_a)
    }

    fn select(&mut self, flag: usize, on_false: Limb2, on_true: Limb2) -> Limb2 {
        constrain_boolean(self.compiler, flag);
        Limb2 {
            lo: select_witness(self.compiler, flag, on_false.lo, on_true.lo),
            hi: select_witness(self.compiler, flag, on_false.hi, on_true.hi),
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Constrains `flag` to be boolean: `flag * flag = flag`.
fn constrain_boolean(compiler: &mut NoirToR1CSCompiler, flag: usize) {
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, flag)],
        &[(FieldElement::ONE, flag)],
        &[(FieldElement::ONE, flag)],
    );
}

/// Single-witness conditional select: `out = on_false + flag * (on_true -
/// on_false)`.
///
/// Produces 3 witnesses and 3 R1CS constraints (diff, flag*diff, out).
/// Does NOT constrain `flag` to be boolean — caller must do that separately.
fn select_witness(
    compiler: &mut NoirToR1CSCompiler,
    flag: usize,
    on_false: usize,
    on_true: usize,
) -> usize {
    let diff = compiler.add_sum(vec![
        SumTerm(None, on_true),
        SumTerm(Some(-FieldElement::ONE), on_false),
    ]);
    let flag_diff = compiler.add_product(flag, diff);
    compiler.add_sum(vec![SumTerm(None, on_false), SumTerm(None, flag_diff)])
}
