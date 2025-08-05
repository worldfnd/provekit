use std::ops::{Add, Div, Mul, Neg, Sub};

pub struct BigNum<let N: u32, let MOD_BITS: u32, Params> {
    pub limbs: [u64; N],
}
// We aim to avoid needing to add a generic parameter to this trait, for this reason we do not allow
// accessing the limbs of the bignum except through slices.
pub trait BigNumTrait: Neg + Add + Sub + Mul + Div + Eq {
    // TODO: this crashes the compiler? v0.32
    // fn default() -> Self { std::default::Default::default  () }
    fn new() -> Self;
    fn zero() -> Self;
    fn one() -> Self;
    // fn derive_from_seed<let SeedBytes: u32>(seed: [u8; SeedBytes]) -> Self;
    // unconstrained fn __derive_from_seed<let SeedBytes: u32>(seed: [u8; SeedBytes]) -> Self;
    fn from_slice(limbs: [u128]) -> Self;
    fn from_be_bytes<let NBytes: u32>(x: [u8; NBytes]) -> Self;
    fn to_le_bytes<let NBytes: u32>(self) -> [u8; NBytes];

    fn modulus() -> Self;
    fn modulus_bits(self) -> u32;
    fn num_limbs(self) -> u32;
    fn get_limbs_slice(self) -> [u128];
    fn get_limb(self, idx: u32) -> u128;
    fn set_limb(&mut self, idx: u32, value: u128);

    unconstrained fn __eq(self, other: Self) -> bool;
    unconstrained fn __is_zero(self) -> bool;

    unconstrained fn __neg(self) -> Self;
    unconstrained fn __add(self, other: Self) -> Self;
    unconstrained fn __sub(self, other: Self) -> Self;
    unconstrained fn __mul(self, other: Self) -> Self;
    unconstrained fn __div(self, other: Self) -> Self;
    unconstrained fn __udiv_mod(self, divisor: Self) -> (Self, Self);
    unconstrained fn __invmod(self) -> Self;
    unconstrained fn __pow(self, exponent: Self) -> Self;

    unconstrained fn __batch_invert<let M: u32>(to_invert: [Self; M]) -> [Self; M];
    unconstrained fn __batch_invert_slice<let M: u32>(to_invert: [Self]) -> [Self];

    unconstrained fn __tonelli_shanks_sqrt(self) -> std::option::Option<Self>;

    unconstrained fn __compute_quadratic_expression<let LHS_N: u32, let RHS_N: u32, let NUM_PRODUCTS: u32, let ADD_N: u32>(
        lhs: [[Self; LHS_N]; NUM_PRODUCTS],
        lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
        rhs: [[Self; RHS_N]; NUM_PRODUCTS],
        rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
        add: [Self; ADD_N],
        add_flags: [bool; ADD_N],
    ) -> (Self, Self);

    fn evaluate_quadratic_expression<let LHS_N: u32, let RHS_N: u32, let NUM_PRODUCTS: u32, let ADD_N: u32>(
        lhs: [[Self; LHS_N]; NUM_PRODUCTS],
        lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
        rhs: [[Self; RHS_N]; NUM_PRODUCTS],
        rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
        add: [Self; ADD_N],
        add_flags: [bool; ADD_N],
    );

    fn assert_is_not_equal(self, other: Self);
    fn validate_in_range(self);
    fn validate_in_field(self);

    fn udiv_mod(self, divisor: Self) -> (Self, Self);
    fn udiv(self, divisor: Self) -> Self;
    fn umod(self, divisor: Self) -> Self;

    fn conditional_select(lhs: Self, rhs: Self, predicate: bool) -> Self;
    fn is_zero(self) -> bool;
}

// impl<let N: u32, let MOD_BITS: u32, Params> std::convert::From<Field> for BigNum<N, MOD_BITS, Params>
// where
//     Params: BigNumParamsGetter<N, MOD_BITS>,
// {
//     fn from(input: Field) -> Self {
//         Self { limbs: from_field::<N, MOD_BITS>(input) }
//     }
// }

// impl<let N: u32, let MOD_BITS: u32, Params> Neg for BigNum<N, MOD_BITS, Params>
// where
//     Params: BigNumParamsGetter<N, MOD_BITS>,
// {
//     fn neg(self) -> Self {
//         let params = Params::get_params();
//         Self { limbs: neg::<_, MOD_BITS>(params, self.limbs) }
//     }
// }

// impl<let N: u32, let MOD_BITS: u32, Params> BigNumTrait for BigNum<N, MOD_BITS, Params>
// where
//     Params: BigNumParamsGetter<N, MOD_BITS>,
// {

//     #[deprecated("`BigNum::zero()` is preferred")]
//     fn new() -> Self {
//         Self::zero()
//     }

//     fn zero() -> Self {
//         Self { limbs: [0; N] }
//     }

//     fn one() -> Self {
//         let mut result = BigNum::zero();
//         result.limbs[0] = 1;
//         result
//     }

// fn derive_from_seed<let SeedBytes: u32>(seed: [u8; SeedBytes]) -> Self {
//     let params = Params::get_params();
//     Self { limbs: derive_from_seed::<_, MOD_BITS, _>(params, seed) }
// }

// unconstrained fn __derive_from_seed<let SeedBytes: u32>(seed: [u8; SeedBytes]) -> Self {
//     let params = Params::get_params();
//     Self { limbs: __derive_from_seed::<_, MOD_BITS, _>(params, seed) }
// }

// fn from_slice(limbs: [u128]) -> Self {
//     Self { limbs: limbs.as_array() }
// }

// fn from_be_bytes<let NBytes: u32>(x: [u8; NBytes]) -> Self {
//     Self { limbs: from_be_bytes::<_, MOD_BITS, _>(x) }
// }

// fn to_le_bytes<let NBytes: u32>(self) -> [u8; NBytes] {
//     to_le_bytes::<_, MOD_BITS, _>(self.limbs)
// }

// fn modulus() -> Self {
//     Self { limbs: Params::get_params().modulus }
// }

// fn modulus_bits(_: Self) -> u32 {
//     MOD_BITS
// }

// fn num_limbs(_: Self) -> u32 {
//     N
// }

// fn get_limbs_slice(self) -> [u128] {
//     self.limbs
// }

// fn get_limb(self, idx: u32) -> u128 {
//     self.limbs[idx]
// }

// fn set_limb(&mut self, idx: u32, value: u128) {
//     self.limbs[idx] = value;
// }

// unconstrained fn __eq(self, other: Self) -> bool {
//     __eq(self.limbs, other.limbs)
// }

// unconstrained fn __is_zero(self) -> bool {
//     __is_zero(self.limbs)
// }

// unconstrained fn __neg(self) -> Self {
//     let params = Params::get_params();
//     Self { limbs: __neg(params, self.limbs) }
// }

// unconstrained fn __add(self, other: Self) -> Self {
//     let params = Params::get_params();
//     Self { limbs: __add(params, self.limbs, other.limbs) }
// }

// unconstrained fn __sub(self, other: Self) -> Self {
//     let params = Params::get_params();
//     Self { limbs: __sub(params, self.limbs, other.limbs) }
// }

// unconstrained fn __mul(self, other: Self) -> Self {
//     let params = Params::get_params();
//     Self { limbs: __mul::<_, MOD_BITS>(params, self.limbs, other.limbs) }
// }
// unconstrained fn __div(self, divisor: Self) -> Self {
//     let params = Params::get_params();
//     Self { limbs: __div::<_, MOD_BITS>(params, self.limbs, divisor.limbs) }
// }
// unconstrained fn __udiv_mod(self, divisor: Self) -> (Self, Self) {
//     let (q, r) = __udiv_mod(self.limbs, divisor.limbs);
//     (Self { limbs: q }, Self { limbs: r })
// }
// unconstrained fn __invmod(self) -> Self {
//     let params = Params::get_params();
//     assert(params.has_multiplicative_inverse);
//     Self { limbs: __invmod::<_, MOD_BITS>(params, self.limbs) }
// }
// unconstrained fn __pow(self, exponent: Self) -> Self {
//     let params = Params::get_params();
//     Self { limbs: __pow::<_, MOD_BITS>(params, self.limbs, exponent.limbs) }
// }
// unconstrained fn __batch_invert<let M: u32>(x: [Self; M]) -> [Self; M] {
//     let params = Params::get_params();
//     assert(params.has_multiplicative_inverse);
//     __batch_invert::<_, MOD_BITS, _>(params, x.map(|bn: Self| bn.limbs)).map(|limbs| {
//         Self { limbs }
//     })
// }
// unconstrained fn __batch_invert_slice<let M: u32>(x: [Self]) -> [Self] {
//     let params = Params::get_params();
//     assert(params.has_multiplicative_inverse);
//     __batch_invert_slice::<_, MOD_BITS>(params, x.map(|bn: Self| bn.limbs)).map(|limbs| {
//         Self { limbs }
//     })
// }
// unconstrained fn __tonelli_shanks_sqrt(self) -> std::option::Option<Self> {
//     let params = Params::get_params();
//     let maybe_limbs = __tonelli_shanks_sqrt(params, self.limbs);
//     maybe_limbs.map(|limbs| Self { limbs })
// }
// unconstrained fn __compute_quadratic_expression<let LHS_N: u32, let RHS_N: u32, let NUM_PRODUCTS: u32, let ADD_N: u32>(
//     lhs_terms: [[Self; LHS_N]; NUM_PRODUCTS],
//     lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
//     rhs_terms: [[Self; RHS_N]; NUM_PRODUCTS],
//     rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
//     linear_terms: [Self; ADD_N],
//     linear_flags: [bool; ADD_N],
// ) -> (Self, Self) {
//     let params = Params::get_params();
//     let (q_limbs, r_limbs) = __compute_quadratic_expression::<_, MOD_BITS, _, _, _, _>(
//         params,
//         map(lhs_terms, |bns| map(bns, |bn: Self| bn.limbs)),
//         lhs_flags,
//         map(rhs_terms, |bns| map(bns, |bn: Self| bn.limbs)),
//         rhs_flags,
//         map(linear_terms, |bn: Self| bn.limbs),
//         linear_flags,
//     );
//     (Self { limbs: q_limbs }, Self { limbs: r_limbs })
// }
// fn evaluate_quadratic_expression<let LHS_N: u32, let RHS_N: u32, let NUM_PRODUCTS: u32, let ADD_N: u32>(
//     lhs_terms: [[Self; LHS_N]; NUM_PRODUCTS],
//     lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
//     rhs_terms: [[Self; RHS_N]; NUM_PRODUCTS],
//     rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
//     linear_terms: [Self; ADD_N],
//     linear_flags: [bool; ADD_N],
// ) {
//     let params = Params::get_params();
//     evaluate_quadratic_expression::<_, MOD_BITS, _, _, _, _>(
//         params,
//         map(lhs_terms, |bns| map(bns, |bn: Self| bn.limbs)),
//         lhs_flags,
//         map(rhs_terms, |bns| map(bns, |bn: Self| bn.limbs)),
//         rhs_flags,
//         map(linear_terms, |bn: Self| bn.limbs),
//         linear_flags,
//     )
// }
// fn validate_in_field(self: Self) {
//     let params = Params::get_params();
//     validate_in_field::<_, MOD_BITS>(params, self.limbs);
// }
// fn validate_in_range(self) {
//     validate_in_range::<_, _, MOD_BITS>(self.limbs);
// }
// fn assert_is_not_equal(self, other: Self) {
//     let params = Params::get_params();
//     assert_is_not_equal(params, self.limbs, other.limbs);
// }
// fn udiv_mod(self, divisor: Self) -> (Self, Self) {
//     let params = Params::get_params();
//     let (q, r) = udiv_mod::<_, MOD_BITS>(params, self.limbs, divisor.limbs);
//     (Self { limbs: q }, Self { limbs: r })
// }
// fn udiv(self, divisor: Self) -> Self {
//     let params = Params::get_params();
//     Self { limbs: udiv::<_, MOD_BITS>(params, self.limbs, divisor.limbs) }
// }
// fn umod(self, divisor: Self) -> Self {
//     let params = Params::get_params();
//     Self { limbs: umod::<_, MOD_BITS>(params, self.limbs, divisor.limbs) }
// }
// fn conditional_select(lhs: Self, rhs: Self, predicate: bool) -> Self {
//     Self { limbs: conditional_select(lhs.limbs, rhs.limbs, predicate) }
// }
// fn is_zero(self) -> bool {
//     is_zero::<N, MOD_BITS>(self.limbs)
// }
// }

// impl<let N: u32, let MOD_BITS: u32, Params> Default for BigNum<N, MOD_BITS, Params>
// where
//     Params: BigNumParamsGetter<N, MOD_BITS>,
// {
//     fn default() -> Self {
//         Self::zero()
//     }
// }

// impl<let N: u32, let MOD_BITS: u32, Params> std::ops::Add for BigNum<N, MOD_BITS, Params>
// where
//     Params: BigNumParamsGetter<N, MOD_BITS>,
// {
//     // Note: this method is expensive! Try to craft quadratic relations and directly evaluate them
//     //       via evaluate_quadratic_expression
//     fn add(self, other: Self) -> Self {
//         let params = Params::get_params();
//         Self { limbs: add::<_, MOD_BITS>(params, self.limbs, other.limbs) }
//     }
// }

// impl<let N: u32, let MOD_BITS: u32, Params> std::ops::Sub for BigNum<N, MOD_BITS, Params>
// where
//     Params: BigNumParamsGetter<N, MOD_BITS>,
// {
//     // Note: this method is expensive! Try to craft quadratic relations and directly evaluate them
//     //       via evaluate_quadratic_expression
//     fn sub(self, other: Self) -> Self {
//         let params = Params::get_params();
//         Self { limbs: sub::<_, MOD_BITS>(params, self.limbs, other.limbs) }
//     }
// }

// impl<let N: u32, let MOD_BITS: u32, Params> std::ops::Mul for BigNum<N, MOD_BITS, Params>
// where
//     Params: BigNumParamsGetter<N, MOD_BITS>,
// {
//     // Note: this method is expensive! Try to craft quadratic relations and directly evaluate them
//     //       via evaluate_quadratic_expression
//     // e.g. performing a sum of multiple multiplications and additions via `evaluate_quadratic_expression`
//     //      will create much fewer constraints than calling `mul` and `add` directly
//     fn mul(self, other: Self) -> Self {
//         let params = Params::get_params();
//         Self { limbs: mul::<_, MOD_BITS>(params, self.limbs, other.limbs) }
//     }
// }

// impl<let N: u32, let MOD_BITS: u32, Params> std::ops::Div for BigNum<N, MOD_BITS, Params>
// where
//     Params: BigNumParamsGetter<N, MOD_BITS>,
// {
//     // Note: this method is expensive! Witness computation is extremely expensive as it requires modular exponentiation
//     fn div(self, other: Self) -> Self {
//         let params = Params::get_params();
//         Self { limbs: div::<_, MOD_BITS>(params, self.limbs, other.limbs) }
//     }
// }

// impl<let N: u32, let MOD_BITS: u32, Params> std::cmp::Eq for BigNum<N, MOD_BITS, Params>
// where
//     Params: BigNumParamsGetter<N, MOD_BITS>,
// {
//     fn eq(self, other: Self) -> bool {
//         let params = Params::get_params();
//         eq::<_, MOD_BITS>(params, self.limbs, other.limbs)
//     }
// }

// impl<let N: u32, let MOD_BITS: u32, Params> std::cmp::Ord for BigNum<N, MOD_BITS, Params>
// where
//     Params: BigNumParamsGetter<N, MOD_BITS>,
// {
//     fn cmp(self, other: Self) -> Ordering {
//         cmp::<_, MOD_BITS>(self.limbs, other.limbs)
//     }
// }

// /// `to_field` converts a BigNum to a Field, conditioned on the bignum fitting in a field element
// ///
// /// we have opted to not add this to the BigNumTrait as it might lead to bad usage of it
// /// i.e. using this function with modulus larger than the Grumpkin modulus would lead to runtime errors, if the bignum is not deliberately picked to be in range, e.g. the bignum is the output of a hash function.
// /// for such use cases we advise developers to use comptime assertions to ensure the modulus is not larger than the Grumpkin modulus
// pub fn to_field<let N: u32, let MOD_BITS: u32, Params>(input: BigNum<N, MOD_BITS, Params>) -> Field
// where
//     Params: BigNumParamsGetter<N, MOD_BITS>,
// {
//     limbs_to_field(Params::get_params(), input.limbs)
// }
