use crate::fns::constrained_ops::limbs_to_field;
use crate::params::BigNumParams;
use std::ops::{Add, Div, Mul, Neg, Sub};

pub trait BigNum: Neg + Add + Sub + Mul + Div + Eq {
    let N: u32;
    let MOD_BITS: u32;

    fn params() -> BigNumParams<N, MOD_BITS>;
    fn modulus_bits(_: Self) -> u32;
    fn num_limbs(_: Self) -> u32;
    fn modulus() -> Self;

    fn new() -> Self;
    fn zero() -> Self;
    fn one() -> Self;
    fn from_limbs(limbs: [u128; N]) -> Self;
    fn get_limbs(self) -> [u128; N];
    fn set_limb(self: &mut Self, idx: u32, value: u128);
    fn derive_from_seed<let SeedBytes: u32>(seed: [u8; SeedBytes]) -> Self;
    unconstrained fn __derive_from_seed<let SeedBytes: u32>(seed: [u8; SeedBytes]) -> Self;
    fn from_be_bytes(x: [u8; (MOD_BITS + 7) / 8]) -> Self;
    fn to_be_bytes(self) -> [u8; (MOD_BITS + 7) / 8];
    fn from_le_bytes(x: [u8; (MOD_BITS + 7) / 8]) -> Self;
    fn to_le_bytes(self) -> [u8; (MOD_BITS + 7) / 8];

    fn get_limb(self: Self, idx: u32) -> u128 {
        self.get_limbs()[idx]
    }

    unconstrained fn __eq(self: Self, other: Self) -> bool;

    unconstrained fn __is_zero(self: Self) -> bool;

    unconstrained fn __neg(self) -> Self;
    unconstrained fn __add(self, other: Self) -> Self;
    unconstrained fn __sub(self, other: Self) -> Self;
    unconstrained fn __mul(self, other: Self) -> Self;
    unconstrained fn __div(self, other: Self) -> Self;
    unconstrained fn __udiv_mod(self, divisor: Self) -> (Self, Self);
    unconstrained fn __invmod(self) -> Self;
    unconstrained fn __pow(self, exponent: Self) -> Self;

    unconstrained fn __tonelli_shanks_sqrt(self) -> std::option::Option<Self>;

    fn assert_is_not_equal(self: Self, other: Self);

    fn validate_in_range(self);
    fn validate_in_field(self);

    fn udiv_mod(self, divisor: Self) -> (Self, Self);
    fn udiv(self, divisor: Self) -> Self;
    fn umod(self, divisor: Self) -> Self;

    fn is_zero(self) -> bool;
}

// we need macros that implement the BigNum, Default, From, Neg, Add, Sub, Mul, Div, Eq, Ord traits for each bignum type
pub comptime fn derive_bignum(
    strukt: TypeDefinition,
    N: u32,
    MOD_BITS: u32,
    params: Quoted,
) -> Quoted {
    let constrained_ops = quote { $crate::fns::constrained_ops };
    let unconstrained_ops = quote { $crate::fns::unconstrained_ops };
    let typ = strukt.as_type();
    let serialization = quote { $crate::fns::serialization };
    quote {

        // implement BigNum for BigNum 
        impl $crate::BigNum for $typ {
            let N: u32 = $N; 
            let MOD_BITS: u32 = $MOD_BITS;
            
            fn modulus_bits(_: Self) -> u32 {
                $MOD_BITS
            }
            
            fn num_limbs(_: Self) -> u32 {
                $N
            }

            fn modulus() -> Self {
                Self { limbs: Self::params().modulus }
            }

            fn new() -> Self {
                Self {limbs: [0; $N]}
            }

            fn params() -> $crate::params::BigNumParams<$N, $MOD_BITS> {
                $params
            }

            fn from_limbs(limbs: [u128; $N]) -> Self {
                Self { limbs }
            }

            fn get_limbs(self: Self) -> [u128; $N] {
                self.limbs
            }

            fn set_limb(self: &mut Self, idx: u32, value: u128) {
                self.limbs[idx] = value;
            }

            fn zero() -> Self {
                Self { limbs: [0; $N] }
            }

            fn one() -> Self {
                let mut limbs = [0; $N];
                limbs[0] = 1;
                Self { limbs }
            }

            fn derive_from_seed<let SeedBytes: u32>(seed: [u8; SeedBytes]) -> Self {
                let params = Self::params();
                $typ::from_limbs($constrained_ops::derive_from_seed::<_, $MOD_BITS, _>(params, seed))
            }

            unconstrained fn __derive_from_seed<let SeedBytes: u32>(seed: [u8; SeedBytes]) -> Self {
                let params = Self::params();
                Self { limbs: $unconstrained_ops::__derive_from_seed::<_, $MOD_BITS, _>(params, seed) }
            }

            fn from_be_bytes(x: [u8; ($MOD_BITS + 7) / 8]) -> Self {
                Self { limbs: $serialization::from_be_bytes::<_, $MOD_BITS>(x) }
            }
            
            fn to_be_bytes(self) -> [u8; ($MOD_BITS + 7) / 8] {
                $serialization::to_be_bytes::<_, $MOD_BITS>(self.limbs)
            }

            fn from_le_bytes(x: [u8; ($MOD_BITS + 7) / 8]) -> Self {
                Self { limbs: $serialization::from_le_bytes::<_, $MOD_BITS>(x) }
            }

            fn to_le_bytes(self) -> [u8; ($MOD_BITS + 7) / 8] {
                $serialization::to_le_bytes::<_, $MOD_BITS>(self.limbs)
            }

            unconstrained fn __eq(self: Self, other: Self) -> bool {
                $crate::fns::unconstrained_ops::__eq(self.get_limbs(), other.get_limbs())
            }

            unconstrained fn __is_zero(self: Self) -> bool {
                $crate::fns::unconstrained_ops::__is_zero(self.get_limbs())
            }

            unconstrained fn __neg(self: Self) -> Self {
                let params = Self::params();
                Self {limbs: $unconstrained_ops::__neg(params.modulus, self.get_limbs())}
            }

            unconstrained fn __add(self: Self, other: Self) -> Self {
                let params = Self::params();
                Self {limbs: $unconstrained_ops::__add(params.modulus, self.get_limbs(), other.get_limbs())}
            }

            unconstrained fn __sub(self: Self, other: Self) -> Self {
                let params = Self::params();
                Self {limbs: $unconstrained_ops::__sub(params.modulus, self.get_limbs(), other.get_limbs())}
            }

            unconstrained fn __mul(self: Self, other: Self) -> Self {
                let params = Self::params();
                Self {limbs: $unconstrained_ops::__mul(params, self.get_limbs(), other.get_limbs())}
            }

            unconstrained fn __div(self: Self, divisor: Self) -> Self {
                let params = Self::params();
                Self {limbs: $unconstrained_ops::__div(params, self.get_limbs(), divisor.get_limbs())}
            }

            unconstrained fn __udiv_mod(self: Self, divisor: Self) -> (Self, Self) {
                let (q, r) = $unconstrained_ops::__udiv_mod(self.get_limbs(), divisor.get_limbs());
                (Self{limbs: q}, Self{limbs: r})
            }

            unconstrained fn __invmod(self: Self) -> Self {
                let params = Self::params();
                assert(params.has_multiplicative_inverse);
                Self {limbs: $unconstrained_ops::__invmod(params, self.get_limbs())}
            }

            unconstrained fn __pow(self: Self, exponent: Self) -> Self {
                let params = Self::params();
                Self {limbs: $unconstrained_ops::__pow(params, self.get_limbs(), exponent.get_limbs())}
            }

            unconstrained fn __tonelli_shanks_sqrt(self: Self) -> std::option::Option<Self> {
                let params = Self::params();
                let maybe_limbs = $unconstrained_ops::__tonelli_shanks_sqrt(params, self.get_limbs());
                maybe_limbs.map(|limbs| Self {limbs: limbs})
            }


            fn assert_is_not_equal(self: Self, other: Self) {
                let params = Self::params();
                $crate::fns::constrained_ops::assert_is_not_equal(
                    params,
                    self.get_limbs(),
                    other.get_limbs(),
                );
            }

            fn validate_in_field(self: Self) {
                let params = Self::params();
                $constrained_ops::validate_in_field::<_, $MOD_BITS>(params, self.get_limbs());
            }

            fn validate_in_range(self: Self) {
                $constrained_ops::validate_in_range::<_, _, $MOD_BITS>(self.get_limbs());
            }

            fn udiv_mod(self: Self, divisor: Self) -> (Self, Self) {
                let params = Self::params();
                let (q, r) = $constrained_ops::udiv_mod::<_, $MOD_BITS>(params, self.get_limbs(), divisor.get_limbs());
                (Self {limbs: q}, Self {limbs: r})
            }

            fn udiv(self: Self, divisor: Self) -> Self {
                let params = Self::params();
                Self {limbs: $constrained_ops::udiv::<_, $MOD_BITS>(params, self.get_limbs(), divisor.get_limbs())}
            }

            fn umod(self: Self, divisor: Self) -> Self {
                let params = Self::params();
                Self {limbs: $constrained_ops::umod::<_, $MOD_BITS>(params, self.get_limbs(), divisor.get_limbs())}
            }

            fn is_zero(self: Self) -> bool {
                $constrained_ops::is_zero::<_, $MOD_BITS>(self.get_limbs())
            }
        }

        // implement Default for BigNum
        impl Default for $typ {
            fn default() -> Self {
                $typ::from_limbs([0; $N])
            }
        }

        impl std::convert::From<Field> for $typ {
            fn from(input: Field) -> Self {
                $typ { limbs: $constrained_ops::from_field::<$N, $MOD_BITS>($params, input) }
            }
        }

        impl std::ops::Neg for $typ {
            fn neg(self) -> Self {
                $typ { limbs: $constrained_ops::neg::<$N, $MOD_BITS>($params, self.limbs) }
            }
        }

        impl std::ops::Add for $typ {
            fn add(self, other: Self) -> Self {
                $typ { limbs: $constrained_ops::add::<$N, $MOD_BITS>($params, self.limbs, other.limbs) }
            }
        }

        impl std::ops::Sub for $typ {
            fn sub(self, other: Self) -> Self {
                $typ { limbs: $constrained_ops::sub::<$N, $MOD_BITS>($params, self.limbs, other.limbs) }
            }
        }

        impl std::ops::Mul for $typ {
            fn mul(self, other: Self) -> Self {
                $typ { limbs: $constrained_ops::mul::<$N, $MOD_BITS>($params, self.limbs, other.limbs) }
            }
        }

        impl std::ops::Div for $typ {
            fn div(self, other: Self) -> Self {
                $typ { limbs: $constrained_ops::div::<$N, $MOD_BITS>($params, self.limbs, other.limbs) }
            }
        }

        impl std::cmp::Eq for $typ {
            fn eq(self, other: Self) -> bool {
                $constrained_ops::eq::<$N, $MOD_BITS>($params, self.limbs, other.limbs)
            }
        }

        impl std::cmp::Ord for $typ {
            fn cmp(self, other: Self) -> std::cmp::Ordering {
                $constrained_ops::cmp::<$N, $MOD_BITS>(self.limbs, other.limbs)
            }
        }

    }
}

pub fn conditional_select<T: BigNum>(lhs: T, rhs: T, predicate: bool) -> T {
    if predicate {
        lhs
    } else {
        rhs
    }
}

pub unconstrained fn compute_quadratic_expression<T: BigNum, let LHS_N: u32, let RHS_N: u32, let NUM_PRODUCTS: u32, let ADD_N: u32>(
    lhs_terms: [[T; LHS_N]; NUM_PRODUCTS],
    lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
    rhs_terms: [[T; RHS_N]; NUM_PRODUCTS],
    rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
    linear_terms: [T; ADD_N],
    linear_flags: [bool; ADD_N],
) -> (T, T) {
    let params = T::params();
    let (q_limbs, r_limbs) = crate::fns::expressions::compute_quadratic_expression(
        params,
        crate::utils::map::map(
            lhs_terms,
            |bns| crate::utils::map::map(bns, |bn: T| bn.get_limbs()),
        ),
        lhs_flags,
        crate::utils::map::map(
            rhs_terms,
            |bns| crate::utils::map::map(bns, |bn: T| bn.get_limbs()),
        ),
        rhs_flags,
        crate::utils::map::map(linear_terms, |bn: T| bn.get_limbs()),
        linear_flags,
    );
    (T::from_limbs(q_limbs), T::from_limbs(r_limbs))
}

pub fn evaluate_quadratic_expression<T: BigNum, let LHS_N: u32, let RHS_N: u32, let NUM_PRODUCTS: u32, let ADD_N: u32>(
    lhs_terms: [[T; LHS_N]; NUM_PRODUCTS],
    lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
    rhs_terms: [[T; RHS_N]; NUM_PRODUCTS],
    rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
    linear_terms: [T; ADD_N],
    linear_flags: [bool; ADD_N],
) {
    let params = T::params();
    crate::fns::expressions::evaluate_quadratic_expression(
        params,
        crate::utils::map::map(
            lhs_terms,
            |bns| crate::utils::map::map(bns, |bn: T| bn.get_limbs()),
        ),
        lhs_flags,
        crate::utils::map::map(
            rhs_terms,
            |bns| crate::utils::map::map(bns, |bn: T| bn.get_limbs()),
        ),
        rhs_flags,
        crate::utils::map::map(linear_terms, |bn: T| bn.get_limbs()),
        linear_flags,
    )
}

pub unconstrained fn batch_invert<T: BigNum, let M: u32>(x: [T; M]) -> [T; M] {
    let params = T::params();
    assert(params.has_multiplicative_inverse);
    crate::fns::unconstrained_ops::batch_invert(params, x.map(|bn: T| bn.get_limbs())).map(|limbs| {
        T::from_limbs(limbs)
    })
}

pub unconstrained fn batch_invert_slice<T: BigNum>(x: [T]) -> [T] {
    let params = T::params();
    assert(params.has_multiplicative_inverse);
    crate::fns::unconstrained_ops::batch_invert_slice(params, x.map(|bn: T| bn.get_limbs()))
        .map(|limbs| T::from_limbs(limbs))
}

pub fn to_field<T: BigNum>(bn: T) -> Field {
    let params = T::params();
    limbs_to_field(params, bn.get_limbs())
}
