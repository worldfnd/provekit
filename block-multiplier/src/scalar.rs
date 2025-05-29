use crate::{
    constants::*,
    subarray,
    utils::{addv, carrying_mul_add, reduce_ct},
};

/// Montgomery squaring in Bn254 scalar field.
///
/// Accepts input in range [0, 2P)
/// Returns output in range [0, P)
#[inline]
pub fn scalar_sqr(a: [u64; 4]) -> [u64; 4] {
    // -- [SCALAR]
    // ---------------------------------------------------------------------------------
    let mut t = [0_u64; 8];

    let mut carry = 0;
    (t[0], carry) = carrying_mul_add(a[0], a[0], t[0], carry);
    (t[1], carry) = carrying_mul_add(a[0], a[1], t[1], carry);
    (t[2], carry) = carrying_mul_add(a[0], a[2], t[2], carry);
    (t[3], carry) = carrying_mul_add(a[0], a[3], t[3], carry);
    t[4] = carry;
    carry = 0;
    (t[1], carry) = carrying_mul_add(a[1], a[0], t[1], carry);
    (t[2], carry) = carrying_mul_add(a[1], a[1], t[2], carry);
    (t[3], carry) = carrying_mul_add(a[1], a[2], t[3], carry);
    (t[4], carry) = carrying_mul_add(a[1], a[3], t[4], carry);
    t[5] = carry;
    carry = 0;
    (t[2], carry) = carrying_mul_add(a[2], a[0], t[2], carry);
    (t[3], carry) = carrying_mul_add(a[2], a[1], t[3], carry);
    (t[4], carry) = carrying_mul_add(a[2], a[2], t[4], carry);
    (t[5], carry) = carrying_mul_add(a[2], a[3], t[5], carry);
    t[6] = carry;
    carry = 0;
    (t[3], carry) = carrying_mul_add(a[3], a[0], t[3], carry);
    (t[4], carry) = carrying_mul_add(a[3], a[1], t[4], carry);
    (t[5], carry) = carrying_mul_add(a[3], a[2], t[5], carry);
    (t[6], carry) = carrying_mul_add(a[3], a[3], t[6], carry);
    t[7] = carry;

    let mut s_r1 = [0_u64; 5];
    (s_r1[0], s_r1[1]) = carrying_mul_add(t[0], U64_I3[0], 0, 0);
    (s_r1[1], s_r1[2]) = carrying_mul_add(t[0], U64_I3[1], s_r1[1], 0);
    (s_r1[2], s_r1[3]) = carrying_mul_add(t[0], U64_I3[2], s_r1[2], 0);
    (s_r1[3], s_r1[4]) = carrying_mul_add(t[0], U64_I3[3], s_r1[3], 0);

    let mut s_r2 = [0_u64; 5];
    (s_r2[0], s_r2[1]) = carrying_mul_add(t[1], U64_I2[0], 0, 0);
    (s_r2[1], s_r2[2]) = carrying_mul_add(t[1], U64_I2[1], s_r2[1], 0);
    (s_r2[2], s_r2[3]) = carrying_mul_add(t[1], U64_I2[2], s_r2[2], 0);
    (s_r2[3], s_r2[4]) = carrying_mul_add(t[1], U64_I2[3], s_r2[3], 0);

    let mut s_r3 = [0_u64; 5];
    (s_r3[0], s_r3[1]) = carrying_mul_add(t[2], U64_I1[0], 0, 0);
    (s_r3[1], s_r3[2]) = carrying_mul_add(t[2], U64_I1[1], s_r3[1], 0);
    (s_r3[2], s_r3[3]) = carrying_mul_add(t[2], U64_I1[2], s_r3[2], 0);
    (s_r3[3], s_r3[4]) = carrying_mul_add(t[2], U64_I1[3], s_r3[3], 0);

    let s = addv(addv(subarray!(t, 3, 5), s_r1), addv(s_r2, s_r3));

    let m = U64_MU0.wrapping_mul(s[0]);
    let mut mp = [0_u64; 5];
    (mp[0], mp[1]) = carrying_mul_add(m, U64_P[0], mp[0], 0);
    (mp[1], mp[2]) = carrying_mul_add(m, U64_P[1], mp[1], 0);
    (mp[2], mp[3]) = carrying_mul_add(m, U64_P[2], mp[2], 0);
    (mp[3], mp[4]) = carrying_mul_add(m, U64_P[3], mp[3], 0);

    reduce_ct(subarray!(addv(s, mp), 1, 4))
}

#[inline]
pub fn scalar_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    // -- [SCALAR]
    // ---------------------------------------------------------------------------------
    let mut t = [0_u64; 8];

    let mut carry = 0;
    (t[0], carry) = carrying_mul_add(a[0], b[0], t[0], carry);
    (t[1], carry) = carrying_mul_add(a[0], b[1], t[1], carry);
    (t[2], carry) = carrying_mul_add(a[0], b[2], t[2], carry);
    (t[3], carry) = carrying_mul_add(a[0], b[3], t[3], carry);
    t[4] = carry;
    carry = 0;
    (t[1], carry) = carrying_mul_add(a[1], b[0], t[1], carry);
    (t[2], carry) = carrying_mul_add(a[1], b[1], t[2], carry);
    (t[3], carry) = carrying_mul_add(a[1], b[2], t[3], carry);
    (t[4], carry) = carrying_mul_add(a[1], b[3], t[4], carry);
    t[5] = carry;
    carry = 0;
    (t[2], carry) = carrying_mul_add(a[2], b[0], t[2], carry);
    (t[3], carry) = carrying_mul_add(a[2], b[1], t[3], carry);
    (t[4], carry) = carrying_mul_add(a[2], b[2], t[4], carry);
    (t[5], carry) = carrying_mul_add(a[2], b[3], t[5], carry);
    t[6] = carry;
    carry = 0;
    (t[3], carry) = carrying_mul_add(a[3], b[0], t[3], carry);
    (t[4], carry) = carrying_mul_add(a[3], b[1], t[4], carry);
    (t[5], carry) = carrying_mul_add(a[3], b[2], t[5], carry);
    (t[6], carry) = carrying_mul_add(a[3], b[3], t[6], carry);
    t[7] = carry;

    let mut s_r1 = [0_u64; 5];
    (s_r1[0], s_r1[1]) = carrying_mul_add(t[0], U64_I3[0], 0, 0);
    (s_r1[1], s_r1[2]) = carrying_mul_add(t[0], U64_I3[1], s_r1[1], 0);
    (s_r1[2], s_r1[3]) = carrying_mul_add(t[0], U64_I3[2], s_r1[2], 0);
    (s_r1[3], s_r1[4]) = carrying_mul_add(t[0], U64_I3[3], s_r1[3], 0);

    let mut s_r2 = [0_u64; 5];
    (s_r2[0], s_r2[1]) = carrying_mul_add(t[1], U64_I2[0], 0, 0);
    (s_r2[1], s_r2[2]) = carrying_mul_add(t[1], U64_I2[1], s_r2[1], 0);
    (s_r2[2], s_r2[3]) = carrying_mul_add(t[1], U64_I2[2], s_r2[2], 0);
    (s_r2[3], s_r2[4]) = carrying_mul_add(t[1], U64_I2[3], s_r2[3], 0);

    let mut s_r3 = [0_u64; 5];
    (s_r3[0], s_r3[1]) = carrying_mul_add(t[2], U64_I1[0], 0, 0);
    (s_r3[1], s_r3[2]) = carrying_mul_add(t[2], U64_I1[1], s_r3[1], 0);
    (s_r3[2], s_r3[3]) = carrying_mul_add(t[2], U64_I1[2], s_r3[2], 0);
    (s_r3[3], s_r3[4]) = carrying_mul_add(t[2], U64_I1[3], s_r3[3], 0);

    let s = addv(addv(subarray!(t, 3, 5), s_r1), addv(s_r2, s_r3));

    let m = U64_MU0.wrapping_mul(s[0]);
    let mut mp = [0_u64; 5];
    (mp[0], mp[1]) = carrying_mul_add(m, U64_P[0], mp[0], 0);
    (mp[1], mp[2]) = carrying_mul_add(m, U64_P[1], mp[1], 0);
    (mp[2], mp[3]) = carrying_mul_add(m, U64_P[2], mp[2], 0);
    (mp[3], mp[4]) = carrying_mul_add(m, U64_P[3], mp[3], 0);

    // ---------------------------------------------------------------------------------------------
    reduce_ct(subarray!(addv(s, mp), 1, 4))
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{constants, test_utils::*},
        ark_bn254::Fr,
        ark_ff::{BigInt, Field},
        primitive_types::U256,
        proptest::proptest,
        rand::{Rng, SeedableRng, rngs},
    };

    #[test]
    fn test_mul_field() {
        let sigma = Fr::from(2).pow([256]).inverse().unwrap();
        proptest!(|(l in safe_bn254_montgomery_input(), r in safe_bn254_montgomery_input())| {
            let fl = Fr::new(BigInt(l));
            let fr = Fr::new(BigInt(r));
            let fe = fl * fr * sigma;
            let r = scalar_mul(l, r);
            let fr = Fr::new(BigInt(r));
            assert_eq!(fr, fe);
        })
    }

    fn mod_mul(a: U256, b: U256) -> U256 {
        let p = U256(constants::U64_P);
        let mut c = [0u64; 4];
        c.copy_from_slice(&(a.full_mul(b) % p).0[0..4]);
        U256(c)
    }

    #[test]
    fn test_scalar_mul() {
        let mut rng = rngs::StdRng::seed_from_u64(0);
        let p = U256(constants::U64_P);
        let r = U256(constants::U64_R);
        let r_inv = U256(constants::U64_R_INV);

        let mut s0_a_bytes = [0u8; 32];
        let mut s0_b_bytes = [0u8; 32];

        for _ in 0..100000 {
            rng.fill(&mut s0_a_bytes);
            rng.fill(&mut s0_b_bytes);
            let s0_a = U256::from_little_endian(&s0_a_bytes) % p;
            let s0_b = U256::from_little_endian(&s0_b_bytes) % p;
            let s0_a_mont = mod_mul(s0_a, r);
            let s0_b_mont = mod_mul(s0_b, r);

            let s0 = scalar_mul(s0_a_mont.0, s0_b_mont.0);
            assert!(U256(s0) < U256(constants::OUTPUT_MAX));
            assert_eq!(mod_mul(U256(s0), r_inv), mod_mul(s0_a, s0_b));
        }
    }

    #[test]
    fn test_scalar_sqr() {
        let mut rng = rngs::StdRng::seed_from_u64(0);
        let p = U256(constants::U64_P);
        let r = U256(constants::U64_R);
        let r_inv = U256(constants::U64_R_INV);

        let mut s0_a_bytes = [0u8; 32];

        for _ in 0..100000 {
            rng.fill(&mut s0_a_bytes);
            let s0_a = U256::from_little_endian(&s0_a_bytes) % p;
            let s0_a_mont = mod_mul(s0_a, r);

            let s0 = scalar_sqr(s0_a_mont.0);
            assert!(U256(s0) < U256(OUTPUT_MAX));
            assert_eq!(mod_mul(U256(s0), r_inv), mod_mul(s0_a, s0_a));
        }
    }

    #[test]
    fn test_max_multiprecision_strategy() {
        let upper_bounds = proptest::array::uniform4(any::<u64>());
        let pairs = upper_bounds.prop_flat_map(|upper_bound| {
            max_multiprecision(upper_bound.to_vec()).prop_map(move |value| (upper_bound, value))
        });
        proptest!(|(pair in pairs)| {
            let (upper_bound, value) = pair;
            // Check if value <= max by comparing limbs from most significant to least
            assert!(value[3] <= upper_bound[3], "value[3] exceeds max[3]");
            assert!(
                !(value[3] == upper_bound[3] && value[2] > upper_bound[2]),
                "value[2] exceeds max[2] when higher limbs are equal"
            );
            assert!(
                !(value[3] == upper_bound[3] && value[2] == upper_bound[2] && value[1] > upper_bound[1]),
                "value[1] exceeds max[1] when higher limbs are equal"
            );
            assert!(
                !(value[3] == upper_bound[3]
                    && value[2] == upper_bound[2]
                    && value[1] == upper_bound[1]
                    && value[0] > upper_bound[0]),
                "value[0] exceeds max[0] when higher limbs are equal"
            );
        });
    }
}
