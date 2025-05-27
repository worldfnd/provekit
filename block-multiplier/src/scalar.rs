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
        crate::constants,
        ark_bn254::Fr,
        ark_ff::{BigInt, Field},
        primitive_types::U256,
        proptest::{
            collection,
            prelude::{Strategy, any},
            proptest,
        },
        rand::{Rng, SeedableRng, rngs},
    };

    /// Given a multiprecision integer in LSB form returns a Strategy that will
    /// return values in the range of 0..=max
    fn max_multiprecision(max: Vec<u64>) -> impl Strategy<Value = Vec<u64>> {
        // Takes a vector and takes ownership of it to deal with the 'static requirement
        // of boxed.
        let size = max.len();
        (0..=max[size - 1]).prop_flat_map(move |limb| {
            // If the generated most significant limb is smaller than the MSL of max, we
            // know that the other limbs are unconstrained
            if limb < max[size - 1] {
                collection::vec(any::<u64>(), size..size + 1)
                    .prop_map(move |mut arr| {
                        arr[size - 1] = limb;
                        assert_eq!(arr.len(), size);
                        arr
                    })
                    .boxed()
            } else {
                // If MSL is equal to max so we make a recursive call to constrain
                // the next limb
                max_multiprecision(max[..size - 1].to_owned())
                    .prop_map(move |mut arr| {
                        arr.push(limb);
                        assert_eq!(arr.len(), size);
                        arr
                    })
                    .boxed()
            }
        })
    }

    /// Upper bound of 2**256-2p
    const UPPER_BOUND_MONTGOMERY: [u64; 4] = [
        0x783c14d81ffffffe,
        0xaf982f6f0c8d1edd,
        0x8f5f7492fcfd4f45,
        0x9f37631a3d9cbfac,
    ];

    fn safe_bn254_montgomery_input() -> impl Strategy<Value = [u64; 4]> {
        max_multiprecision(UPPER_BOUND_MONTGOMERY.to_vec()).prop_map(|vec| vec.try_into().unwrap())
    }

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

    const OUTPUT_MAX: [u64; 4] = [
        0x783c14d81ffffffe,
        0xaf982f6f0c8d1edd,
        0x8f5f7492fcfd4f45,
        0x9f37631a3d9cbfac,
    ];

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
            assert!(U256(s0) < U256(OUTPUT_MAX));
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
    fn test_max_field_strategy() {
        proptest!(|(pair in proptest::array::uniform4(any::<u64>()).prop_flat_map(|upper_bound| {
            max_multiprecision(upper_bound.to_vec()).prop_map(move |value| (upper_bound, value))
        }))| {
            let (upper_bound, value) = pair;
            // Check if value <= max by comparing limbs from most significant to least
            assert!(value[3] <= upper_bound[3], "Value[3] exceeds max[3]");
            assert!(
                !(value[3] == upper_bound[3] && value[2] > upper_bound[2]),
                "Value[2] exceeds max[2] when value[3] == max[3]"
            );
            assert!(
                !(value[3] == upper_bound[3] && value[2] == upper_bound[2] && value[1] > upper_bound[1]),
                "Value[1] exceeds max[1] when higher limbs equal"
            );
            assert!(
                !(value[3] == upper_bound[3]
                    && value[2] == upper_bound[2]
                    && value[1] == upper_bound[1]
                    && value[0] > upper_bound[0]),
                "Value[0] exceeds max[0] when higher limbs equal"
            );
        });
    }
}
