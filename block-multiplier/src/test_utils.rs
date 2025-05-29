#![cfg(test)]

use {
    crate::constants::OUTPUT_MAX,
    ark_bn254::Fr,
    ark_ff::{BigInt, Field},
    proptest::{
        collection,
        prelude::{Strategy, any},
        proptest,
    },
};

/// Given a multiprecision integer in little-endian format, returns a
/// `Strategy` that generates values uniformly in the range `0..=max`.
fn max_multiprecision(max: Vec<u64>) -> impl Strategy<Value = Vec<u64>> {
    // Takes ownership of a vector rather to deal with the 'static
    // requirement of boxed()
    let size = max.len();
    (0..=max[size - 1]).prop_flat_map(move |limb| {
        // If the generated most significant limb is smaller than the MSL of max the
        // the remaining limbs can be unconstrained.
        if limb < max[size - 1] {
            collection::vec(any::<u64>(), size..size + 1)
                .prop_map(move |mut arr| {
                    arr[size - 1] = limb;
                    assert_eq!(arr.len(), size);
                    arr
                })
                .boxed()
        } else {
            // If MSL is equal to max constrain the next limbs
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

/// Generates a value between [0, 2ˆ256-2p]
pub fn safe_bn254_montgomery_input() -> impl Strategy<Value = [u64; 4]> {
    max_multiprecision(OUTPUT_MAX.to_vec()).prop_map(|vec| vec.try_into().unwrap())
}

/// Reference for montgomery multiplication l*r*Rˆ-1
pub fn ark_ff_reference(l: [u64; 4], r: [u64; 4]) -> Fr {
    let sigma = Fr::from(2).pow([256]).inverse().unwrap();
    let fl = Fr::new(BigInt(l));
    let fr = Fr::new(BigInt(r));
    fl * fr * sigma
}

#[test]
fn test_max_multiprecision_strategy() {
    proptest!(|(pair in proptest::array::uniform4(any::<u64>()).prop_flat_map(|upper_bound| {
        max_multiprecision(upper_bound.to_vec()).prop_map(move |value| (upper_bound, value))
    }))| {
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
