use {
    bn254_multiplier::{
        constants::U64_P_MULTIPLES,
        utils::{self, div_p_2b, subtraction_reduce},
    },
    rayon::iter::{IntoParallelRefMutIterator, ParallelIterator},
};
#[cfg(not(kani))]
use {
    crate::{define_ntt, extend_roots_table},
    ark_bn254::Fr,
    bn254_multiplier::{constants, rne, utils::addv},
    std::mem,
};

#[cfg(not(kani))]
define_ntt!(interleaved_ntt_nr, [u64; 4], b51_kernel);

#[cfg(not(kani))]
pub fn ntt_nr_b51(values: &mut [Fr], codeword_size: usize, num_groups: usize) {
    let new_root = extend_roots_table(codeword_size);
    // SAFETY: `Fr` is `#[repr(transparent)]` over `BigInt<4>`, which is
    // `#[repr(transparent)]` over `[u64; 4]`, so the layouts are identical.
    let (roots, raw): (&[[u64; 4]], &mut [[u64; 4]]) =
        unsafe { (mem::transmute(new_root.roots()), mem::transmute(values)) };
    interleaved_ntt_nr(roots, raw, codeword_size, num_groups);
    canonicalize_b51(raw);
}

#[cfg(not(kani))]
#[inline(always)]
fn b51_kernel(even: &mut [u64; 4], odd: &mut [u64; 4], omega: &[u64; 4]) {
    // rne multiplier will takes any value times <p to a value less than 3p.
    // to not overflow in addition even needs to be less than ~2.3p (2**256-1 - 3*p)
    //
    // subtraction_reduce here reduces any value in [0,2**256) value to [0,2.3p)
    // creating our invariant
    let f = rne::mono::mul(*odd, *omega);
    let l = subtraction_reduce(div_p_2b, addv(*even, f));
    let r = subtraction_reduce(
        div_p_2b,
        addv(*even, utils::sub(constants::U64_P_MULTIPLES[3], f)),
    );
    (*even, *odd) = (l, r);
}

#[inline(always)]
fn canonicalize_b51_element(elem: [u64; 4]) -> [u64; 4] {
    let reduced = subtraction_reduce(div_p_2b, elem);
    let tentative = utils::sub(reduced, U64_P_MULTIPLES[1]);
    if tentative[3] >> 63 == 1 {
        reduced
    } else {
        tentative
    }
}

/// Fit values within [0,p). Necessary to be compatible with Ark
fn canonicalize_b51(values: &mut [[u64; 4]]) {
    values
        .par_iter_mut()
        .for_each(|elem| *elem = canonicalize_b51_element(*elem));
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use {
        crate::{ark_interleaved::ntt_nr_ark, b51_interleaved::ntt_nr_b51},
        ark_bn254::Fr,
        ark_ff::{BigInt, PrimeField},
        bn254_multiplier::constants::U64_P_MULTIPLES,
        proptest::{collection, prelude::*},
    };

    proptest! {
        #[test]
        fn b51_matches_ark(
            values in (1_usize..=15).prop_flat_map(|k| {
                let len = 1 << k;
                collection::vec(
                    proptest::array::uniform4(0u64..).prop_map(|val| Fr::new(BigInt(val))),
                    len..=len,
                )
            })
        ) {
            let codeword_size = values.len();

            let mut b51_out = values.clone();
            ntt_nr_b51(&mut b51_out, codeword_size, 1);

            let mut ark_out = values;
            ntt_nr_ark(&mut ark_out, codeword_size, 1);

            prop_assert_eq!(b51_out, ark_out);
        }

        #[test]
        fn b51_matches_ark_interleaved(
            codeword_log2 in 3_usize..=12,
            num_groups_log2 in 0_usize..=3,
        ) {
            let codeword_size = 1 << codeword_log2;
            let num_groups = 1 << num_groups_log2;
            let total = codeword_size * num_groups;
            let mut rng = ark_std::test_rng();
            let values: Vec<Fr> = (0..total).map(|_| <Fr as ark_ff::UniformRand>::rand(&mut rng)).collect();

            let mut b51_out = values.clone();
            ntt_nr_b51(&mut b51_out, codeword_size, num_groups);
            let mut ark_out = values;
            ntt_nr_ark(&mut ark_out, codeword_size, num_groups);

            prop_assert_eq!(b51_out, ark_out);
        }

        // Samples raw [u64;4] directly so inputs can cover the full [0, 3p)
        // range the kernel invariant allows (Fr::rand only covers [0, p)).
        #[test]
        fn canonicalize_b51_is_canonical(
            raw in proptest::array::uniform4(0u64..),
        ) {
            use bn254_multiplier::utils;
            let below_3p = utils::sub(raw, U64_P_MULTIPLES[3])[3] >> 63 == 1;
            prop_assume!(below_3p);

            let mut buf = vec![raw];
            super::canonicalize_b51(&mut buf);

            let bi = BigInt(buf[0]);
            prop_assert!(Fr::from_bigint(bi).is_some(),
                "canonicalize_b51 left value ≥ p: {:?}", buf[0]);
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use {
        super::canonicalize_b51_element,
        bn254_multiplier::{constants::U64_P_MULTIPLES, utils::sub},
    };

    fn le256(a: [u64; 4], b: [u64; 4]) -> bool {
        for i in (0..4).rev() {
            if a[i] != b[i] {
                return a[i] < b[i];
            }
        }
        true
    }

    #[kani::proof]
    fn canonicalize_b51_produces_canonical() {
        let elem: [u64; 4] = [kani::any(), kani::any(), kani::any(), kani::any()];
        kani::assume(le256(elem, U64_P_MULTIPLES[3]));
        let result = canonicalize_b51_element(elem);
        let diff = sub(result, U64_P_MULTIPLES[1]);
        assert!(diff[3] >> 63 == 1, "result must be < p");
    }
}
