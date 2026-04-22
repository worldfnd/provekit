use {
    crate::{define_ntt, extend_roots_table},
    ark_bn254::Fr,
    bn254_multiplier::{
        constants::{self, U64_P_MULTIPLES},
        rne,
        utils::{self, addv, div_p_2b, subtraction_reduce},
    },
    rayon::iter::{IntoParallelRefMutIterator, ParallelIterator},
    std::mem,
};

define_ntt!(interleaved_ntt_nr, [u64; 4], b51_kernel);

pub fn ntt_nr_b51(values: &mut [Fr], codeword_size: usize, num_groups: usize) {
    let new_root = extend_roots_table(codeword_size);
    // SAFETY: `Fr` is `#[repr(transparent)]` over `BigInt<4>`, which is
    // `#[repr(transparent)]` over `[u64; 4]`, so the layouts are identical.
    let (roots, raw): (&[[u64; 4]], &mut [[u64; 4]]) =
        unsafe { (mem::transmute(new_root.roots()), mem::transmute(values)) };
    interleaved_ntt_nr(roots, raw, codeword_size, num_groups);
    canonicalize_b51(raw);
}

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

/// Fit values within [0,p). Necessary to be compatible with Ark
fn canonicalize_b51(values: &mut [[u64; 4]]) {
    // After the kernel the values are within [0,2.3p]. We use subtraction reduce to
    // get the value within 2p such that we can use a conditional subtract.
    values.par_iter_mut().for_each(|elem| {
        let reduced = subtraction_reduce(div_p_2b, *elem);
        let tentative = utils::sub(reduced, U64_P_MULTIPLES[1]);
        *elem = if tentative[3] >> 63 == 1 {
            reduced
        } else {
            tentative
        };
    });
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use {
        crate::{ark_interleaved::ntt_nr_ark, b51_interleaved::ntt_nr_b51},
        ark_bn254::Fr,
        ark_ff::BigInt,
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
    }
}
