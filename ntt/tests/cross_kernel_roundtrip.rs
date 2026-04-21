//! Cross-kernel correctness: simulate "prove with one kernel, verify with the
//! other" at the NTT level. The production dispatch in `ntt_nr()` is
//! target-gated (`cfg(target_arch = "wasm32")`), so on native we can only run
//! one kernel. These tests explicitly drive both `ntt_nr_ark` and
//! `ntt_nr_b51` on the same input and assert byte-identical output — the
//! property on which "prover on wasm, verifier on native" compatibility
//! ultimately rests.

#![cfg(not(target_arch = "wasm32"))]

use {
    ark_bn254::Fr,
    ark_ff::UniformRand,
    ntt::{ark_interleaved::ntt_nr_ark, b51_interleaved::ntt_nr_b51},
};

fn make_values(codeword_log2: u32, num_groups_log2: u32) -> Vec<Fr> {
    let total = 1usize << (codeword_log2 + num_groups_log2);
    let mut rng = ark_std::test_rng();
    (0..total).map(|_| Fr::rand(&mut rng)).collect()
}

#[test]
fn ark_and_b51_agree_across_interleaving_strides() {
    for codeword_log2 in [6u32, 10, 14, 16] {
        for num_groups_log2 in 0u32..=5 {
            let codeword_size = 1usize << codeword_log2;
            let num_groups = 1usize << num_groups_log2;
            let values = make_values(codeword_log2, num_groups_log2);

            let mut ark_out = values.clone();
            ntt_nr_ark(&mut ark_out, codeword_size, num_groups);
            let mut b51_out = values;
            ntt_nr_b51(&mut b51_out, codeword_size, num_groups);

            assert_eq!(
                ark_out, b51_out,
                "mismatch at codeword=2^{codeword_log2}, num_groups=2^{num_groups_log2}"
            );
        }
    }
}

#[test]
fn b51_forward_ark_inverse_roundtrips() {
    for codeword_log2 in [8u32, 12, 14] {
        let codeword_size = 1usize << codeword_log2;
        let values = make_values(codeword_log2, 0);

        let mut working = values.clone();
        ntt_nr_b51(&mut working, codeword_size, 1);

        // intt_rn expects reverse-bit-ordered evaluations → normal-order
        // coefficients. ntt_nr produces reverse-bit-ordered evaluations, so we
        // can feed directly.
        ntt::intt_rn(&mut working);

        assert_eq!(
            working, values,
            "b51→ark roundtrip diverged at size 2^{codeword_log2}"
        );
    }
}


#[test]
fn ark_forward_matches_b51_forward_then_canonical() {
    for codeword_log2 in [8u32, 12, 14] {
        let codeword_size = 1usize << codeword_log2;
        let values = make_values(codeword_log2, 0);

        let mut ark_out = values.clone();
        ntt_nr_ark(&mut ark_out, codeword_size, 1);

        let mut b51_out = values;
        ntt_nr_b51(&mut b51_out, codeword_size, 1);

        // b51 already canonicalizes internally via canonicalize_b51, so raw
        // limbs should match without post-processing.
        assert_eq!(ark_out, b51_out);
    }
}
