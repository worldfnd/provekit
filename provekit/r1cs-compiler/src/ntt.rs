#![allow(dead_code)] // Remove once RSFr is used for WHIR
use {ark_bn254::Fr, ark_ff::AdditiveGroup, ntt::ntt_nr, whir::algebra::ntt::ReedSolomon};

pub struct RSFr;
impl ReedSolomon<Fr> for RSFr {
    fn interleaved_encode(
        &self,
        interleaved_coeffs: &[Fr],
        expansion: usize,
        interleaving_depth: usize,
    ) -> Vec<Fr> {
        debug_assert!(expansion > 0);
        interleaved_rs_encode(interleaved_coeffs, expansion, interleaving_depth)
    }
}

fn interleaved_rs_encode(
    interleaved_coeffs: &[Fr],
    expansion: usize,
    interleaving_depth: usize,
) -> Vec<Fr> {
    let expanded_size = interleaved_coeffs.len() * expansion;

    debug_assert_eq!(expanded_size % interleaving_depth, 0);

    let mut result = vec![Fr::ZERO; expanded_size];
    result[..interleaved_coeffs.len()].copy_from_slice(interleaved_coeffs);

    let mut ntt = ntt::NTT::new(result, interleaving_depth).expect(
        "interleaved_coeffs.len() * expansion / interleaving_depth needs to be a power of two.",
    );

    ntt_nr(&mut ntt);

    ntt.into_inner()
}
