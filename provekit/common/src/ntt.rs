use {ark_bn254::Fr, ark_ff::AdditiveGroup, whir::ntt::ReedSolomon};

pub struct RSFr;
impl ReedSolomon<Fr> for RSFr {
    fn interleaved_encode(
        &self,
        interleaved_coeffs: &[Fr],
        expansion: usize,
        fold_factor: usize,
    ) -> Vec<Fr> {
        interleaved_rs_encode(interleaved_coeffs, expansion, fold_factor)
    }
}

fn interleaved_rs_encode(
    interleaved_coeffs: &[Fr],
    expansion: usize,
    fold_factor: usize,
) -> Vec<Fr> {
    let fold_factor_exp = 2usize.pow(fold_factor as u32);
    let expanded_size = interleaved_coeffs.len() * expansion;

    debug_assert_eq!(expanded_size % fold_factor_exp, 0);

    // 1. Create zero-padded message of appropriate size
    let mut result = vec![Fr::ZERO; expanded_size];
    result[..interleaved_coeffs.len()].copy_from_slice(interleaved_coeffs);

    let mut ntt = ntt::NTT::new(result, fold_factor_exp)
        .expect("interleaved_coeffs.len() * expension / 2^fold_factor needs to be a power of two.");
    let mut engine = ntt::NTTEngine::new();
    engine.interleaved_ntt_nr(&mut ntt);

    ntt.into_inner()
}
