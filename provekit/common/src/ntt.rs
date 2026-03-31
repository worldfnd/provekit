use {
    ark_bn254::Fr,
    ark_ff::{AdditiveGroup, FftField, Field},
    ntt::ntt_nr,
    whir::algebra::ntt::ReedSolomon,
};

#[derive(Debug)]
pub struct RSFr;

impl ReedSolomon<Fr> for RSFr {
    fn next_order(&self, size: usize) -> Option<usize> {
        let order = size.next_power_of_two();
        if order <= 1 << 28 {
            Some(order)
        } else {
            None
        }
    }

    fn evaluation_points(
        &self,
        _masked_message_length: usize,
        codeword_length: usize,
        indices: &[usize],
    ) -> Vec<Fr> {
        indices
            .into_iter()
            .map(|i| {
                let bits = usize::BITS - (codeword_length - 1).leading_zeros();
                let k = if bits == 0 {
                    *i
                } else {
                    i.reverse_bits() >> (usize::BITS - bits)
                };

                // Optimise generator away
                let generator = Fr::get_root_of_unity(codeword_length as u64).unwrap();
                generator.pow([k as u64])
            })
            .collect()
    }

    fn interleaved_encode(
        &self,
        messages: &[&[Fr]],
        masks: &[Fr],
        codeword_length: usize,
    ) -> Vec<Fr> {
        todo!()
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

    // Tranpose needs to happen here.

    let mut ntt = ntt::NTT::new(result, interleaving_depth).expect(
        "interleaved_coeffs.len() * expansion / interleaving_depth needs to be a power of two.",
    );

    ntt_nr(&mut ntt);

    ntt.into_inner()
}
