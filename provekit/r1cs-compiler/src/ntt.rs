use {ark_bn254::Fr, ark_ff::AdditiveGroup, ntt::ntt_nr, whir::ntt::ReedSolomon};

pub struct RSFr;

impl Default for RSFr {
    fn default() -> Self {
        Self
    }
}
impl ReedSolomon<Fr> for RSFr {
    #[tracing::instrument(skip(self, interleaved_coeffs), fields(size = interleaved_coeffs.len()))]
    fn interleaved_encode(
        &self,
        interleaved_coeffs: &[Fr],
        expansion: usize,
        fold_factor: usize,
    ) -> Vec<Fr> {
        debug_assert!(expansion > 0);
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

    let mut result = vec![Fr::ZERO; expanded_size];
    result[..interleaved_coeffs.len()].copy_from_slice(interleaved_coeffs);

    let mut ntt = ntt::NTT::new(result, fold_factor_exp)
        .expect("interleaved_coeffs.len() * expansion / 2^fold_factor needs to be a power of two.");

    ntt_nr(&mut ntt);

    let mut result = ntt.into_inner();

    let poly_size = expanded_size / fold_factor_exp;
    interleaved_bit_reversal(&mut result, poly_size, fold_factor_exp);

    result
}

fn interleaved_bit_reversal(data: &mut [Fr], poly_size: usize, num_polys: usize) {
    if poly_size <= 1 {
        return;
    }

    let bits = poly_size.trailing_zeros();

    for i in 0..poly_size {
        let rev = reverse_bits(i, bits);
        if i < rev {
            let i_start = i * num_polys;
            let rev_start = rev * num_polys;
            let (left, right) = data.split_at_mut(rev_start);
            left[i_start..i_start + num_polys].swap_with_slice(&mut right[..num_polys]);
        }
    }
}

#[inline]
fn reverse_bits(val: usize, bits: u32) -> usize {
    val.reverse_bits() >> (usize::BITS - bits)
}

#[cfg(test)]
mod tests {
    use {super::*, ark_std::UniformRand, whir::ntt::RSDefault};

    #[test]
    fn test_rsfr_matches_rsdefault() {
        let mut rng = ark_std::test_rng();
        let count = 1 << 16;
        let expansion = 4;
        let folding_factor = 4;

        let poly: Vec<Fr> = (0..count).map(|_| Fr::rand(&mut rng)).collect();

        let expected = RSDefault.interleaved_encode(&poly, expansion, folding_factor);
        let actual = RSFr.interleaved_encode(&poly, expansion, folding_factor);

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_rsfr_various_sizes() {
        let mut rng = ark_std::test_rng();

        for log_count in 10..18 {
            for expansion in [2, 4, 8] {
                for folding_factor in [2, 4, 6] {
                    let count = 1 << log_count;
                    let poly: Vec<Fr> = (0..count).map(|_| Fr::rand(&mut rng)).collect();

                    let expected = RSDefault.interleaved_encode(&poly, expansion, folding_factor);
                    let actual = RSFr.interleaved_encode(&poly, expansion, folding_factor);

                    assert_eq!(
                        expected, actual,
                        "Mismatch for count={count}, expansion={expansion}, \
                         folding_factor={folding_factor}"
                    );
                }
            }
        }
    }
}
