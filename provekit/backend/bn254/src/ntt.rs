use {
    ark_bn254::Fr,
    ark_ff::{AdditiveGroup, FftField, Field},
    ntt::ntt_nr,
    tracing::instrument,
    whir::{
        algebra::ntt::{Polynomials, ReedSolomon},
        buffer::{Buffer, BufferOps},
    },
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

                let generator = self.generator(codeword_length);
                generator.pow([k as u64])
            })
            .collect()
    }

    #[instrument(skip(self, polynomials), fields(
        num_polynomials = polynomials.len(),
        polynomial_len = polynomials.polynomial_length(),
        codeword_length = codeword_length,
    ))]
    fn interleaved_encode(
        &self,
        polynomials: Polynomials<'_, Fr>,
        codeword_length: usize,
    ) -> Buffer<Fr> {
        let num_polynomials = polynomials.len();
        if num_polynomials == 0 {
            return Buffer::from(vec![]);
        }

        let polynomial_length = polynomials.polynomial_length();
        assert!(polynomial_length <= codeword_length);
        let total_size = num_polynomials * codeword_length;

        let mut result = vec![Fr::ZERO; total_size];
        let mut column_offset = 0;
        for segment in polynomials.segments() {
            let row_width = segment.row_width();
            let rows_per_buffer = segment.rows_per_buffer();
            for polynomial in 0..num_polynomials {
                let buffer = segment.buffer(polynomial / rows_per_buffer).to_slice();
                let row = polynomial % rows_per_buffer;
                let start = row * row_width;
                for column in 0..row_width {
                    result[(column_offset + column) * num_polynomials + polynomial] =
                        buffer[start + column];
                }
            }
            column_offset += row_width;
        }

        let mut coset_size = self.next_order(polynomial_length).unwrap();
        while codeword_length % coset_size != 0 {
            coset_size = self.next_order(coset_size + 1).unwrap();
        }
        let num_cosets = codeword_length / coset_size;

        let chunk_size = coset_size * num_polynomials;
        for k in 1..num_cosets {
            result.copy_within(0..chunk_size, k * chunk_size);
        }

        ntt_nr(&mut result, codeword_length, num_cosets);

        Buffer::from(result)
    }

    fn generator(&self, codeword_length: usize) -> Fr {
        Fr::get_root_of_unity(codeword_length as u64).unwrap()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use {
        super::*,
        ark_ff::{BigInt, PrimeField},
        proptest::{collection, prelude::*},
        whir::algebra::ntt::NttEngine,
    };

    fn fr() -> impl Strategy<Value = Fr> + Clone {
        proptest::array::uniform4(0u64..).prop_map(|val| Fr::new(BigInt(val)))
    }

    proptest! {
        #[test]
        fn interleaved_encode_matches_whir_reference(
            log_msg in 0_usize..=4,
            log_extra in 0_usize..=3,
            num_messages in 1_usize..=4,
            log_mask in 0_usize..=3,
            messages_flat in collection::vec(fr(), 0..=64),
            masks_flat in collection::vec(fr(), 0..=64),
        ) {
            let message_length = 1 << log_msg;
            let mask_length: usize = 1 << log_mask;
            let masked_message_length = message_length + mask_length;
            let codeword_length = masked_message_length.next_power_of_two() << log_extra;

            let total = num_messages * message_length;
            let mut data = messages_flat;
            data.resize(total, Fr::ZERO);

            let messages: Vec<Buffer<Fr>> = data
                .chunks(message_length)
                .map(Buffer::from)
                .collect();
            let messages_refs: Vec<&Buffer<Fr>> = messages.iter().collect();

            let mask_total = num_messages * mask_length;
            let mut masks = masks_flat;
            masks.resize(mask_total, Fr::ZERO);

            let masks = Buffer::from(masks);
            let mask_refs = [&masks];
            let segments = [
                whir::algebra::ntt::PolynomialSegment::from_rows(&messages_refs, 1),
                whir::algebra::ntt::PolynomialSegment::from_rows(&mask_refs, num_messages),
            ];

            let indices: Vec<usize> = (0..codeword_length).collect();

            let reference = NttEngine::<Fr>::new_from_fftfield();
            let our_codeword = RSFr.interleaved_encode(
                Polynomials::from_segments(&segments),
                codeword_length,
            );
            let ref_codeword = reference.interleaved_encode(
                Polynomials::from_segments(&segments),
                codeword_length,
            );

            let our_points =
                RSFr.evaluation_points(masked_message_length, codeword_length, &indices);
            let ref_points =
                reference.evaluation_points(masked_message_length, codeword_length, &indices);

            // Pair each evaluation point with its num_messages-wide slice, then sort
            // by point so that ordering differences between implementations don't matter.
            let mut our_rows: Vec<_> = our_points.iter().enumerate()
                .map(|(i, pt)| (pt.into_bigint(), &our_codeword.to_slice()[i * num_messages..(i + 1) * num_messages]))
                .collect();
            our_rows.sort_by_key(|(k, _)| *k);

            let mut ref_rows: Vec<_> = ref_points.iter().enumerate()
                .map(|(i, pt)| (pt.into_bigint(), &ref_codeword.to_slice()[i * num_messages..(i + 1) * num_messages]))
                .collect();
            ref_rows.sort_by_key(|(k, _)| *k);

            prop_assert_eq!(our_rows, ref_rows);
        }
    }
}
