use {
    ark_bn254::Fr,
    ark_ff::{AdditiveGroup, FftField, Field},
    ntt::ntt_nr,
    tracing::instrument,
    whir::{
        algebra::ntt::{Messages, ReedSolomon},
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

    #[instrument(skip(self, messages, masks), fields(
        num_messages = messages.vectors.len() * messages.interleaving_depth,
        message_len = messages.message_length,
        codeword_length = codeword_length,
        mask_len = masks.len().checked_div(messages.vectors.len() * messages.interleaving_depth)
    ))]
    fn interleaved_encode(
        &self,
        messages: Messages<'_, Fr>,
        masks: &Buffer<Fr>,
        codeword_length: usize,
    ) -> Buffer<Fr> {
        let masks = masks.to_slice();
        let messages = messages
            .vectors
            .iter()
            .flat_map(|message| {
                message
                    .to_slice()
                    .chunks_exact(messages.message_length)
                    .take(messages.interleaving_depth)
            })
            .collect::<Vec<_>>();
        if messages.is_empty() {
            return Buffer::from(vec![]);
        }

        let num_messages = messages.len();

        let message_length = messages[0].len();
        for message in &messages {
            assert_eq!(message_length, message.len())
        }

        let total_size = num_messages * codeword_length;

        let mut result = vec![Fr::ZERO; total_size];

        (0..message_length).for_each(|column| {
            let base = column * num_messages;
            for row in 0..num_messages {
                result[base + row] = messages[row][column];
            }
        });

        result[message_length * num_messages..message_length * num_messages + masks.len()]
            .copy_from_slice(masks);

        let mask_length = masks.len() / num_messages;

        let masked_message_length = message_length + mask_length;

        let mut coset_size = self.next_order(masked_message_length).unwrap();
        while !codeword_length.is_multiple_of(coset_size) {
            coset_size = self.next_order(coset_size + 1).unwrap();
        }
        let num_cosets = codeword_length / coset_size;

        let chunk_size = coset_size * num_messages;
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

            let messages: Vec<Buffer<Fr>> = data.chunks(message_length).map(|c| Buffer::from(c)).collect();
            let messages_refs: Vec<&Buffer<Fr>> = messages.iter().collect();

            // Our masks are interleaved: num_messages x mask_length in row-major order
            // i.e. [m0_c0, m1_c0, m0_c1, m1_c1, ...]
            let mask_total = num_messages * mask_length;
            let mut masks = masks_flat;
            masks.resize(mask_total, Fr::ZERO);

            // Whir expects masks per-message (column-major from our perspective):
            // [m0_c0, m0_c1, ..., m1_c0, m1_c1, ...]
            // Transpose the num_messages x mask_length matrix.
            let mut masks_transposed = vec![Fr::ZERO; mask_total];
            for row in 0..num_messages {
                for col in 0..mask_length {
                    masks_transposed[row * mask_length + col] = masks[col * num_messages + row];
                }
            }

            let messages = Messages::new(&messages_refs, message_length, 1);
            let masks = Buffer::from(masks);
            let masks_transposed = Buffer::from(masks_transposed);

            let indices: Vec<usize> = (0..codeword_length).collect();

            let reference = NttEngine::<Fr>::new_from_fftfield();
            let our_codeword = RSFr.interleaved_encode(messages.clone(), &masks, codeword_length);
            let ref_codeword =
                reference.interleaved_encode(messages, &masks_transposed, codeword_length);

            let our_points = RSFr.evaluation_points(message_length, codeword_length, &indices);
            let ref_points = reference.evaluation_points(message_length, codeword_length, &indices);

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
