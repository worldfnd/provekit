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

                // TODO Optimise generator away by storing it in the engine
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
        interleaved_rs_encode(messages, masks, codeword_length)
    }
}

fn interleaved_rs_encode(messages: &[&[Fr]], _masks: &[Fr], codeword_length: usize) -> Vec<Fr> {
    if messages.is_empty() {
        return vec![];
    }

    let num_messages = messages.len();

    let message_length = messages[0].len();
    for message in messages {
        assert_eq!(message_length, message.len())
    }

    let expanded_size = num_messages * codeword_length;

    let mut result = vec![Fr::ZERO; expanded_size];

    for (row, message) in messages.iter().enumerate() {
        for (column, element) in message.iter().enumerate() {
            result[column * num_messages + row] = *element;
        }
    }

    ntt_nr(&mut result, codeword_length);
    result
}

#[cfg(test)]
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

    // Sort a codeword by evaluation point so ordering differences don't matter.
    fn sort_by_points(
        rs: &dyn whir::algebra::ntt::ReedSolomon<Fr>,
        message_length: usize,
        codeword_length: usize,
        num_messages: usize,
        codeword: &[Fr],
    ) -> Vec<Vec<Fr>> {
        let indices: Vec<usize> = (0..codeword_length).collect();
        let points = rs.evaluation_points(message_length, codeword_length, &indices);
        let mut rows: Vec<(ark_ff::BigInt<4>, Vec<Fr>)> = points
            .iter()
            .enumerate()
            .map(|(i, pt)| {
                let values: Vec<Fr> = (0..num_messages)
                    .map(|row| codeword[i * num_messages + row])
                    .collect();
                (pt.into_bigint(), values)
            })
            .collect();
        rows.sort_by_key(|(k, _)| *k);
        rows.into_iter().map(|(_, v)| v).collect()
    }

    proptest! {
        #[test]
        fn interleaved_encode_matches_whir_reference(
            log_msg in 0_usize..=4,
            log_extra in 0_usize..=3,
            num_messages in 1_usize..=4,
            messages_flat in collection::vec(fr(), 0..=64),
        ) {
            let message_length = 1 << log_msg;
            let codeword_length = message_length << log_extra;

            let total = num_messages * message_length;
            let mut data = messages_flat;
            data.resize(total, Fr::ZERO);

            let messages: Vec<&[Fr]> = data.chunks(message_length).collect();

            let reference = NttEngine::<Fr>::new_from_fftfield();
            let our_codeword = RSFr.interleaved_encode(&messages, &[], codeword_length);
            let ref_codeword = reference.interleaved_encode(&messages, &[], codeword_length);

            let our_sorted = sort_by_points(&RSFr, message_length, codeword_length, num_messages, &our_codeword);
            let ref_sorted = sort_by_points(&reference, message_length, codeword_length, num_messages, &ref_codeword);

            prop_assert_eq!(our_sorted, ref_sorted);
        }
    }
}
