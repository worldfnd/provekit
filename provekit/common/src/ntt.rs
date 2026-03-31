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

fn interleaved_rs_encode(messages: &[&[Fr]], masks: &[Fr], codeword_length: usize) -> Vec<Fr> {
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
