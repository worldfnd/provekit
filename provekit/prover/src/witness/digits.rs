use provekit_common::{
    witness::{decompose_into_digits, DigitalDecompositionWitnesses},
    FieldElement,
};

pub(crate) trait DigitalDecompositionWitnessesSolver {
    fn solve(&self, witness: &mut [Option<FieldElement>]);
}

impl DigitalDecompositionWitnessesSolver for DigitalDecompositionWitnesses {
    fn solve(&self, witness: &mut [Option<FieldElement>]) {
        self.witnesses_to_decompose
            .iter()
            .enumerate()
            .for_each(|(i, value_witness_idx)| {
                let value = witness[*value_witness_idx].unwrap();
                let digits = decompose_into_digits(value, &self.log_bases);
                digits
                    .iter()
                    .enumerate()
                    .for_each(|(digit_place, digit_value)| {
                        witness[self.first_witness_idx
                            + digit_place * self.witnesses_to_decompose.len()
                            + i] = Some(*digit_value);
                    });
            });
    }
}
