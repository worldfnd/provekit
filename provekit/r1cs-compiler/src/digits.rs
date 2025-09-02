use {
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    ark_std::One,
    provekit_common::{
        witness::{DigitalDecompositionWitnesses, WitnessBuilder},
        FieldElement,
    },
};

pub trait DigitalDecompositionWitnessesBuilder {
    fn new(
        next_witness_idx: usize,
        log_bases: Vec<usize>,
        witnesses_to_decompose: Vec<usize>,
    ) -> Self;

    fn get_digit_witness_index(&self, digit_place: usize, value_offset: usize) -> usize;
}

impl DigitalDecompositionWitnessesBuilder for DigitalDecompositionWitnesses {
    fn new(
        next_witness_idx: usize,
        log_bases: Vec<usize>,
        witnesses_to_decompose: Vec<usize>,
    ) -> Self {
        let num_witnesses_to_decompose = witnesses_to_decompose.len();
        let digital_decomp_length = log_bases.len();
        Self {
            log_bases,
            num_witnesses_to_decompose,
            witnesses_to_decompose,
            first_witness_idx: next_witness_idx,
            num_witnesses: digital_decomp_length * num_witnesses_to_decompose,
        }
    }

    /// Returns the witness index of the `value_offset`-th witness of the
    /// `digit_place`-th digit. Note that `value_offset` is the index of the
    /// witness in the original list of witnesses (not itself a witness
    /// index).
    fn get_digit_witness_index(&self, digit_place: usize, value_offset: usize) -> usize {
        debug_assert!(digit_place < self.log_bases.len());
        debug_assert!(value_offset < self.num_witnesses_to_decompose);
        self.first_witness_idx + digit_place * self.num_witnesses_to_decompose + value_offset
    }
}

/// Adds the witnesses and constraints for the digital decomposition of the
/// given witnesses in a mixed base decomposition (see
/// [DigitalDecompositionWitnesses]).  Does NOT add constraints for
/// range checking the digits - this is left to the caller (as sometimes these
/// range checks are obviated e.g. by later lookups, as in the case of the binop
/// codes).
pub(crate) fn add_digital_decomposition(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    log_bases: Vec<usize>,
    witnesses_to_decompose: Vec<usize>,
) -> DigitalDecompositionWitnesses {
    let next_witness_idx = r1cs_compiler.num_witnesses();
    let dd_struct = DigitalDecompositionWitnesses::new(
        next_witness_idx,
        log_bases.clone(),
        witnesses_to_decompose,
    );
    r1cs_compiler.add_witness_builder(WitnessBuilder::DigitalDecomposition(dd_struct.clone()));
    // Add the constraints for the digital recomposition
    let mut digit_multipliers = vec![FieldElement::one()];
    for log_base in log_bases[..log_bases.len() - 1].iter() {
        let multiplier = *digit_multipliers.last().unwrap() * FieldElement::from(1u64 << *log_base);
        digit_multipliers.push(multiplier);
    }
    dd_struct
        .witnesses_to_decompose
        .iter()
        .enumerate()
        .for_each(|(i, value)| {
            let mut recomp_summands = vec![];
            digit_multipliers
                .iter()
                .enumerate()
                .for_each(|(digit_place, digit_multiplier)| {
                    let digit_witness = dd_struct.get_digit_witness_index(digit_place, i);
                    recomp_summands.push((FieldElement::from(*digit_multiplier), digit_witness));
                });
            r1cs_compiler.r1cs.add_constraint(
                &[(FieldElement::one(), r1cs_compiler.witness_one())],
                &[(FieldElement::one(), *value)],
                &recomp_summands,
            );
        });
    dd_struct
}
