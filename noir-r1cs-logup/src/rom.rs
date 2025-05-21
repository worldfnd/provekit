use {
    crate::{
        compiler::R1CS,
        memory::{MemoryBlock, MemoryOperation},
        solver::WitnessBuilder,
    },
    acir::{AcirField, FieldElement},
    std::ops::Neg,
};

/// Add witnesses and constraints enforcing the integrity of read operations
/// on a read-only memory block, using LogUp.
pub(crate) fn add_rom_checking(r1cs: &mut R1CS, block: &MemoryBlock) {
    assert!(
        block.is_read_only(),
        "ROM checking can only be applied to read-only memory blocks"
    );
    let addr_witnesses = block
        .operations
        .iter()
        .map(|op| match op {
            MemoryOperation::Load(addr_witness, _) => *addr_witness,
            MemoryOperation::Store(..) => unreachable!(),
        })
        .collect::<Vec<_>>();
    let memory_length = block.initial_value_witnesses.len();
    let wb =
        WitnessBuilder::MultiplicitiesForRange(r1cs.num_witnesses(), memory_length, addr_witnesses);
    let access_counts_first_witness = r1cs.add_witness_builder(wb);

    // Add two verifier challenges for the lookup
    let rs_challenge = r1cs.add_witness_builder(WitnessBuilder::Challenge(r1cs.num_witnesses()));
    let sz_challenge = r1cs.add_witness_builder(WitnessBuilder::Challenge(r1cs.num_witnesses()));

    // Calculate the sum, over all reads, of 1/denominator
    let summands_for_reads = block
        .operations
        .iter()
        .map(|op| match op {
            MemoryOperation::Load(addr_witness, value) => add_indexed_lookup_factor(
                r1cs,
                rs_challenge,
                sz_challenge,
                FieldElement::one(),
                *addr_witness,
                *value,
            ),
            MemoryOperation::Store(..) => {
                unreachable!();
            }
        })
        .map(|coeff| (None, coeff))
        .collect();
    let sum_for_reads = r1cs.add_sum(summands_for_reads);

    // Calculate the sum over all table elements of multiplicity/factor
    let summands_for_table = block
        .initial_value_witnesses
        .iter()
        .zip(0..memory_length)
        .enumerate()
        .map(|(addr, (value, access_count_idx_offset))| {
            let denominator = add_indexed_lookup_factor(
                r1cs,
                rs_challenge,
                sz_challenge,
                addr.into(),
                r1cs.witness_one(),
                *value,
            );
            r1cs.add_product(
                access_counts_first_witness + access_count_idx_offset,
                denominator,
            )
        })
        .map(|coeff| (None, coeff))
        .collect();
    let sum_for_table = r1cs.add_sum(summands_for_table);

    // Enforce that the two sums are equal
    r1cs.matrices.add_constraint(
        &[(FieldElement::one(), r1cs.witness_one())],
        &[(FieldElement::one(), sum_for_reads)],
        &[(FieldElement::one(), sum_for_table)],
    );
}

// Helper function for adding a new lookup factor to the R1CS instance.
// Adds a new witness `denominator` and constrains it to represent
//    `denominator - (sz_challenge - (index_coeff * index + rs_challenge *
// value)) == 0`, where `sz_challenge`, `index`, `rs_challenge` and `value` are
// the provided R1CS witness indices. Finally, adds a new witness for its
// inverse, constrains it to be such, and returns its index.
fn add_indexed_lookup_factor(
    r1cs: &mut R1CS,
    rs_challenge: usize,
    sz_challenge: usize,
    index: FieldElement,
    index_witness: usize,
    value: usize,
) -> usize {
    let wb = WitnessBuilder::IndexedLogUpDenominator(
        r1cs.num_witnesses(),
        sz_challenge,
        (index, index_witness),
        rs_challenge,
        value,
    );
    let denominator = r1cs.add_witness_builder(wb);
    r1cs.matrices.add_constraint(
        &[(FieldElement::one(), rs_challenge)],
        &[(FieldElement::one(), value)],
        &[
            (FieldElement::one().neg(), denominator),
            (FieldElement::one(), sz_challenge),
            (index.neg(), index_witness),
        ],
    );
    let inverse =
        r1cs.add_witness_builder(WitnessBuilder::Inverse(r1cs.num_witnesses(), denominator));
    r1cs.matrices.add_constraint(
        &[(FieldElement::one(), denominator)],
        &[(FieldElement::one(), inverse)],
        &[(FieldElement::one(), r1cs.witness_one())],
    );
    inverse
}
