use {
    crate::{
        memory::{MemoryBlock, MemoryOperation},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_std::{ops::Neg, One},
    provekit_common::{
        witness::{SumTerm, WitnessBuilder, WitnessCoefficient},
        FieldElement,
    },
};

/// Add witnesses and constraints enforcing the integrity of read operations
/// on a read-only memory block, using LogUp.
pub(crate) fn add_rom_checking(r1cs_compiler: &mut NoirToR1CSCompiler, block: &MemoryBlock) {
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
    let wb = WitnessBuilder::MultiplicitiesForRange(
        r1cs_compiler.num_witnesses(),
        memory_length,
        addr_witnesses,
    );
    let access_counts_first_witness = r1cs_compiler.add_witness_builder(wb);

    // Add two verifier challenges for the lookup
    let rs_challenge =
        r1cs_compiler.add_witness_builder(WitnessBuilder::Challenge(r1cs_compiler.num_witnesses()));
    let sz_challenge =
        r1cs_compiler.add_witness_builder(WitnessBuilder::Challenge(r1cs_compiler.num_witnesses()));

    // Calculate the sum, over all reads, of 1/denominator
    let summands_for_reads = block
        .operations
        .iter()
        .map(|op| match op {
            MemoryOperation::Load(addr_witness, value) => add_indexed_lookup_factor(
                r1cs_compiler,
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
        .map(|coeff| SumTerm(None, coeff))
        .collect();
    let sum_for_reads = r1cs_compiler.add_sum(summands_for_reads);

    // Calculate the sum over all table elements of multiplicity/factor
    let summands_for_table = block
        .initial_value_witnesses
        .iter()
        .zip(0..memory_length)
        .enumerate()
        .map(|(addr, (value, access_count_idx_offset))| {
            let multiplicity =
                access_counts_first_witness + access_count_idx_offset;
            add_indexed_table_entry_quotient(
                r1cs_compiler,
                rs_challenge,
                sz_challenge,
                FieldElement::from(addr as u64),
                r1cs_compiler.witness_one(),
                *value,
                multiplicity,
            )
        })
        .map(|coeff| SumTerm(None, coeff))
        .collect();
    let sum_for_table = r1cs_compiler.add_sum(summands_for_table);

    // Enforce that the two sums are equal
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), sum_for_reads)],
        &[(FieldElement::one(), sum_for_table)],
    );
}

/// Fused table-entry quotient for ROM LogUp.
///
/// Computes quotient = multiplicity / denominator using 2 R1CS constraints
/// instead of the 3 that `add_indexed_lookup_factor` + `add_product` would
/// need:
///   Constraint 1: rs × value = sz − index·index_witness − denominator
///   Constraint 2: denominator × quotient = multiplicity   (fused)
fn add_indexed_table_entry_quotient(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    rs_challenge: usize,
    sz_challenge: usize,
    index: FieldElement,
    index_witness: usize,
    value: usize,
    multiplicity_witness: usize,
) -> usize {
    // Create denominator witness
    let wb = WitnessBuilder::IndexedLogUpDenominator(
        r1cs_compiler.num_witnesses(),
        sz_challenge,
        WitnessCoefficient(index, index_witness),
        rs_challenge,
        value,
    );
    let denominator = r1cs_compiler.add_witness_builder(wb);
    // Constraint 1: rs × value = −denom + sz − index·index_witness
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), rs_challenge)],
        &[(FieldElement::one(), value)],
        &[
            (FieldElement::one().neg(), denominator),
            (FieldElement::one(), sz_challenge),
            (index.neg(), index_witness),
        ],
    );

    // Inverse witness (needed by solver for batch inversion, not constrained)
    let inverse = r1cs_compiler.add_witness_builder(WitnessBuilder::Inverse(
        r1cs_compiler.num_witnesses(),
        denominator,
    ));

    // Quotient = multiplicity × inverse (computed by solver)
    let quotient = r1cs_compiler.add_witness_builder(WitnessBuilder::Product(
        r1cs_compiler.num_witnesses(),
        multiplicity_witness,
        inverse,
    ));

    // Constraint 2 (fused): denominator × quotient = multiplicity
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), denominator)],
        &[(FieldElement::one(), quotient)],
        &[(FieldElement::one(), multiplicity_witness)],
    );

    quotient
}

// Helper function for adding a new lookup factor to the R1CS instance.
// Adds a new witness `denominator` and constrains it to represent
//    `denominator - (sz_challenge - (index_coeff * index + rs_challenge *
// value)) == 0`, where `sz_challenge`, `index`, `rs_challenge` and `value` are
// the provided R1CS witness indices. Finally, adds a new witness for its
// inverse, constrains it to be such, and returns its index.
fn add_indexed_lookup_factor(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    rs_challenge: usize,
    sz_challenge: usize,
    index: FieldElement,
    index_witness: usize,
    value: usize,
) -> usize {
    let wb = WitnessBuilder::IndexedLogUpDenominator(
        r1cs_compiler.num_witnesses(),
        sz_challenge,
        WitnessCoefficient(index, index_witness),
        rs_challenge,
        value,
    );
    let denominator = r1cs_compiler.add_witness_builder(wb);
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), rs_challenge)],
        &[(FieldElement::one(), value)],
        &[
            (FieldElement::one().neg(), denominator),
            (FieldElement::one(), sz_challenge),
            (index.neg(), index_witness),
        ],
    );
    let inverse = r1cs_compiler.add_witness_builder(WitnessBuilder::Inverse(
        r1cs_compiler.num_witnesses(),
        denominator,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), denominator)],
        &[(FieldElement::one(), inverse)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
    );
    inverse
}
