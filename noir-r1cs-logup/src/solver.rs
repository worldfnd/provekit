use {
    crate::{digits::DigitalDecompositionWitnesses, ram::SpiceWitnesses},
    acir::{
        native_types::{Witness as AcirWitness, WitnessMap},
        AcirField, FieldElement,
    },
    rand::Rng,
};

#[derive(Debug, Clone)]
/// Indicates how to solve for a collection of R1CS witnesses in terms of
/// earlier (i.e. already solved for) R1CS witnesses and/or ACIR witness values.
pub enum WitnessBuilder {
    /// Constant value, used for the constant one witness & e.g. static lookups
    /// (witness index, constant value)
    Constant(usize, FieldElement),
    /// A witness value carried over from the ACIR circuit (at the specified
    /// ACIR witness index) (includes ACIR inputs and outputs)
    /// (witness index, ACIR witness index)
    Acir(usize, usize),
    /// A Fiat-Shamir challenge value
    /// (witness index)
    Challenge(usize),
    /// The inverse of the value at a specified witness index
    /// (witness index, operand witness index)
    Inverse(usize, usize),
    /// A linear combination of witness values, where the coefficients are field
    /// elements. First argument is the witness index of the sum.
    /// Vector consists of (optional coefficient, witness index) tuples, one for
    /// each summand. The coefficient is optional, and if it is None, the
    /// coefficient is 1.
    Sum(usize, Vec<(Option<FieldElement>, usize)>),
    /// The product of the values at two specified witness indices
    /// (witness index, operand witness index a, operand witness index b)
    Product(usize, usize, usize),
    /// Solves for the number of times that each memory address occurs in
    /// read-only memory. Arguments: (first witness index, range size,
    /// vector of all witness indices for values purported to be in the range)
    MultiplicitiesForRange(usize, usize, Vec<usize>),
    /// For solving for the denominator of an indexed lookup.
    /// Fields are (witness index, sz_challenge, (index_coeff, index),
    /// rs_challenge, value).
    IndexedLogUpDenominator(usize, usize, (FieldElement, usize), usize, usize),
    /// For solving for the denominator of a lookup (non-indexed).
    /// Field are (witness index, sz_challenge, (value_coeff, value)).
    LogUpDenominator(usize, usize, (FieldElement, usize)),
    /// Products with linear operations on the witness indices.
    /// Fields are ProductLinearOperation(witness_idx, (index, a, b), (index, c,
    /// d)) such that we wish to compute (ax + b) * (cx + d).
    ProductLinearOperation(
        usize,
        (usize, FieldElement, FieldElement),
        (usize, FieldElement, FieldElement),
    ),
    /// A factor of the multiset check used in read/write memory checking.
    /// Values: (witness index, sz_challenge, rs_challenge, (addr,
    /// addr_witness), value, (timer, timer_witness)) where sz_challenge,
    /// rs_challenge, addr_witness, timer_witness are witness indices.
    /// Solver computes:
    /// sz_challenge - (addr * addr_witness + rs_challenge * value +
    /// rs_challenge * rs_challenge * timer * timer_witness)
    SpiceMultisetFactor(
        usize,
        usize,
        usize,
        (FieldElement, usize),
        usize,
        (FieldElement, usize),
    ),
    /// Builds the witnesses values required for the Spice memory model.
    /// (Note that some witness values are already solved for by the ACIR
    /// solver.)
    SpiceWitnesses(SpiceWitnesses),
    /// Builds the witnesses values required for the mixed base digital
    /// decomposition of other witness values.
    DigitalDecomposition(DigitalDecompositionWitnesses),
}

impl WitnessBuilder {
    /// The number of witness values that this builder writes to the witness
    /// vector.
    pub fn num_witnesses(&self) -> usize {
        match self {
            WitnessBuilder::Constant(..) => 1,
            WitnessBuilder::Acir(..) => 1,
            WitnessBuilder::Challenge(_) => 1,
            WitnessBuilder::Inverse(..) => 1,
            WitnessBuilder::Sum(..) => 1,
            WitnessBuilder::Product(..) => 1,
            WitnessBuilder::MultiplicitiesForRange(_, range_size, _) => *range_size,
            WitnessBuilder::IndexedLogUpDenominator(..) => 1,
            WitnessBuilder::LogUpDenominator(..) => 1,
            WitnessBuilder::ProductLinearOperation(..) => 1,
            WitnessBuilder::SpiceMultisetFactor(..) => 1,
            WitnessBuilder::SpiceWitnesses(spice_witnesses_struct) => {
                spice_witnesses_struct.num_witnesses
            }
            WitnessBuilder::DigitalDecomposition(dd_struct) => dd_struct.num_witnesses,
        }
    }

    /// Return the index of the first witness value that this builder writes to.
    pub fn first_witness_idx(&self) -> usize {
        match self {
            WitnessBuilder::Constant(start_idx, _) => *start_idx,
            WitnessBuilder::Acir(start_idx, _) => *start_idx,
            WitnessBuilder::Challenge(start_idx) => *start_idx,
            WitnessBuilder::Inverse(start_idx, _) => *start_idx,
            WitnessBuilder::Sum(start_idx, _) => *start_idx,
            WitnessBuilder::Product(start_idx, ..) => *start_idx,
            WitnessBuilder::MultiplicitiesForRange(start_idx, ..) => *start_idx,
            WitnessBuilder::IndexedLogUpDenominator(start_idx, ..) => *start_idx,
            WitnessBuilder::LogUpDenominator(start_idx, ..) => *start_idx,
            WitnessBuilder::ProductLinearOperation(start_idx, ..) => *start_idx,
            WitnessBuilder::SpiceMultisetFactor(start_idx, ..) => *start_idx,
            WitnessBuilder::SpiceWitnesses(spice_witnesses_struct) => {
                spice_witnesses_struct.first_witness_idx
            }
            WitnessBuilder::DigitalDecomposition(dd_struct) => dd_struct.first_witness_idx,
        }
    }

    /// As per solve(), but additionally appends the solved witness values to
    /// the transcript.
    pub fn solve_and_append_to_transcript(
        &self,
        witness: &mut [FieldElement],
        acir_witnesses: &WitnessMap<FieldElement>,
        transcript: &mut MockTranscript,
    ) {
        self.solve(witness, acir_witnesses, transcript);
        for i in 0..self.num_witnesses() {
            transcript.append(witness[self.first_witness_idx() + i]);
        }
    }

    /// Solves for the witness value(s) specified by this builder and writes
    /// them to the witness vector.
    pub fn solve(
        &self,
        witness: &mut [FieldElement],
        acir_witnesses: &WitnessMap<FieldElement>,
        transcript: &mut MockTranscript,
    ) {
        match self {
            WitnessBuilder::Constant(witness_idx, c) => {
                witness[*witness_idx] = *c;
            }
            WitnessBuilder::Acir(witness_idx, acir_witness_idx) => {
                witness[*witness_idx] = acir_witnesses[&AcirWitness(*acir_witness_idx as u32)];
            }
            WitnessBuilder::Challenge(witness_idx) => {
                witness[*witness_idx] = transcript.draw_challenge();
            }
            WitnessBuilder::Inverse(witness_idx, operand_idx) => {
                let operand: FieldElement = witness[*operand_idx];
                witness[*witness_idx] = operand.inverse();
            }
            WitnessBuilder::Sum(witness_idx, operands) => {
                witness[*witness_idx] = operands
                    .iter()
                    .map(|(coeff, witness_idx)| {
                        if let Some(coeff) = coeff {
                            *coeff * witness[*witness_idx]
                        } else {
                            witness[*witness_idx]
                        }
                    })
                    .fold(FieldElement::zero(), |acc, x| acc + x);
            }
            WitnessBuilder::Product(witness_idx, operand_idx_a, operand_idx_b) => {
                let a: FieldElement = witness[*operand_idx_a];
                let b: FieldElement = witness[*operand_idx_b];
                witness[*witness_idx] = a * b;
            }
            WitnessBuilder::IndexedLogUpDenominator(
                witness_idx,
                sz_challenge,
                (index_coeff, index),
                rs_challenge,
                value,
            ) => {
                let index = witness[*index];
                let value = witness[*value];
                let rs_challenge = witness[*rs_challenge];
                let sz_challenge = witness[*sz_challenge];
                witness[*witness_idx] =
                    sz_challenge - (*index_coeff * index + rs_challenge * value);
            }
            WitnessBuilder::LogUpDenominator(witness_idx, sz_challenge, (value_coeff, value)) => {
                witness[*witness_idx] = witness[*sz_challenge] - (*value_coeff * witness[*value]);
            }
            WitnessBuilder::ProductLinearOperation(witness_idx, (x, a, b), (y, c, d)) => {
                witness[*witness_idx] = (*a * witness[*x] + *b) * (*c * witness[*y] + *d);
            }
            WitnessBuilder::MultiplicitiesForRange(start_idx, range_size, value_witnesses) => {
                let mut multiplicities = vec![0u32; *range_size];
                for value_witness_idx in value_witnesses {
                    let value = witness[*value_witness_idx].try_to_u64().unwrap() as usize;
                    multiplicities[value] += 1;
                }
                for (i, count) in multiplicities.iter().enumerate() {
                    witness[start_idx + i] = FieldElement::from(*count);
                }
            }
            WitnessBuilder::SpiceMultisetFactor(
                witness_idx,
                sz_challenge,
                rs_challenge,
                (addr, addr_witness),
                value,
                (timer, timer_witness),
            ) => {
                witness[*witness_idx] = witness[*sz_challenge]
                    - (*addr * witness[*addr_witness]
                        + witness[*rs_challenge] * witness[*value]
                        + witness[*rs_challenge]
                            * witness[*rs_challenge]
                            * *timer
                            * witness[*timer_witness]);
            }
            WitnessBuilder::SpiceWitnesses(spice_witnesses) => {
                spice_witnesses.solve(witness);
            }
            WitnessBuilder::DigitalDecomposition(dd_struct) => {
                dd_struct.solve(witness);
            }
        }
    }
}

/// Mock transcript. To be replaced.
pub struct MockTranscript {}

impl MockTranscript {
    pub fn new() -> Self {
        Self {}
    }

    pub fn append(&mut self, _value: FieldElement) {}

    pub fn draw_challenge(&mut self) -> FieldElement {
        let mut rng = rand::thread_rng();
        let n: u32 = rng.gen();
        n.into()
    }
}
