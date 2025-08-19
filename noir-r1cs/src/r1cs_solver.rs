use {
    crate::{
        binops::BINOP_ATOMIC_BITS,
        digits::DigitalDecompositionWitnesses,
        noir_to_r1cs::ConstantOrR1CSWitness,
        ram::SpiceWitnesses,
        skyscraper::SkyscraperSponge,
        utils::{noir_to_native, serde_ark, serde_ark_option},
        FieldElement,
    },
    acir::{native_types::WitnessMap, FieldElement as NoirFieldElement},
    ark_ff::{Field, PrimeField},
    ark_std::Zero,
    serde::{Deserialize, Serialize},
    spongefish::{codecs::arkworks_algebra::UnitToField, ProverState},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SumTerm(
    #[serde(with = "serde_ark_option")] pub Option<FieldElement>,
    pub usize,
);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConstantTerm(pub usize, #[serde(with = "serde_ark")] pub FieldElement);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessCoefficient(#[serde(with = "serde_ark")] pub FieldElement, pub usize);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductLinearTerm(
    pub usize,
    #[serde(with = "serde_ark")] pub FieldElement,
    #[serde(with = "serde_ark")] pub FieldElement,
);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// Indicates how to solve for a collection of R1CS witnesses in terms of
/// earlier (i.e. already solved for) R1CS witnesses and/or ACIR witness values.
pub enum WitnessBuilder {
    /// Constant value, used for the constant one witness & e.g. static lookups
    /// (witness index, constant value)
    Constant(ConstantTerm),
    /// A witness value carried over from the ACIR circuit (at the specified
    /// ACIR witness index) (includes ACIR inputs and outputs)
    /// (witness index, ACIR witness index)
    Acir(usize, usize),
    /// A linear combination of witness values, where the coefficients are field
    /// elements. First argument is the witness index of the sum.
    /// Vector consists of (optional coefficient, witness index) tuples, one for
    /// each summand. The coefficient is optional, and if it is None, the
    /// coefficient is 1.
    Sum(usize, Vec<SumTerm>),
    /// The product of the values at two specified witness indices
    /// (witness index, operand witness index a, operand witness index b)
    Product(usize, usize, usize),
    /// Solves for the number of times that each memory address occurs in
    /// read-only memory. Arguments: (first witness index, range size,
    /// vector of all witness indices for values purported to be in the range)
    MultiplicitiesForRange(usize, usize, Vec<usize>),
    /// A Fiat-Shamir challenge value
    /// (witness index)
    Challenge(usize),
    /// For solving for the denominator of an indexed lookup.
    /// Fields are (witness index, sz_challenge, (index_coeff, index),
    /// rs_challenge, value).
    IndexedLogUpDenominator(usize, usize, WitnessCoefficient, usize, usize),
    /// The inverse of the value at a specified witness index
    /// (witness index, operand witness index)
    Inverse(usize, usize),
    /// Products with linear operations on the witness indices.
    /// Fields are ProductLinearOperation(witness_idx, (index, a, b), (index, c,
    /// d)) such that we wish to compute (ax + b) * (cx + d).
    ProductLinearOperation(usize, ProductLinearTerm, ProductLinearTerm),
    /// For solving for the denominator of a lookup (non-indexed).
    /// Field are (witness index, sz_challenge, (value_coeff, value)).
    LogUpDenominator(usize, usize, WitnessCoefficient),
    /// Builds the witnesses values required for the mixed base digital
    /// decomposition of other witness values.
    DigitalDecomposition(DigitalDecompositionWitnesses),
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
        WitnessCoefficient,
        usize,
        WitnessCoefficient,
    ),
    /// Builds the witnesses values required for the Spice memory model.
    /// (Note that some witness values are already solved for by the ACIR
    /// solver.)
    SpiceWitnesses(SpiceWitnesses),
    /// A witness value for the denominator of a bin op lookup.
    /// Arguments: `(witness index, sz_challenge, rs_challenge,
    /// rs_challenge_sqrd, lhs, rhs, output)`, where `lhs`, `rhs`, and
    /// `output` are either constant or witness values.
    BinOpLookupDenominator(
        usize,
        usize,
        usize,
        usize,
        ConstantOrR1CSWitness,
        ConstantOrR1CSWitness,
        ConstantOrR1CSWitness,
    ),
    /// Witness values for the number of times that each pair of input values
    /// occurs in the bin op.
    MultiplicitiesForBinOp(usize, Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness)>),
}

impl WitnessBuilder {
    /// The number of witness values that this builder writes to the witness
    /// vector.
    pub fn num_witnesses(&self) -> usize {
        match self {
            WitnessBuilder::MultiplicitiesForRange(_, range_size, _) => *range_size,
            WitnessBuilder::DigitalDecomposition(dd_struct) => dd_struct.num_witnesses,
            WitnessBuilder::SpiceWitnesses(spice_witnesses_struct) => {
                spice_witnesses_struct.num_witnesses
            }
            WitnessBuilder::MultiplicitiesForBinOp(..) => 2usize.pow(2 * BINOP_ATOMIC_BITS as u32),
            _ => 1,
        }
    }

    /// Return the index of the first witness value that this builder writes to.
    pub fn first_witness_idx(&self) -> usize {
        match self {
            WitnessBuilder::Constant(ConstantTerm(start_idx, _)) => *start_idx,
            WitnessBuilder::Acir(start_idx, _) => *start_idx,
            WitnessBuilder::Sum(start_idx, _) => *start_idx,
            WitnessBuilder::Product(start_idx, ..) => *start_idx,
            WitnessBuilder::MultiplicitiesForRange(start_idx, ..) => *start_idx,
            WitnessBuilder::IndexedLogUpDenominator(start_idx, ..) => *start_idx,
            WitnessBuilder::Challenge(start_idx) => *start_idx,
            WitnessBuilder::Inverse(start_idx, _) => *start_idx,
            WitnessBuilder::LogUpDenominator(start_idx, ..) => *start_idx,
            WitnessBuilder::ProductLinearOperation(start_idx, ..) => *start_idx,
            WitnessBuilder::DigitalDecomposition(dd_struct) => dd_struct.first_witness_idx,
            WitnessBuilder::SpiceMultisetFactor(start_idx, ..) => *start_idx,
            WitnessBuilder::SpiceWitnesses(spice_witnesses_struct) => {
                spice_witnesses_struct.first_witness_idx
            }

            WitnessBuilder::BinOpLookupDenominator(start_idx, ..) => *start_idx,
            WitnessBuilder::MultiplicitiesForBinOp(start_idx, _) => *start_idx,
        }
    }

    /// Solves for the witness value(s) specified by this builder and writes
    /// them to the witness vector.
    pub fn solve(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<NoirFieldElement>,
        witness: &mut [Option<FieldElement>],
        transcript: &mut ProverState<SkyscraperSponge, FieldElement>,
    ) {
        match self {
            WitnessBuilder::Constant(ConstantTerm(witness_idx, c)) => {
                witness[*witness_idx] = Some(*c);
            }
            WitnessBuilder::Acir(witness_idx, acir_witness_idx) => {
                witness[*witness_idx] = Some(noir_to_native(
                    *acir_witness_idx_to_value_map
                        .get_index(*acir_witness_idx as u32)
                        .unwrap(),
                ));
            }
            WitnessBuilder::Sum(witness_idx, operands) => {
                witness[*witness_idx] = Some(
                    operands
                        .iter()
                        .map(|SumTerm(coeff, witness_idx)| {
                            if let Some(coeff) = coeff {
                                *coeff * witness[*witness_idx].unwrap()
                            } else {
                                witness[*witness_idx].unwrap()
                            }
                        })
                        .fold(FieldElement::zero(), |acc, x| acc + x),
                );
            }
            WitnessBuilder::Product(witness_idx, operand_idx_a, operand_idx_b) => {
                let a: FieldElement = witness[*operand_idx_a].unwrap();
                let b: FieldElement = witness[*operand_idx_b].unwrap();
                witness[*witness_idx] = Some(a * b);
            }
            WitnessBuilder::Inverse(witness_idx, operand_idx) => {
                let operand: FieldElement = witness[*operand_idx].unwrap();
                witness[*witness_idx] = Some(operand.inverse().unwrap());
            }
            WitnessBuilder::IndexedLogUpDenominator(
                witness_idx,
                sz_challenge,
                WitnessCoefficient(index_coeff, index),
                rs_challenge,
                value,
            ) => {
                let index = witness[*index].unwrap();
                let value = witness[*value].unwrap();
                let rs_challenge = witness[*rs_challenge].unwrap();
                let sz_challenge = witness[*sz_challenge].unwrap();
                witness[*witness_idx] =
                    Some(sz_challenge - (*index_coeff * index + rs_challenge * value));
            }
            WitnessBuilder::MultiplicitiesForRange(start_idx, range_size, value_witnesses) => {
                let mut multiplicities = vec![0u32; *range_size];
                for value_witness_idx in value_witnesses {
                    // If the value is representable as just a u64, then it should be the least
                    // significant value in the BigInt representation.
                    let value = witness[*value_witness_idx].unwrap().into_bigint().0[0];
                    multiplicities[value as usize] += 1;
                }
                for (i, count) in multiplicities.iter().enumerate() {
                    witness[start_idx + i] = Some(FieldElement::from(*count));
                }
            }
            WitnessBuilder::Challenge(witness_idx) => {
                let mut one = [FieldElement::zero(); 1];
                let _ = transcript.fill_challenge_scalars(&mut one);
                witness[*witness_idx] = Some(one[0]);
            }
            WitnessBuilder::LogUpDenominator(
                witness_idx,
                sz_challenge,
                WitnessCoefficient(value_coeff, value),
            ) => {
                witness[*witness_idx] = Some(
                    witness[*sz_challenge].unwrap() - (*value_coeff * witness[*value].unwrap()),
                );
            }
            WitnessBuilder::ProductLinearOperation(
                witness_idx,
                ProductLinearTerm(x, a, b),
                ProductLinearTerm(y, c, d),
            ) => {
                witness[*witness_idx] =
                    Some((*a * witness[*x].unwrap() + *b) * (*c * witness[*y].unwrap() + *d));
            }
            WitnessBuilder::DigitalDecomposition(dd_struct) => {
                dd_struct.solve(witness);
            }
            WitnessBuilder::SpiceMultisetFactor(
                witness_idx,
                sz_challenge,
                rs_challenge,
                WitnessCoefficient(addr, addr_witness),
                value,
                WitnessCoefficient(timer, timer_witness),
            ) => {
                witness[*witness_idx] = Some(
                    witness[*sz_challenge].unwrap()
                        - (*addr * witness[*addr_witness].unwrap()
                            + witness[*rs_challenge].unwrap() * witness[*value].unwrap()
                            + witness[*rs_challenge].unwrap()
                                * witness[*rs_challenge].unwrap()
                                * *timer
                                * witness[*timer_witness].unwrap()),
                );
            }
            WitnessBuilder::SpiceWitnesses(spice_witnesses) => {
                spice_witnesses.solve(witness);
            }
            WitnessBuilder::BinOpLookupDenominator(
                witness_idx,
                sz_challenge,
                rs_challenge,
                rs_challenge_sqrd,
                lhs,
                rhs,
                output,
            ) => {
                let lhs = match lhs {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let rhs = match rhs {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let output = match output {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                witness[*witness_idx] = Some(
                    witness[*sz_challenge].unwrap()
                        - (lhs
                            + witness[*rs_challenge].unwrap() * rhs
                            + witness[*rs_challenge_sqrd].unwrap() * output),
                );
            }
            WitnessBuilder::MultiplicitiesForBinOp(witness_idx, operands) => {
                let mut multiplicities = vec![0u32; 2usize.pow(2 * BINOP_ATOMIC_BITS as u32)];
                for (lhs, rhs) in operands {
                    let lhs = match lhs {
                        ConstantOrR1CSWitness::Constant(c) => *c,
                        ConstantOrR1CSWitness::Witness(witness_idx) => {
                            witness[*witness_idx].unwrap()
                        }
                    };
                    let rhs = match rhs {
                        ConstantOrR1CSWitness::Constant(c) => *c,
                        ConstantOrR1CSWitness::Witness(witness_idx) => {
                            witness[*witness_idx].unwrap()
                        }
                    };
                    let index =
                        (lhs.into_bigint().0[0] << BINOP_ATOMIC_BITS) + rhs.into_bigint().0[0];
                    multiplicities[index as usize] += 1;
                }
                for (i, count) in multiplicities.iter().enumerate() {
                    witness[witness_idx + i] = Some(FieldElement::from(*count));
                }
            }
        }
    }
}
