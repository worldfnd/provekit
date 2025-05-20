use {
    crate::{
        utils::{noir_to_native, serde_ark, serde_ark_option},
        FieldElement,
    },
    acir::{native_types::WitnessMap, FieldElement as NoirFieldElement},
    ark_std::Zero,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SumTerm(
    #[serde(with = "serde_ark_option")] pub Option<FieldElement>,
    pub usize,
);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConstantTerm(pub usize, #[serde(with = "serde_ark")] pub FieldElement);

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
}

impl WitnessBuilder {
    /// The number of witness values that this builder writes to the witness
    /// vector.
    pub fn num_witnesses(&self) -> usize {
        1
    }

    /// Return the index of the first witness value that this builder writes to.
    pub fn first_witness_idx(&self) -> usize {
        match self {
            WitnessBuilder::Constant(ConstantTerm(start_idx, _)) => *start_idx,
            WitnessBuilder::Acir(start_idx, _) => *start_idx,
            WitnessBuilder::Sum(start_idx, _) => *start_idx,
            WitnessBuilder::Product(start_idx, ..) => *start_idx,
        }
    }

    /// Solves for the witness value(s) specified by this builder and writes
    /// them to the witness vector.
    pub fn solve(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<NoirFieldElement>,
        witness: &mut [Option<FieldElement>],
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
        }
    }
}
