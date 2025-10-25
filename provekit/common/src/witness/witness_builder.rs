use {
    crate::{
        utils::{serde_ark, serde_ark_option},
        witness::{
            binops::BINOP_ATOMIC_BITS,
            digits::DigitalDecompositionWitnesses,
            layer_scheduler::{
                LayerScheduler, LayeredWitnessBuilders, SplitWitnessBuilders, WitnessIndexRemapper,
                WitnessSplitter,
            },
            ram::SpiceWitnesses,
            ConstantOrR1CSWitness,
        },
        FieldElement, R1CS,
    },
    serde::{Deserialize, Serialize},
    std::num::NonZeroU32,
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
    /// U32 addition with carry: computes result = (a + b) % 2^32 and carry = (a
    /// + b) / 2^32 Arguments: (result_witness_index, carry_witness_index,
    /// a, b)
    U32Addition(usize, usize, ConstantOrR1CSWitness, ConstantOrR1CSWitness),
    /// AND operation: computes result = a & b
    /// Arguments: (result_witness_index, a, b)
    /// Note: only for 32-bit operands
    And(usize, ConstantOrR1CSWitness, ConstantOrR1CSWitness),
    /// XOR operation: computes result = a ⊕ b
    /// Arguments: (result_witness_index, a, b)
    /// Note: only for 32-bit operands
    Xor(usize, ConstantOrR1CSWitness, ConstantOrR1CSWitness),
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
            WitnessBuilder::U32Addition(..) => 2,
            _ => 1,
        }
    }

    /// Constructs a layered execution plan optimized for batch inversion.
    ///
    /// Uses frontier-based scheduling to group operations and minimize
    /// expensive field inversions via Montgomery's batch inversion trick.
    pub fn prepare_layers(witness_builders: &[WitnessBuilder]) -> LayeredWitnessBuilders {
        if witness_builders.is_empty() {
            return LayeredWitnessBuilders { layers: Vec::new() };
        }

        let scheduler = LayerScheduler::new(witness_builders);
        scheduler.build_layers()
    }

    /// Splits witness builders into w1/w2, remaps indices, and schedules both
    /// groups.
    ///
    /// This enables sound challenge generation:
    /// 1. Split builders: w1 = transitive deps of lookups, w2 = challenges +
    ///    dependents
    /// 2. Remap witness indices: w1 → [0, k), w2 → [k, n)
    /// 3. Remap R1CS matrices and ACIR witness map
    /// 4. Schedule both groups with batch inversions
    ///
    /// Returns (SplitWitnessBuilders, remapped R1CS, remapped witness
    /// map)
    pub fn split_and_prepare_layers(
        witness_builders: &[WitnessBuilder],
        r1cs: R1CS,
        witness_map: Vec<Option<NonZeroU32>>,
    ) -> (SplitWitnessBuilders, R1CS, Vec<Option<NonZeroU32>>) {
        if witness_builders.is_empty() {
            return (
                SplitWitnessBuilders {
                    w1_layers: LayeredWitnessBuilders { layers: Vec::new() },
                    w2_layers: LayeredWitnessBuilders { layers: Vec::new() },
                    w1_size:   0,
                },
                r1cs,
                witness_map,
            );
        }

        // Step 1: Analyze dependencies and split into w1/w2
        let splitter = WitnessSplitter::new(witness_builders);
        let (w1_indices, w2_indices) = splitter.split_builders();

        // Step 2: Extract w1 and w2 builders in order
        let w1_builders: Vec<WitnessBuilder> = w1_indices
            .iter()
            .map(|&idx| witness_builders[idx].clone())
            .collect();

        let w2_builders: Vec<WitnessBuilder> = w2_indices
            .iter()
            .map(|&idx| witness_builders[idx].clone())
            .collect();

        // Step 3: Create witness index remapper
        let remapper = WitnessIndexRemapper::new(&w1_builders, &w2_builders);
        let w1_size = remapper.w1_size;

        // Step 4: Remap all builders
        let remapped_w1_builders: Vec<WitnessBuilder> = w1_builders
            .iter()
            .map(|b| remapper.remap_builder(b))
            .collect();

        let remapped_w2_builders: Vec<WitnessBuilder> = w2_builders
            .iter()
            .map(|b| remapper.remap_builder(b))
            .collect();

        // Step 5: Remap R1CS and witness map
        let remapped_r1cs = remapper.remap_r1cs(r1cs);
        let remapped_witness_map = remapper.remap_acir_witness_map(witness_map);

        // Step 6: Schedule both groups independently with batch inversions
        let w1_layers = if remapped_w1_builders.is_empty() {
            LayeredWitnessBuilders { layers: Vec::new() }
        } else {
            let scheduler = LayerScheduler::new(&remapped_w1_builders);
            scheduler.build_layers()
        };

        let w2_layers = if remapped_w2_builders.is_empty() {
            LayeredWitnessBuilders { layers: Vec::new() }
        } else {
            let scheduler = LayerScheduler::new(&remapped_w2_builders);
            scheduler.build_layers()
        };

        (
            SplitWitnessBuilders {
                w1_layers,
                w2_layers,
                w1_size,
            },
            remapped_r1cs,
            remapped_witness_map,
        )
    }
}
