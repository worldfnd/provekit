use {
    crate::witness::{
        ConstantOrR1CSWitness, ConstantTerm, ProductLinearTerm, SumTerm, WitnessBuilder,
        WitnessCoefficient, BINOP_ATOMIC_BITS,
    },
    std::collections::HashMap,
};

/// Pre-computed dependency graph for witness builder scheduling.
///
/// Caches four key pieces of information to avoid repeated traversals:
/// - Which witness indices each builder reads (inputs)
/// - Which builders depend on each builder's outputs (graph edges)
/// - How many dependencies each builder has (in-degree for topological sort)
/// - For each witness: the builder that produces it.
#[derive(Debug)]
pub struct DependencyInfo {
    /// For each builder: the witness indices it reads.
    pub reads:            Vec<Vec<usize>>,
    /// For each builder: the builders that depend on its outputs.
    pub adjacency_list:   Vec<Vec<usize>>,
    /// For each builder: the number of unprocessed dependencies (in-degree).
    pub in_degrees:       Vec<usize>,
    /// For each witness: the builder that produces it.
    pub witness_producer: HashMap<usize, usize>,
}

impl DependencyInfo {
    /// Constructs the dependency graph by analyzing all witness builders.
    ///
    /// This performs three passes:
    /// 1. Extract which witnesses each builder reads
    /// 2. Map each witness to its producer builder
    /// 3. Build adjacency list and compute in-degrees for topological sorting
    pub fn new(witness_builders: &[WitnessBuilder]) -> Self {
        let builder_count = witness_builders.len();

        // Pass 1: Extract read dependencies for each builder
        let reads: Vec<Vec<usize>> = witness_builders.iter().map(Self::extract_reads).collect();

        // Pass 2: Build witness-to-producer mapping
        let mut witness_producer = HashMap::with_capacity(builder_count * 2);
        for (builder_idx, builder) in witness_builders.iter().enumerate() {
            for witness_idx in Self::extract_writes(builder) {
                witness_producer.insert(witness_idx, builder_idx);
            }
        }

        // Pass 3: Construct dependency edges
        let mut adjacency_list = vec![Vec::new(); builder_count];
        let mut in_degrees = vec![0; builder_count];

        for (consumer_idx, read_set) in reads.iter().enumerate() {
            for &required_witness in read_set {
                if let Some(&producer_idx) = witness_producer.get(&required_witness) {
                    if producer_idx != consumer_idx {
                        adjacency_list[producer_idx].push(consumer_idx);
                        in_degrees[consumer_idx] += 1;
                    }
                }
            }
        }

        Self {
            reads,
            adjacency_list,
            in_degrees,
            witness_producer,
        }
    }

    /// Extracts the witness indices that a builder reads as inputs.
    fn extract_reads(wb: &WitnessBuilder) -> Vec<usize> {
        match wb {
            WitnessBuilder::Constant(_)
            | WitnessBuilder::Acir(..)
            | WitnessBuilder::Challenge(_) => vec![],
            WitnessBuilder::Sum(_, ops) => ops.iter().map(|SumTerm(_, idx)| *idx).collect(),
            WitnessBuilder::Product(_, a, b) => vec![*a, *b],
            WitnessBuilder::MultiplicitiesForRange(_, _, values) => values.clone(),
            WitnessBuilder::Inverse(_, x) => vec![*x],
            WitnessBuilder::IndexedLogUpDenominator(
                _,
                sz,
                WitnessCoefficient(_, index),
                rs,
                value,
            ) => {
                vec![*sz, *index, *rs, *value]
            }
            WitnessBuilder::ProductLinearOperation(
                _,
                ProductLinearTerm(x, ..),
                ProductLinearTerm(y, ..),
            ) => {
                vec![*x, *y]
            }
            WitnessBuilder::LogUpDenominator(_, sz, WitnessCoefficient(_, value)) => {
                vec![*sz, *value]
            }
            WitnessBuilder::DigitalDecomposition(dd) => dd.witnesses_to_decompose.clone(),
            WitnessBuilder::SpiceMultisetFactor(
                _,
                sz,
                rs,
                WitnessCoefficient(_, addr_w),
                value,
                WitnessCoefficient(_, timer_w),
            ) => {
                vec![*sz, *rs, *addr_w, *value, *timer_w]
            }
            WitnessBuilder::SpiceWitnesses(sw) => {
                let mut v: Vec<usize> =
                    (sw.initial_values_start..sw.initial_values_start + sw.memory_length).collect();
                for op in &sw.memory_operations {
                    match op {
                        crate::witness::SpiceMemoryOperation::Load(addr, value, _) => {
                            v.extend([*addr, *value]);
                        }
                        crate::witness::SpiceMemoryOperation::Store(addr, _, new_value, _) => {
                            v.extend([*addr, *new_value]);
                        }
                    }
                }
                v
            }
            WitnessBuilder::BinOpLookupDenominator(_, sz, rs, rs2, lhs, rhs, output) => {
                let mut v = vec![*sz, *rs, *rs2];
                for c in [lhs, rhs, output] {
                    if let ConstantOrR1CSWitness::Witness(w) = c {
                        v.push(*w);
                    }
                }
                v
            }
            WitnessBuilder::MultiplicitiesForBinOp(_, pairs) => {
                let mut v = Vec::with_capacity(pairs.len() * 2);
                for (lhs, rhs) in pairs {
                    for c in [lhs, rhs] {
                        if let ConstantOrR1CSWitness::Witness(w) = c {
                            v.push(*w);
                        }
                    }
                }
                v
            }
            WitnessBuilder::U32Addition(_, _, a, b) => {
                let mut v = Vec::new();
                for c in [a, b] {
                    if let ConstantOrR1CSWitness::Witness(w) = c {
                        v.push(*w);
                    }
                }
                v
            }
            WitnessBuilder::And(_, lh, rh) | WitnessBuilder::Xor(_, lh, rh) => {
                let mut v = Vec::new();
                for c in [lh, rh] {
                    if let ConstantOrR1CSWitness::Witness(w) = c {
                        v.push(*w);
                    }
                }
                v
            }
        }
    }

    /// Extracts the witness indices that a builder writes as outputs.
    pub fn extract_writes(wb: &WitnessBuilder) -> Vec<usize> {
        match wb {
            WitnessBuilder::Constant(ConstantTerm(idx, _))
            | WitnessBuilder::Acir(idx, _)
            | WitnessBuilder::Sum(idx, _)
            | WitnessBuilder::Product(idx, ..)
            | WitnessBuilder::Challenge(idx)
            | WitnessBuilder::IndexedLogUpDenominator(idx, ..)
            | WitnessBuilder::Inverse(idx, _)
            | WitnessBuilder::ProductLinearOperation(idx, ..)
            | WitnessBuilder::LogUpDenominator(idx, ..)
            | WitnessBuilder::SpiceMultisetFactor(idx, ..)
            | WitnessBuilder::BinOpLookupDenominator(idx, ..)
            | WitnessBuilder::And(idx, ..)
            | WitnessBuilder::Xor(idx, ..) => vec![*idx],

            WitnessBuilder::MultiplicitiesForRange(start, range, _) => {
                (*start..*start + *range).collect()
            }
            WitnessBuilder::DigitalDecomposition(dd) => {
                (dd.first_witness_idx..dd.first_witness_idx + dd.num_witnesses).collect()
            }
            WitnessBuilder::SpiceWitnesses(sw) => {
                (sw.first_witness_idx..sw.first_witness_idx + sw.num_witnesses).collect()
            }
            WitnessBuilder::MultiplicitiesForBinOp(start, ..) => {
                let n = (2usize).pow(2 * (BINOP_ATOMIC_BITS as u32));
                (*start..*start + n).collect()
            }
            WitnessBuilder::U32Addition(result_idx, carry_idx, ..) => {
                vec![*result_idx, *carry_idx]
            }
        }
    }
}
