use {
    super::WitnessBuilder,
    crate::witness::{
        ConstantOrR1CSWitness, ConstantTerm, ProductLinearTerm, SumTerm, WitnessCoefficient,
        BINOP_ATOMIC_BITS,
    },
    std::{
        collections::{HashMap, HashSet, VecDeque},
        mem,
    },
};

/// Layered plan for serial batched-inversion solving.
///
/// Optimized single-array design:
/// - `builders` contains ALL builders in execution order: [pre1, pre2, ...,
///   inv1, inv2, ..., pre3, ...]
/// - For layer i: PRE slice is `builders[pre_starts[i] .. inverse_starts[i]]`
/// - For layer i: INVERSE slice is `builders[inverse_starts[i] ..
///   pre_starts[i+1] or end]`
/// - Perfect cache locality: execution order = memory order
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct LayeredWitnessBuilders {
    pub builders:       Vec<WitnessBuilder>,
    pub pre_starts:     Vec<usize>,
    pub inverse_starts: Vec<usize>,
}

impl LayeredWitnessBuilders {
    pub fn layers_len(&self) -> usize {
        self.pre_starts.len()
    }

    /// Returns pre-builders for the specified layer
    pub fn pre_builders(&self, layer_idx: usize) -> &[WitnessBuilder] {
        let start = self.pre_starts[layer_idx];
        let end = self.inverse_starts[layer_idx];
        &self.builders[start..end]
    }

    /// Returns inverse-builders for the specified layer
    pub fn inverse_builders(&self, layer_idx: usize) -> &[WitnessBuilder] {
        let start = self.inverse_starts[layer_idx];
        let end = self
            .pre_starts
            .get(layer_idx + 1)
            .copied()
            .unwrap_or(self.builders.len());
        &self.builders[start..end]
    }

    /// Legacy compatibility - returns (start, end) range for pre-builders
    #[deprecated(note = "Use pre_builders() instead")]
    pub fn layer_range(&self, layer_idx: usize) -> (usize, usize) {
        let start = self.pre_starts[layer_idx];
        let end = self.inverse_starts[layer_idx];
        (start, end)
    }
}

/// Cached dependency information for efficient processing
#[derive(Debug)]
struct DependencyInfo {
    reads:          Vec<Vec<usize>>,
    adjacency_list: Vec<Vec<usize>>,
    in_degrees:     Vec<usize>,
}

impl DependencyInfo {
    fn new(witness_builders: &[WitnessBuilder]) -> Self {
        let builder_count = witness_builders.len();

        // Pre-compute all dependency information once
        let reads: Vec<Vec<usize>> = witness_builders.iter().map(Self::extract_reads).collect();

        // Build dependency graph using cached reads
        let mut witness_producer = HashMap::with_capacity(builder_count * 2);
        for (builder_idx, builder) in witness_builders.iter().enumerate() {
            for witness_idx in Self::extract_writes(builder) {
                witness_producer.insert(witness_idx, builder_idx);
            }
        }

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
        }
    }

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
        }
    }

    fn extract_writes(wb: &WitnessBuilder) -> Vec<usize> {
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
            | WitnessBuilder::BinOpLookupDenominator(idx, ..) => vec![*idx],

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
        }
    }
}

/// Optimized layer scheduler with minimal state and cached dependencies
pub struct LayerScheduler<'a> {
    witness_builders: &'a [WitnessBuilder],
    deps:             DependencyInfo,

    // Mutable processing state
    frontier:  VecDeque<usize>,
    processed: Vec<bool>,

    // Layer construction
    pre_layers:              Vec<Vec<usize>>,
    inverse_batches:         Vec<Vec<usize>>,
    current_pre_segment:     Vec<usize>,
    pending_inverse_outputs: HashSet<usize>,
    pending_inverses:        Vec<usize>,
}

impl<'a> LayerScheduler<'a> {
    pub fn new(witness_builders: &'a [WitnessBuilder]) -> Self {
        let deps = DependencyInfo::new(witness_builders);
        let frontier = (0..witness_builders.len())
            .filter(|&i| deps.in_degrees[i] == 0)
            .collect();

        Self {
            witness_builders,
            deps,
            frontier,
            processed: vec![false; witness_builders.len()],
            pre_layers: Vec::new(),
            inverse_batches: Vec::new(),
            current_pre_segment: Vec::new(),
            pending_inverse_outputs: HashSet::new(),
            pending_inverses: Vec::new(),
        }
    }

    pub fn build_layers(mut self) -> LayeredWitnessBuilders {
        while !self.frontier.is_empty() || !self.pending_inverses.is_empty() {
            if !self.process_current_frontier() {
                if !self.pending_inverses.is_empty() {
                    self.flush_layer();
                } else {
                    break;
                }
            }
        }

        if !self.current_pre_segment.is_empty() || !self.pending_inverses.is_empty() {
            self.flush_layer();
        }

        self.build_result()
    }

    fn process_current_frontier(&mut self) -> bool {
        let initial_frontier_size = self.frontier.len();
        let mut deferred = VecDeque::new();

        // Process all ready nodes
        while let Some(node_idx) = self.frontier.pop_front() {
            if self.processed[node_idx] {
                continue;
            }

            if self.can_process_now(node_idx) {
                self.process_node(node_idx);
            } else {
                deferred.push_back(node_idx);
            }
        }

        // Restore deferred nodes
        self.frontier = deferred;

        // Return true if we made progress
        self.frontier.len() < initial_frontier_size
    }

    #[inline]
    fn can_process_now(&self, node_idx: usize) -> bool {
        // Quick check: does this node read any pending inverse outputs?
        !self.deps.reads[node_idx]
            .iter()
            .any(|&witness| self.pending_inverse_outputs.contains(&witness))
    }

    fn process_node(&mut self, node_idx: usize) {
        match &self.witness_builders[node_idx] {
            WitnessBuilder::Inverse(out_witness, _) => {
                // Defer inverse for batching
                self.pending_inverses.push(node_idx);
                self.pending_inverse_outputs.insert(*out_witness);
            }
            _ => {
                // Process immediately
                self.current_pre_segment.push(node_idx);
                self.mark_processed(node_idx);
            }
        }
    }

    fn mark_processed(&mut self, node_idx: usize) {
        self.processed[node_idx] = true;

        // Unlock dependent nodes
        let dependents = self.deps.adjacency_list[node_idx].clone();
        for dependent in dependents {
            self.deps.in_degrees[dependent] -= 1;
            if self.deps.in_degrees[dependent] == 0 {
                self.frontier.push_back(dependent);
            }
        }
    }

    fn flush_layer(&mut self) {
        // Save current segments
        self.pre_layers
            .push(mem::take(&mut self.current_pre_segment));
        let inverse_batch = mem::take(&mut self.pending_inverses);

        // Process pending inverses to unlock dependencies
        for &inverse_idx in &inverse_batch {
            if !self.processed[inverse_idx] {
                self.mark_processed(inverse_idx);
            }
        }

        self.inverse_batches.push(inverse_batch);
        self.pending_inverse_outputs.clear();
    }

    fn build_result(self) -> LayeredWitnessBuilders {
        let mut builders = Vec::new();
        let mut pre_starts = Vec::with_capacity(self.pre_layers.len());
        let mut inverse_starts = Vec::with_capacity(self.inverse_batches.len());

        for (pre_layer, inverse_batch) in self.pre_layers.iter().zip(&self.inverse_batches) {
            // Mark pre-segment start
            pre_starts.push(builders.len());

            // Add pre-builders
            for &builder_idx in pre_layer {
                builders.push(self.witness_builders[builder_idx].clone());
            }

            // Mark inverse-segment start
            inverse_starts.push(builders.len());

            // Add inverse builders
            for &inverse_idx in inverse_batch {
                builders.push(self.witness_builders[inverse_idx].clone());
            }
        }

        LayeredWitnessBuilders {
            builders,
            pre_starts,
            inverse_starts,
        }
    }
}
