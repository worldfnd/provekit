use {
    super::WitnessBuilder,
    crate::witness::{
        ConstantOrR1CSWitness, ConstantTerm, ProductLinearTerm, SumTerm, WitnessCoefficient,
        BINOP_ATOMIC_BITS,
    },
    std::{
        collections::{BTreeMap, BTreeSet, VecDeque},
        mem,
    },
};

/// Layered plan for serial batched-inversion solving.
///
/// Semantics:
/// - `pre_builders` contains only non-`Inverse` builders, concatenated
///   segment-by-segment.
/// - For segment i, the PRE slice is `pre_builders[pre_segment_starts[i] ..
///   pre_segment_starts[i+1] or end]`.
/// - Immediately after PRE[i], batch-invert all denominators listed in
///   `inverse_batches[i]`.
/// - Each `inverse_batches[i]` contains only `WitnessBuilder::Inverse(out,
///   denom)` elements.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct LayeredWitnessBuilders {
    pub pre_builders:       Vec<WitnessBuilder>,
    pub pre_segment_starts: Vec<usize>,
    pub inverse_batches:    Vec<Vec<WitnessBuilder>>,
}

impl LayeredWitnessBuilders {
    pub fn layers_len(&self) -> usize {
        self.pre_segment_starts.len()
    }

    pub fn layer_range(&self, seg_idx: usize) -> (usize, usize) {
        let start = self.pre_segment_starts[seg_idx];
        let end = self
            .pre_segment_starts
            .get(seg_idx + 1)
            .copied()
            .unwrap_or(self.pre_builders.len());
        (start, end)
    }
}

/// Internal state manager for the layer scheduling algorithm.
///
/// Encapsulates the complex state tracking needed for frontier-based
/// topological sorting with deferred inverse batching.
pub struct LayerScheduler<'a> {
    witness_builders: &'a [WitnessBuilder],
    adjacency_list:   Vec<Vec<usize>>,
    in_degrees:       Vec<usize>,

    // Processing state
    frontier:        VecDeque<usize>,
    processed:       Vec<bool>,
    processed_count: usize,

    // Layer building state
    pre_layers:          Vec<Vec<usize>>,
    inverse_batches:     Vec<Vec<WitnessBuilder>>,
    current_pre_segment: Vec<usize>,

    // Inverse tracking state
    pending_inverse_nodes:    Vec<usize>,
    pending_inverse_builders: Vec<WitnessBuilder>,
    pending_inverse_outputs:  BTreeSet<usize>,
}

impl<'a> LayerScheduler<'a> {
    pub fn new(witness_builders: &'a [WitnessBuilder]) -> Self {
        let builder_count = witness_builders.len();
        let (adjacency_list, in_degrees) = Self::build_dependency_graph(witness_builders);

        let frontier = (0..builder_count).filter(|&i| in_degrees[i] == 0).collect();

        Self {
            witness_builders,
            adjacency_list,
            in_degrees,
            frontier,
            processed: vec![false; builder_count],
            processed_count: 0,
            pre_layers: Vec::new(),
            inverse_batches: Vec::new(),
            current_pre_segment: Vec::new(),
            pending_inverse_nodes: Vec::new(),
            pending_inverse_builders: Vec::new(),
            pending_inverse_outputs: BTreeSet::new(),
        }
    }

    /// Returns the witness indices written by this builder.
    fn writes_of(wb: &WitnessBuilder) -> Vec<usize> {
        match wb {
            WitnessBuilder::Constant(ConstantTerm(idx, _)) => vec![*idx],
            WitnessBuilder::Acir(idx, _) => vec![*idx],
            WitnessBuilder::Sum(idx, _) => vec![*idx],
            WitnessBuilder::Product(idx, ..) => vec![*idx],
            WitnessBuilder::MultiplicitiesForRange(start, range, _) => {
                (*start..*start + *range).collect()
            }
            WitnessBuilder::Challenge(idx) => vec![*idx],
            WitnessBuilder::IndexedLogUpDenominator(idx, ..) => vec![*idx],
            WitnessBuilder::Inverse(idx, _) => vec![*idx],
            WitnessBuilder::ProductLinearOperation(idx, ..) => vec![*idx],
            WitnessBuilder::LogUpDenominator(idx, ..) => vec![*idx],
            WitnessBuilder::DigitalDecomposition(dd) => {
                (dd.first_witness_idx..dd.first_witness_idx + dd.num_witnesses).collect()
            }
            WitnessBuilder::SpiceMultisetFactor(idx, ..) => vec![*idx],
            WitnessBuilder::SpiceWitnesses(sw) => {
                (sw.first_witness_idx..sw.first_witness_idx + sw.num_witnesses).collect()
            }
            WitnessBuilder::BinOpLookupDenominator(idx, ..) => vec![*idx],
            WitnessBuilder::MultiplicitiesForBinOp(start, ..) => {
                let n = (2usize).pow(2 * (BINOP_ATOMIC_BITS as u32));
                (*start..*start + n).collect()
            }
        }
    }

    /// Returns the witness indices read by this builder.
    fn reads_of(wb: &WitnessBuilder) -> Vec<usize> {
        match wb {
            WitnessBuilder::Constant(_) => vec![],
            WitnessBuilder::Acir(..) => vec![],
            WitnessBuilder::Sum(_, ops) => ops.iter().map(|SumTerm(_, idx)| *idx).collect(),
            WitnessBuilder::Product(_, a, b) => vec![*a, *b],
            WitnessBuilder::MultiplicitiesForRange(_, _, values) => values.clone(),
            WitnessBuilder::Challenge(_) => vec![],
            WitnessBuilder::IndexedLogUpDenominator(
                _,
                sz,
                WitnessCoefficient(_, index),
                rs,
                value,
            ) => {
                vec![*sz, *index, *rs, *value]
            }
            WitnessBuilder::Inverse(_, x) => vec![*x],
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
                        crate::witness::SpiceMemoryOperation::Load(addr, value, _rt) => {
                            v.push(*addr);
                            v.push(*value);
                        }
                        crate::witness::SpiceMemoryOperation::Store(
                            addr,
                            _old_value,
                            new_value,
                            _rt,
                        ) => {
                            v.push(*addr);
                            v.push(*new_value);
                        }
                    }
                }
                v
            }
            WitnessBuilder::BinOpLookupDenominator(_, sz, rs, rs2, lhs, rhs, output) => {
                let mut v = vec![*sz, *rs, *rs2];
                let mut push_w = |c: &ConstantOrR1CSWitness| {
                    if let ConstantOrR1CSWitness::Witness(w) = c {
                        v.push(*w)
                    }
                };
                push_w(lhs);
                push_w(rhs);
                push_w(output);
                v
            }
            WitnessBuilder::MultiplicitiesForBinOp(_, pairs) => {
                let mut v = Vec::new();
                for (lhs, rhs) in pairs {
                    if let ConstantOrR1CSWitness::Witness(w) = lhs {
                        v.push(*w);
                    }
                    if let ConstantOrR1CSWitness::Witness(w) = rhs {
                        v.push(*w);
                    }
                }
                v
            }
        }
    }

    /// Builds a dependency graph from witness builders.
    ///
    /// Returns (adjacency_list, in_degrees) where adjacency_list[i] contains
    /// all builders that depend on builder i, and in_degrees[i] is the number
    /// of dependencies for builder i.
    fn build_dependency_graph(
        witness_builders: &[WitnessBuilder],
    ) -> (Vec<Vec<usize>>, Vec<usize>) {
        let builder_count = witness_builders.len();

        // Map each witness index to the builder that produces it
        let mut witness_producer: BTreeMap<usize, usize> = BTreeMap::new();
        for (builder_idx, builder) in witness_builders.iter().enumerate() {
            for witness_idx in Self::writes_of(builder) {
                witness_producer.insert(witness_idx, builder_idx);
            }
        }

        // Build adjacency list and count incoming edges
        let mut adjacency_list: Vec<Vec<usize>> = vec![Vec::new(); builder_count];
        let mut in_degrees: Vec<usize> = vec![0; builder_count];

        for (consumer_idx, builder) in witness_builders.iter().enumerate() {
            for required_witness in Self::reads_of(builder) {
                if let Some(&producer_idx) = witness_producer.get(&required_witness) {
                    if producer_idx != consumer_idx {
                        adjacency_list[producer_idx].push(consumer_idx);
                        in_degrees[consumer_idx] += 1;
                    }
                }
                // Note: witnesses without producers (ACIR inputs, constants)
                // are implicitly available so we don't add
                // dependencies for them
            }
        }

        (adjacency_list, in_degrees)
    }

    pub fn build_layers(mut self) -> LayeredWitnessBuilders {
        while self.processed_count < self.witness_builders.len() {
            if !self.try_process_frontier() {
                if self.has_pending_inverses() {
                    self.flush_current_layer();
                } else if !self.frontier.is_empty() {
                    // This should not happen in a valid DAG
                    self.handle_deadlock();
                } else {
                    break; // All done
                }
            }
        }

        // Handle any remaining work
        if !self.current_pre_segment.is_empty() || self.has_pending_inverses() {
            self.flush_current_layer();
        }

        self.build_final_plan()
    }

    /// Attempts to process the current frontier, returning true if progress was
    /// made.
    fn try_process_frontier(&mut self) -> bool {
        let mut any_progress = false;
        let mut deferred_builders = VecDeque::new();
        let frontier_size = self.frontier.len();

        // Process each builder in the current frontier
        for _ in 0..frontier_size {
            let builder_idx = self.frontier.pop_front().unwrap();
            if self.processed[builder_idx] {
                continue;
            }

            if self.can_process_builder(builder_idx) {
                self.process_builder(builder_idx);
                any_progress = true;
            } else {
                deferred_builders.push_back(builder_idx);
            }
        }

        // Restore deferred builders to frontier
        self.frontier.extend(deferred_builders);
        any_progress
    }

    /// Checks if a builder can be processed in the current PRE segment.
    fn can_process_builder(&self, builder_idx: usize) -> bool {
        // Check if this builder reads any pending inverse outputs
        let reads_pending_inverse = Self::reads_of(&self.witness_builders[builder_idx])
            .iter()
            .any(|witness| self.pending_inverse_outputs.contains(witness));

        !reads_pending_inverse
    }

    /// Processes a single builder, either adding to PRE segment or collecting
    /// for inversion.
    fn process_builder(&mut self, builder_idx: usize) {
        match &self.witness_builders[builder_idx] {
            WitnessBuilder::Inverse(out_witness, denom_witness) => {
                // Collect inverse for batching
                self.pending_inverse_nodes.push(builder_idx);
                self.pending_inverse_builders
                    .push(WitnessBuilder::Inverse(*out_witness, *denom_witness));
                self.pending_inverse_outputs.insert(*out_witness);
            }
            _ => {
                // Add to current PRE segment
                self.current_pre_segment.push(builder_idx);
                self.mark_processed(builder_idx);
            }
        }
    }

    /// Marks a builder as processed and updates the dependency graph.
    fn mark_processed(&mut self, builder_idx: usize) {
        self.processed[builder_idx] = true;
        self.processed_count += 1;

        // Update dependencies and frontier
        for &dependent_idx in &self.adjacency_list[builder_idx] {
            self.in_degrees[dependent_idx] -= 1;
            if self.in_degrees[dependent_idx] == 0 {
                self.frontier.push_back(dependent_idx);
            }
        }
    }

    /// Flushes the current PRE segment and inverse batch, then processes
    /// pending inverses.
    fn flush_current_layer(&mut self) {
        // Emit current PRE segment and inverse batch
        self.pre_layers
            .push(mem::take(&mut self.current_pre_segment));
        self.inverse_batches
            .push(mem::take(&mut self.pending_inverse_builders));
        self.pending_inverse_outputs.clear();

        // Process all pending inverse nodes to unlock their dependencies
        let pending_nodes: Vec<usize> = self.pending_inverse_nodes.drain(..).collect();
        for inverse_idx in pending_nodes {
            if !self.processed[inverse_idx] {
                self.mark_processed(inverse_idx);
            }
        }
    }

    fn has_pending_inverses(&self) -> bool {
        !self.pending_inverse_builders.is_empty()
    }

    fn handle_deadlock(&self) -> ! {
        panic!(
            "Layer scheduling deadlock: {} builders remain unprocessed with no valid progress path",
            self.witness_builders.len() - self.processed_count
        );
    }

    /// Builds the final LayeredWitnessBuilders from the computed layers.
    fn build_final_plan(self) -> LayeredWitnessBuilders {
        let mut pre_builders = Vec::new();
        let mut pre_segment_starts = Vec::with_capacity(self.pre_layers.len());

        for pre_layer in &self.pre_layers {
            pre_segment_starts.push(pre_builders.len());
            for &builder_idx in pre_layer {
                pre_builders.push(self.witness_builders[builder_idx].clone());
            }
        }

        LayeredWitnessBuilders {
            pre_builders,
            pre_segment_starts,
            inverse_batches: self.inverse_batches,
        }
    }
}
