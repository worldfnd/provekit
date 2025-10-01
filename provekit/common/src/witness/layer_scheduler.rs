use {
    super::WitnessBuilder,
    crate::witness::{
        ConstantOrR1CSWitness, ConstantTerm, ProductLinearTerm, SumTerm, WitnessCoefficient,
        BINOP_ATOMIC_BITS,
    },
    serde::{Deserialize, Serialize},
    std::{
        collections::{HashMap, HashSet, VecDeque},
        mem,
    },
};

/// Type of operations contained in a layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LayerType {
    /// Regular operations (non-inverse).
    Other,
    /// Field inversion operations that should be batch computed.
    Inverse,
}

/// A single layer in the execution plan.
///
/// Each layer groups witness builders that should be executed together,
/// either as regular operations or as a batch of field inversions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Layer {
    /// The witness builders to execute in this layer.
    pub witness_builders: Vec<WitnessBuilder>,
    /// The type of operations in this layer.
    pub typ:              LayerType,
}

/// Execution plan for witness computation with batched field inversions.
///
/// Organizes witness builders into layers where layers alternate between:
/// 1. Regular operations (LayerType::Other)
/// 2. Batched inverse operations (LayerType::Inverse)
///
/// This enables Montgomery's batch inversion trick: instead of computing n
/// individual field inversions (expensive), we compute them in a batch using
/// only 1 inversion and 3n multiplications.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LayeredWitnessBuilders {
    /// The layers of witness builders in execution order.
    pub layers: Vec<Layer>,
}

impl LayeredWitnessBuilders {
    /// Returns the total number of layers.
    pub fn layers_len(&self) -> usize {
        self.layers.len()
    }
}

/// Pre-computed dependency graph for witness builder scheduling.
///
/// Caches three key pieces of information to avoid repeated traversals:
/// - Which witness indices each builder reads (inputs)
/// - Which builders depend on each builder's outputs (graph edges)
/// - How many dependencies each builder has (in-degree for topological sort)
#[derive(Debug)]
struct DependencyInfo {
    /// For each builder: the witness indices it reads.
    reads:          Vec<Vec<usize>>,
    /// For each builder: the builders that depend on its outputs.
    adjacency_list: Vec<Vec<usize>>,
    /// For each builder: the number of unprocessed dependencies (in-degree).
    in_degrees:     Vec<usize>,
}

impl DependencyInfo {
    /// Constructs the dependency graph by analyzing all witness builders.
    ///
    /// This performs three passes:
    /// 1. Extract which witnesses each builder reads
    /// 2. Map each witness to its producer builder
    /// 3. Build adjacency list and compute in-degrees for topological sorting
    fn new(witness_builders: &[WitnessBuilder]) -> Self {
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
        }
    }

    /// Extracts the witness indices that a builder writes as outputs.
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

/// Schedules witness builders into layers using topological sorting.
///
/// The scheduler performs a modified BFS traversal of the dependency graph,
/// grouping operations into layers. Each layer consists of:
/// 1. Regular operations that can be computed in any order (pre-builders)
/// 2. Inverse operations that should be batched together (inverse-builders)
///
/// The key optimization: when we encounter an inverse operation, we defer it
/// and continue processing other ready operations. This maximizes the batch
/// size for expensive field inversions. We only flush a layer when no more
/// regular operations are ready and inverses are blocking progress.
pub struct LayerScheduler<'a> {
    witness_builders: &'a [WitnessBuilder],
    deps:             DependencyInfo,

    // Topological sort state
    /// Builders that are ready to process (all dependencies satisfied).
    frontier:  VecDeque<usize>,
    /// Tracks which builders have been processed.
    processed: Vec<bool>,

    // Layer accumulation state
    /// Completed layers of pre-builders.
    pre_layers:              Vec<Vec<usize>>,
    /// Completed batches of inverse-builders.
    inverse_batches:         Vec<Vec<usize>>,
    /// Pre-builders for the current layer being constructed.
    current_pre_segment:     Vec<usize>,
    /// Witness indices that are outputs of pending inverses.
    pending_inverse_outputs: HashSet<usize>,
    /// Inverse builders waiting to be flushed as a batch.
    pending_inverses:        Vec<usize>,
}

impl<'a> LayerScheduler<'a> {
    /// Initializes the scheduler with the dependency graph and frontier.
    ///
    /// The frontier starts with all builders that have no dependencies
    /// (in-degree 0).
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

    /// Executes the scheduling algorithm and returns the layered execution
    /// plan.
    ///
    /// Main loop: process ready builders from the frontier, deferring inverses.
    /// When progress stalls, flush pending inverses as a batch to unblock the
    /// next layer. Continue until all builders are scheduled.
    pub fn build_layers(mut self) -> LayeredWitnessBuilders {
        while !self.frontier.is_empty() || !self.pending_inverses.is_empty() {
            if !self.process_current_frontier() {
                // No progress made; flush inverses to unblock
                if !self.pending_inverses.is_empty() {
                    self.flush_layer();
                } else {
                    break;
                }
            }
        }

        // Handle any remaining work
        if !self.current_pre_segment.is_empty() || !self.pending_inverses.is_empty() {
            self.flush_layer();
        }

        self.build_result()
    }

    /// Processes all builders in the current frontier, deferring those blocked
    /// by pending inverse outputs.
    ///
    /// Returns true if progress was made (at least one builder was processed).
    fn process_current_frontier(&mut self) -> bool {
        let initial_frontier_size = self.frontier.len();
        let mut deferred = VecDeque::new();

        // Try to process each ready builder
        while let Some(node_idx) = self.frontier.pop_front() {
            if self.processed[node_idx] {
                continue;
            }

            if self.can_process_now(node_idx) {
                self.process_node(node_idx);
            } else {
                // Must wait for pending inverses
                deferred.push_back(node_idx);
            }
        }

        // Put deferred builders back in the frontier
        self.frontier = deferred;

        // Return true if we made progress
        self.frontier.len() < initial_frontier_size
    }

    /// Checks if a builder can be processed now, or if it must wait for
    /// pending inverse operations to complete.
    #[inline]
    fn can_process_now(&self, node_idx: usize) -> bool {
        // Cannot process if it depends on a witness that will be produced by
        // a pending inverse (those inverses haven't been flushed yet)
        !self.deps.reads[node_idx]
            .iter()
            .any(|&witness| self.pending_inverse_outputs.contains(&witness))
    }

    /// Processes a single builder: inverses are deferred for batching,
    /// others are added to the current layer immediately.
    fn process_node(&mut self, node_idx: usize) {
        match &self.witness_builders[node_idx] {
            WitnessBuilder::Inverse(out_witness, _) => {
                // Defer inverse for batching
                self.pending_inverses.push(node_idx);
                self.pending_inverse_outputs.insert(*out_witness);
            }
            _ => {
                // Add to current layer and mark as processed
                self.current_pre_segment.push(node_idx);
                self.mark_processed(node_idx);
            }
        }
    }

    /// Marks a builder as processed and unlocks any builders that were waiting
    /// for its outputs.
    fn mark_processed(&mut self, node_idx: usize) {
        self.processed[node_idx] = true;

        // Decrement in-degree for all dependents and add to frontier if ready
        let dependents = self.deps.adjacency_list[node_idx].clone();
        for dependent in dependents {
            self.deps.in_degrees[dependent] -= 1;
            if self.deps.in_degrees[dependent] == 0 {
                self.frontier.push_back(dependent);
            }
        }
    }

    /// Completes the current layer by saving pre-builders and inverse batches.
    ///
    /// This marks all pending inverses as processed, which unlocks any builders
    /// that were waiting for their outputs. This enables the next layer to
    /// proceed.
    fn flush_layer(&mut self) {
        // Save the current pre-builders and inverse batch
        self.pre_layers
            .push(mem::take(&mut self.current_pre_segment));
        let inverse_batch = mem::take(&mut self.pending_inverses);

        // Mark all inverses as processed to unlock dependent builders
        for &inverse_idx in &inverse_batch {
            if !self.processed[inverse_idx] {
                self.mark_processed(inverse_idx);
            }
        }

        self.inverse_batches.push(inverse_batch);
        self.pending_inverse_outputs.clear();
    }

    /// Assembles the final layered structure from the accumulated layers.
    ///
    /// Creates alternating layers of regular operations and inverse batches,
    /// skipping any empty layers.
    fn build_result(self) -> LayeredWitnessBuilders {
        let mut layers = Vec::new();

        for (pre_layer, inverse_batch) in self.pre_layers.iter().zip(&self.inverse_batches) {
            // Add pre-builders layer if non-empty
            if !pre_layer.is_empty() {
                let witness_builders = pre_layer
                    .iter()
                    .map(|&builder_idx| self.witness_builders[builder_idx].clone())
                    .collect();
                layers.push(Layer {
                    witness_builders,
                    typ: LayerType::Other,
                });
            }

            // Add inverse batch layer if non-empty
            if !inverse_batch.is_empty() {
                let witness_builders = inverse_batch
                    .iter()
                    .map(|&inverse_idx| self.witness_builders[inverse_idx].clone())
                    .collect();
                layers.push(Layer {
                    witness_builders,
                    typ: LayerType::Inverse,
                });
            }
        }

        LayeredWitnessBuilders { layers }
    }
}
