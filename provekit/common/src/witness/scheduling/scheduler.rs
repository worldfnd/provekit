use {
    crate::witness::{
        scheduling::DependencyInfo, Layer, LayerType, LayeredWitnessBuilders, WitnessBuilder,
    },
    std::{
        collections::{HashSet, VecDeque},
        mem::take,
    },
};

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
        self.pre_layers.push(take(&mut self.current_pre_segment));
        let inverse_batch = take(&mut self.pending_inverses);

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
