use {
    crate::witness::{scheduling::DependencyInfo, WitnessBuilder},
    std::collections::{HashSet, VecDeque},
};

/// Analyzes witness builder dependencies and splits them into w1/w2 groups.
///
/// Uses backward reachability from challenge consumers (lookup builders) to
/// identify which builders must be committed before challenge extraction (w1),
/// minimizing overhead.
pub struct WitnessSplitter<'a> {
    witness_builders: &'a [WitnessBuilder],
    deps:             DependencyInfo,
}

impl<'a> WitnessSplitter<'a> {
    pub fn new(witness_builders: &'a [WitnessBuilder]) -> Self {
        let deps = DependencyInfo::new(witness_builders);
        Self {
            witness_builders,
            deps,
        }
    }

    /// Identifies which builders should be in w1 (pre-challenge) vs w2
    /// (post-challenge).
    ///
    /// Returns (w1_builder_indices, w2_builder_indices)
    pub fn split_builders(&self) -> (Vec<usize>, Vec<usize>) {
        let builder_count = self.witness_builders.len();

        // Step 1: Find all Challenge builders
        let challenge_builders: HashSet<usize> = self
            .witness_builders
            .iter()
            .enumerate()
            .filter_map(|(idx, builder)| {
                matches!(builder, WitnessBuilder::Challenge(_)).then_some(idx)
            })
            .collect();

        if challenge_builders.is_empty() {
            return ((0..builder_count).collect(), Vec::new());
        }

        // Step 2: Reuse pre-computed witness-to-producer mapping
        let witness_producer = &self.deps.witness_producer;

        // Step 3: Find lookup builders
        let mut lookup_builders = HashSet::new();
        for &challenge_idx in &challenge_builders {
            for &consumer_idx in &self.deps.adjacency_list[challenge_idx] {
                lookup_builders.insert(consumer_idx);
            }
        }

        // Step 4: Backward DFS from lookup builders
        let mut w1_set = HashSet::new();
        let mut visited = vec![false; builder_count];
        let mut stack = VecDeque::new();

        for &lookup_idx in &lookup_builders {
            stack.push_back(lookup_idx);
        }

        while let Some(current_idx) = stack.pop_front() {
            if visited[current_idx] {
                continue;
            }
            visited[current_idx] = true;

            if !challenge_builders.contains(&current_idx) && !lookup_builders.contains(&current_idx)
            {
                w1_set.insert(current_idx);
            }

            for &witness_idx in &self.deps.reads[current_idx] {
                if let Some(&producer_idx) = witness_producer.get(&witness_idx) {
                    if !visited[producer_idx] {
                        stack.push_back(producer_idx);
                    }
                }
            }
        }

        // Step 5: Partition
        let mut w1_indices = Vec::new();
        let mut w2_indices = Vec::new();

        for idx in 0..builder_count {
            if w1_set.contains(&idx) {
                w1_indices.push(idx);
            } else {
                w2_indices.push(idx);
            }
        }

        (w1_indices, w2_indices)
    }
}
