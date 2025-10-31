use {
    crate::witness::{scheduling::DependencyInfo, WitnessBuilder},
    std::collections::{HashSet, VecDeque},
};

/// Analyzes witness builder dependencies and splits them into w1/w2 groups.
///
/// Uses backward reachability from challenge consumers (lookup builders) to
/// identify which builders must be committed before challenge extraction (w1),
/// minimizing overhead. Balances witness counts between w1 and w2.
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

        // Step 2: Forward DFS from challenges to find mandatory_w2
        // (all builders that transitively depend on challenge outputs)
        // Also collect lookup builders (direct challenge consumers)
        let mut mandatory_w2 = challenge_builders.clone();
        let mut lookup_builders = HashSet::new();
        let mut visited = vec![false; builder_count];
        let mut stack = VecDeque::new();

        for &challenge_idx in &challenge_builders {
            visited[challenge_idx] = true;
            // Collect direct consumers as lookup builders
            for &consumer_idx in &self.deps.adjacency_list[challenge_idx] {
                lookup_builders.insert(consumer_idx);
                if !visited[consumer_idx] {
                    visited[consumer_idx] = true;
                    mandatory_w2.insert(consumer_idx);
                    stack.push_back(consumer_idx);
                }
            }
        }

        // Continue DFS to find all transitive dependents
        while let Some(current_idx) = stack.pop_front() {
            for &consumer_idx in &self.deps.adjacency_list[current_idx] {
                if !visited[consumer_idx] {
                    visited[consumer_idx] = true;
                    mandatory_w2.insert(consumer_idx);
                    stack.push_back(consumer_idx);
                }
            }
        }

        // Step 4: Backward DFS from lookup builders to find mandatory_w1
        // (exclude anything in mandatory_w2 to maintain disjoint sets)
        let witness_producer = &self.deps.witness_producer;
        let mut mandatory_w1 = HashSet::new();
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

            // Only add to w1 if not in mandatory_w2 (maintain disjoint)
            if !mandatory_w2.contains(&current_idx)
                && !challenge_builders.contains(&current_idx)
                && !lookup_builders.contains(&current_idx)
            {
                mandatory_w1.insert(current_idx);
            }

            for &witness_idx in &self.deps.reads[current_idx] {
                if let Some(&producer_idx) = witness_producer.get(&witness_idx) {
                    if !visited[producer_idx] && !mandatory_w2.contains(&producer_idx) {
                        stack.push_back(producer_idx);
                    }
                }
            }
        }

        // Step 5: Identify free builders (not in either mandatory set)
        let mut free_builders = Vec::new();
        for idx in 0..builder_count {
            if !mandatory_w1.contains(&idx) && !mandatory_w2.contains(&idx) {
                free_builders.push(idx);
            }
        }

        // Step 6: Calculate witness counts for balancing
        let mut w1_witness_count: usize = mandatory_w1
            .iter()
            .map(|&idx| DependencyInfo::extract_writes(&self.witness_builders[idx]).len())
            .sum();

        let mut w2_witness_count: usize = mandatory_w2
            .iter()
            .map(|&idx| DependencyInfo::extract_writes(&self.witness_builders[idx]).len())
            .sum();

        // Step 7: Greedy balancing - assign free builders to smaller side
        let mut w1_set = mandatory_w1;
        let mut w2_set = mandatory_w2;

        for &free_idx in &free_builders {
            let witness_count =
                DependencyInfo::extract_writes(&self.witness_builders[free_idx]).len();

            if w1_witness_count <= w2_witness_count {
                w1_set.insert(free_idx);
                w1_witness_count += witness_count;
            } else {
                w2_set.insert(free_idx);
                w2_witness_count += witness_count;
            }
        }

        // Step 8: Convert sets to sorted vectors
        let mut w1_indices: Vec<usize> = w1_set.into_iter().collect();
        let mut w2_indices: Vec<usize> = w2_set.into_iter().collect();

        w1_indices.sort_unstable();
        w2_indices.sort_unstable();

        (w1_indices, w2_indices)
    }
}
