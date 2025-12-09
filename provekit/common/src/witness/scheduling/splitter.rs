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
    pub fn split_builders(&self, acir_public_inputs_indices_set: HashSet<u32>) -> (Vec<usize>, Vec<usize>) {
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
            let w1_indices = self.rearrange_w1(
                (0..builder_count).collect(),
                &acir_public_inputs_indices_set,
            );
            return (w1_indices, Vec::new());
        }

        // Step 2: Forward DFS from challenges to find mandatory_w2
        // (all builders that transitively depend on challenge outputs)
        // Also collect lookup builders (direct challenge consumers)
        let mut mandatory_w2 = challenge_builders.clone();
        let mut lookup_builders = HashSet::new();
        let mut forward_visited = vec![false; builder_count];
        let mut forward_stack = VecDeque::new();

        for &challenge_idx in &challenge_builders {
            forward_visited[challenge_idx] = true;
            // Collect direct consumers as lookup builders
            for &consumer_idx in &self.deps.adjacency_list[challenge_idx] {
                lookup_builders.insert(consumer_idx);
                if !forward_visited[consumer_idx] {
                    forward_visited[consumer_idx] = true;
                    mandatory_w2.insert(consumer_idx);
                    forward_stack.push_back(consumer_idx);
                }
            }
        }

        // Continue DFS to find all transitive dependents
        while let Some(current_idx) = forward_stack.pop_front() {
            for &consumer_idx in &self.deps.adjacency_list[current_idx] {
                if !forward_visited[consumer_idx] {
                    forward_visited[consumer_idx] = true;
                    mandatory_w2.insert(consumer_idx);
                    forward_stack.push_back(consumer_idx);
                }
            }
        }

        // Step 4: Backward DFS from lookup builders to find mandatory_w1
        // (exclude anything in mandatory_w2 to maintain disjoint sets)
        let witness_producer = &self.deps.witness_producer;
        let mut mandatory_w1 = HashSet::new();
        let mut backward_visited = vec![false; builder_count];
        let mut backward_stack = VecDeque::new();

        for &lookup_idx in &lookup_builders {
            backward_stack.push_back(lookup_idx);
        }

        while let Some(current_idx) = backward_stack.pop_front() {
            if backward_visited[current_idx] {
                continue;
            }
            backward_visited[current_idx] = true;

            // Only add to w1 if not in mandatory_w2 (maintain disjoint)
            if !mandatory_w2.contains(&current_idx)
                && !challenge_builders.contains(&current_idx)
                && !lookup_builders.contains(&current_idx)
            {
                mandatory_w1.insert(current_idx);
            }

            for &witness_idx in &self.deps.reads[current_idx] {
                if let Some(&producer_idx) = witness_producer.get(&witness_idx) {
                    if !backward_visited[producer_idx] && !mandatory_w2.contains(&producer_idx) {
                        backward_stack.push_back(producer_idx);
                    }
                }
            }
        }

        // witness_one (builder 0) must always be in w1 to preserve R1CS index 0
        // invariant
        mandatory_w1.insert(0);

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

        // Step 7: Assign free builders greedily while respecting dependencies
        // Rule: if any dependency is in w2, the builder must also be in w2
        // (because w1 is solved before w2)
        // with the exception of public builders writing public witnesses)
        let mut w1_set = mandatory_w1;
        let mut w2_set = mandatory_w2;

        for idx in free_builders {
            // Check if any dependency is in w2
            let must_be_w2 = self.deps.reads[idx].iter().any(|&read_witness| {
                self.deps
                    .witness_producer
                    .get(&read_witness)
                    .map_or(false, |&producer| w2_set.contains(&producer))
            });

            let witness_count = DependencyInfo::extract_writes(&self.witness_builders[idx]).len();

             // If free builder writes a public witness, add it to w1_set.
            if let WitnessBuilder::Acir(_, acir_idx) = &self.witness_builders[idx] {
                if acir_public_inputs_indices_set.contains(&(*acir_idx as u32)) {
                    w1_set.insert(idx);
                    w1_witness_count += witness_count;
                    continue;
                }
            }

            if must_be_w2 {
                w2_set.insert(idx);
                w2_witness_count += witness_count;
            } else if w1_witness_count <= w2_witness_count {
                w1_set.insert(idx);
                w1_witness_count += witness_count;
            } else {
                w2_set.insert(idx);
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

        /// Rearranges w1 indices: constant builder (0) first, then public inputs,
    /// then rest.
    fn rearrange_w1(
        &self,
        w1_indices: Vec<usize>,
        acir_public_inputs_indices_set: &HashSet<u32>,
    ) -> Vec<usize> {
        let mut public_input_builder_indices = Vec::new();
        let mut rest_indices = Vec::new();

        // Sanity Check: Make sure all public inputs and WITNESS_ONE_IDX are in
        // w1_indices.
        for &idx in acir_public_inputs_indices_set.iter() {
            if !w1_indices.contains(&(idx as usize)) {
                panic!("Public input {} is not in w1_indices", idx);
            }
        }

        // Separate into: 0, public inputs, and rest
        for builder_idx in w1_indices {
            if builder_idx == 0 {
                continue; // Will add 0 first
            } else if let WitnessBuilder::Acir(_, acir_idx) = &self.witness_builders[builder_idx] {
                if acir_public_inputs_indices_set.contains(&(*acir_idx as u32)) {
                    public_input_builder_indices.push(builder_idx);
                    continue;
                }
            }
            rest_indices.push(builder_idx);
        }

        public_input_builder_indices.sort_unstable();
        rest_indices.sort_unstable();

        // Reorder: 0 first, then public inputs, then rest
        let mut new_w1_indices = vec![0];
        new_w1_indices.extend(public_input_builder_indices);
        new_w1_indices.extend(rest_indices);
        new_w1_indices
    }
}
