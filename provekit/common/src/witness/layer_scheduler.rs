use {
    super::WitnessBuilder,
    crate::{
        interner::Interner,
        sparse_matrix::SparseMatrix,
        witness::{
            ConstantOrR1CSWitness, ConstantTerm, ProductLinearTerm, SumTerm, WitnessCoefficient,
            BINOP_ATOMIC_BITS,
        },
        R1CS,
    },
    serde::{Deserialize, Serialize},
    std::{
        collections::{HashMap, HashSet, VecDeque},
        mem,
        num::NonZeroU32,
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

/// Split witness builders for sound challenge generation.
///
/// Contains w1 (pre-challenge commitment) and w2 (post-challenge) witness
/// builders, each with their own layered execution plans.
/// Reference: https://hackmd.io/@shreyas-londhe/HkgVaTXCxx
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SplitWitnessBuilders {
    /// Witness builders that must be computed before challenge extraction.
    /// These are committed to w1 before challenges are generated.
    pub w1_layers: LayeredWitnessBuilders,
    /// Witness builders computed after challenge extraction.
    /// These include challenges themselves and anything depending on them.
    pub w2_layers: LayeredWitnessBuilders,
    /// Number of witnesses in w1 (used for indexing split).
    pub w1_size:   usize,
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

        // If no challenges, everything goes in w1
        if challenge_builders.is_empty() {
            return ((0..builder_count).collect(), Vec::new());
        }

        // Step 2: Build witness-to-producer mapping
        let mut witness_producer: HashMap<usize, usize> = HashMap::new();
        for (builder_idx, builder) in self.witness_builders.iter().enumerate() {
            for witness_idx in DependencyInfo::extract_writes(builder) {
                witness_producer.insert(witness_idx, builder_idx);
            }
        }

        // Step 3: Find all builders that READ challenge witnesses (lookup builders)
        let mut lookup_builders = HashSet::new();
        for &challenge_builder_idx in &challenge_builders {
            let challenge_witnesses =
                DependencyInfo::extract_writes(&self.witness_builders[challenge_builder_idx]);

            for challenge_witness in challenge_witnesses {
                for (consumer_idx, reads) in self.deps.reads.iter().enumerate() {
                    if reads.contains(&challenge_witness) {
                        lookup_builders.insert(consumer_idx);
                    }
                }
            }
        }

        // Step 4: Backward DFS from lookup builders to find transitive dependencies
        let mut w1_set = HashSet::new();
        let mut visited = vec![false; builder_count];
        let mut stack = VecDeque::new();

        // Initialize with lookup builders
        for &lookup_idx in &lookup_builders {
            stack.push_back(lookup_idx);
        }

        // Backward DFS
        while let Some(current_idx) = stack.pop_front() {
            if visited[current_idx] {
                continue;
            }
            visited[current_idx] = true;

            // Don't include challenges or lookups in w1 - they go to w2
            if !challenge_builders.contains(&current_idx) && !lookup_builders.contains(&current_idx)
            {
                w1_set.insert(current_idx);
            }

            // Traverse backward through dependencies
            for &witness_idx in &self.deps.reads[current_idx] {
                if let Some(&producer_idx) = witness_producer.get(&witness_idx) {
                    if !visited[producer_idx] {
                        stack.push_back(producer_idx);
                    }
                }
            }
        }

        // Step 5: Partition into w1 and w2, preserving original order
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

/// Remaps witness indices to create disjoint w1 and w2 ranges.
///
/// After remapping:
/// - w1 witnesses occupy indices [0, k)
/// - w2 witnesses occupy indices [k, n)
///
/// This ensures w1 can be committed independently before challenge extraction.
pub struct WitnessIndexRemapper {
    /// Maps old witness index to new witness index
    pub old_to_new: HashMap<usize, usize>,
    /// Number of witnesses in w1 (boundary between w1 and w2)
    pub w1_size:    usize,
}

impl WitnessIndexRemapper {
    /// Creates a remapping from w1 and w2 builder lists.
    ///
    /// Assigns w1 builder outputs to [0, k) and w2 builder outputs to [k, n).
    pub fn new(w1_builders: &[WitnessBuilder], w2_builders: &[WitnessBuilder]) -> Self {
        let mut old_to_new = HashMap::new();
        let mut next_w1_idx = 0;
        let mut next_w2_idx = 0;

        // Map w1 builder outputs to [0, k)
        for builder in w1_builders {
            let writes = DependencyInfo::extract_writes(builder);
            for old_idx in writes {
                old_to_new.insert(old_idx, next_w1_idx);
                next_w1_idx += 1;
            }
        }

        let w1_size = next_w1_idx;

        // Map w2 builder outputs to [k, n)
        for builder in w2_builders {
            let writes = DependencyInfo::extract_writes(builder);
            for old_idx in writes {
                old_to_new.insert(old_idx, w1_size + next_w2_idx);
                next_w2_idx += 1;
            }
        }

        Self {
            old_to_new,
            w1_size,
        }
    }

    /// Remaps a single witness index.
    pub fn remap(&self, old_idx: usize) -> usize {
        *self
            .old_to_new
            .get(&old_idx)
            .unwrap_or_else(|| panic!("Witness index {} not in remapping", old_idx))
    }

    /// Helper to remap ConstantOrR1CSWitness variants
    pub fn remap_const_or_witness(&self, val: &ConstantOrR1CSWitness) -> ConstantOrR1CSWitness {
        match val {
            ConstantOrR1CSWitness::Constant(c) => ConstantOrR1CSWitness::Constant(*c),
            ConstantOrR1CSWitness::Witness(w) => ConstantOrR1CSWitness::Witness(self.remap(*w)),
        }
    }

    /// Remaps a witness builder, updating all witness indices it references.
    pub fn remap_builder(&self, builder: &WitnessBuilder) -> WitnessBuilder {
        match builder {
            WitnessBuilder::Constant(ConstantTerm(idx, val)) => {
                WitnessBuilder::Constant(ConstantTerm(self.remap(*idx), *val))
            }
            WitnessBuilder::Acir(idx, acir_idx) => {
                WitnessBuilder::Acir(self.remap(*idx), *acir_idx)
            }
            WitnessBuilder::Sum(idx, terms) => {
                let new_terms = terms
                    .iter()
                    .map(|SumTerm(coeff, operand_idx)| SumTerm(*coeff, self.remap(*operand_idx)))
                    .collect();
                WitnessBuilder::Sum(self.remap(*idx), new_terms)
            }
            WitnessBuilder::Product(idx, a, b) => {
                WitnessBuilder::Product(self.remap(*idx), self.remap(*a), self.remap(*b))
            }
            WitnessBuilder::MultiplicitiesForRange(start, range, values) => {
                let new_values = values.iter().map(|&v| self.remap(v)).collect();
                WitnessBuilder::MultiplicitiesForRange(self.remap(*start), *range, new_values)
            }
            WitnessBuilder::Challenge(idx) => WitnessBuilder::Challenge(self.remap(*idx)),
            WitnessBuilder::IndexedLogUpDenominator(
                idx,
                sz,
                WitnessCoefficient(coeff, index),
                rs,
                value,
            ) => WitnessBuilder::IndexedLogUpDenominator(
                self.remap(*idx),
                self.remap(*sz),
                WitnessCoefficient(*coeff, self.remap(*index)),
                self.remap(*rs),
                self.remap(*value),
            ),
            WitnessBuilder::Inverse(idx, operand) => {
                WitnessBuilder::Inverse(self.remap(*idx), self.remap(*operand))
            }
            WitnessBuilder::ProductLinearOperation(
                idx,
                ProductLinearTerm(x, a, b),
                ProductLinearTerm(y, c, d),
            ) => WitnessBuilder::ProductLinearOperation(
                self.remap(*idx),
                ProductLinearTerm(self.remap(*x), *a, *b),
                ProductLinearTerm(self.remap(*y), *c, *d),
            ),
            WitnessBuilder::LogUpDenominator(idx, sz, WitnessCoefficient(coeff, value)) => {
                WitnessBuilder::LogUpDenominator(
                    self.remap(*idx),
                    self.remap(*sz),
                    WitnessCoefficient(*coeff, self.remap(*value)),
                )
            }
            WitnessBuilder::DigitalDecomposition(dd) => {
                let new_witnesses_to_decompose = dd
                    .witnesses_to_decompose
                    .iter()
                    .map(|&w| self.remap(w))
                    .collect();
                WitnessBuilder::DigitalDecomposition(
                    crate::witness::DigitalDecompositionWitnesses {
                        log_bases:                  dd.log_bases.clone(),
                        num_witnesses_to_decompose: dd.num_witnesses_to_decompose,
                        witnesses_to_decompose:     new_witnesses_to_decompose,
                        first_witness_idx:          self.remap(dd.first_witness_idx),
                        num_witnesses:              dd.num_witnesses,
                    },
                )
            }
            WitnessBuilder::SpiceMultisetFactor(
                idx,
                sz,
                rs,
                WitnessCoefficient(addr_c, addr_w),
                value,
                WitnessCoefficient(timer_c, timer_w),
            ) => WitnessBuilder::SpiceMultisetFactor(
                self.remap(*idx),
                self.remap(*sz),
                self.remap(*rs),
                WitnessCoefficient(*addr_c, self.remap(*addr_w)),
                self.remap(*value),
                WitnessCoefficient(*timer_c, self.remap(*timer_w)),
            ),
            WitnessBuilder::SpiceWitnesses(sw) => {
                let new_memory_operations = sw
                    .memory_operations
                    .iter()
                    .map(|op| match op {
                        crate::witness::SpiceMemoryOperation::Load(addr, value, rt) => {
                            crate::witness::SpiceMemoryOperation::Load(
                                self.remap(*addr),
                                self.remap(*value),
                                self.remap(*rt),
                            )
                        }
                        crate::witness::SpiceMemoryOperation::Store(addr, old_val, new_val, rt) => {
                            crate::witness::SpiceMemoryOperation::Store(
                                self.remap(*addr),
                                self.remap(*old_val),
                                self.remap(*new_val),
                                self.remap(*rt),
                            )
                        }
                    })
                    .collect();
                WitnessBuilder::SpiceWitnesses(crate::witness::SpiceWitnesses {
                    memory_length:        sw.memory_length,
                    initial_values_start: self.remap(sw.initial_values_start),
                    memory_operations:    new_memory_operations,
                    rv_final_start:       self.remap(sw.rv_final_start),
                    rt_final_start:       self.remap(sw.rt_final_start),
                    first_witness_idx:    self.remap(sw.first_witness_idx),
                    num_witnesses:        sw.num_witnesses,
                })
            }
            WitnessBuilder::BinOpLookupDenominator(idx, sz, rs, rs2, lhs, rhs, output) => {
                WitnessBuilder::BinOpLookupDenominator(
                    self.remap(*idx),
                    self.remap(*sz),
                    self.remap(*rs),
                    self.remap(*rs2),
                    self.remap_const_or_witness(lhs),
                    self.remap_const_or_witness(rhs),
                    self.remap_const_or_witness(output),
                )
            }
            WitnessBuilder::MultiplicitiesForBinOp(start, pairs) => {
                let new_pairs = pairs
                    .iter()
                    .map(|(lhs, rhs)| {
                        (
                            self.remap_const_or_witness(lhs),
                            self.remap_const_or_witness(rhs),
                        )
                    })
                    .collect();
                WitnessBuilder::MultiplicitiesForBinOp(self.remap(*start), new_pairs)
            }
            WitnessBuilder::U32Addition(result_idx, carry_idx, a, b) => {
                WitnessBuilder::U32Addition(
                    self.remap(*result_idx),
                    self.remap(*carry_idx),
                    self.remap_const_or_witness(a),
                    self.remap_const_or_witness(b),
                )
            }
            WitnessBuilder::And(idx, lh, rh) => WitnessBuilder::And(
                self.remap(*idx),
                self.remap_const_or_witness(lh),
                self.remap_const_or_witness(rh),
            ),
            WitnessBuilder::Xor(idx, lh, rh) => WitnessBuilder::Xor(
                self.remap(*idx),
                self.remap_const_or_witness(lh),
                self.remap_const_or_witness(rh),
            ),
        }
    }

    /// Remaps witness indices in R1CS constraint matrices.
    ///
    /// Creates a new R1CS with remapped column indices (witness indices).
    /// Row indices (constraints) remain unchanged.
    pub fn remap_r1cs(&self, r1cs: R1CS) -> R1CS {
        let mut new_r1cs = R1CS::new();
        new_r1cs.num_public_inputs = r1cs.num_public_inputs;
        new_r1cs.interner = r1cs.interner.clone();

        // Remap each matrix (A, B, C)
        let new_a = self.remap_sparse_matrix(r1cs.a, &r1cs.interner, &mut new_r1cs.interner);
        let new_b = self.remap_sparse_matrix(r1cs.b, &r1cs.interner, &mut new_r1cs.interner);
        let new_c = self.remap_sparse_matrix(r1cs.c, &r1cs.interner, &mut new_r1cs.interner);

        // Build new R1CS with remapped matrices
        new_r1cs.a = new_a;
        new_r1cs.b = new_b;
        new_r1cs.c = new_c;

        new_r1cs
    }

    /// Helper to remap a single sparse matrix
    pub fn remap_sparse_matrix(
        &self,
        matrix: SparseMatrix,
        read_interner: &Interner,
        write_interner: &mut Interner,
    ) -> SparseMatrix {
        // Create new matrix with same dimensions
        let mut new_matrix = SparseMatrix::new(matrix.num_rows, matrix.num_cols);

        // Iterate through all entries and remap column indices
        let hydrated = matrix.hydrate(read_interner);
        for ((row, old_col), value) in hydrated.iter() {
            let new_col = self.remap(old_col);
            new_matrix.set(row, new_col, write_interner.intern(value));
        }

        new_matrix
    }

    /// Remaps ACIR witness map.
    ///
    /// The map goes from ACIR witness index -> R1CS witness index.
    /// We need to update the R1CS indices to their new remapped values.
    pub fn remap_acir_witness_map(&self, map: Vec<Option<NonZeroU32>>) -> Vec<Option<NonZeroU32>> {
        map.into_iter()
            .map(|opt_idx| {
                opt_idx.map(|idx| {
                    let old_r1cs_idx = idx.get() as usize;
                    let new_r1cs_idx = self.remap(old_r1cs_idx);
                    NonZeroU32::new(new_r1cs_idx as u32).expect("Remapped index should be non-zero")
                })
            })
            .collect()
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
