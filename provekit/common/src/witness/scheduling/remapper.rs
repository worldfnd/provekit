use {
    crate::{
        sparse_matrix::SparseMatrix,
        witness::{
            scheduling::DependencyInfo, ConstantOrR1CSWitness, ConstantTerm, ProductLinearTerm,
            SumTerm, WitnessBuilder, WitnessCoefficient,
        },
        R1CS,
    },
    std::{collections::HashMap, num::NonZeroU32},
};

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
        new_r1cs.interner = r1cs.interner;

        // Remap A, B, C in parallel - they're independent
        let (new_a, (new_b, new_c)) = rayon::join(
            || self.remap_sparse_matrix(r1cs.a),
            || {
                rayon::join(
                    || self.remap_sparse_matrix(r1cs.b),
                    || self.remap_sparse_matrix(r1cs.c),
                )
            },
        );

        new_r1cs.a = new_a;
        new_r1cs.b = new_b;
        new_r1cs.c = new_c;

        new_r1cs
    }

    /// Helper to remap a single sparse matrix
    fn remap_sparse_matrix(&self, mut matrix: SparseMatrix) -> SparseMatrix {
        matrix.remap_columns(|old_col| self.remap(old_col));
        matrix
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
