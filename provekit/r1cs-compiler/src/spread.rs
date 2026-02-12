use {
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    ark_ff::{Field, Zero},
    provekit_common::{
        witness::{ConstantOrR1CSWitness, SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::{
        collections::{BTreeMap, HashMap},
        ops::Neg,
    },
};

// SHA256 chunk decompositions (bit widths, LSB first)
pub(crate) const SIGMA0_CHUNKS: [u32; 4] = [2, 11, 9, 10];
pub(crate) const SIGMA1_CHUNKS: [u32; 4] = [6, 5, 14, 7];
pub(crate) const SMALL_SIGMA0_CHUNKS: [u32; 4] = [3, 4, 11, 14];
pub(crate) const SMALL_SIGMA1_CHUNKS: [u32; 4] = [10, 7, 2, 13];
pub(crate) const BYTE_CHUNKS: [u32; 4] = [8, 8, 8, 8];

/// Max sub-chunk bit width for spread table
const SPREAD_TABLE_BITS: u32 = 8;

/// spread(0xFFFFFFFF) = 0x5555555555555555
const SPREAD_ALL_ONES: u64 = 0x5555_5555_5555_5555;

/// Pure function: compute spread(val) — interleave bits with zeros.
pub(crate) fn compute_spread(val: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..32 {
        result |= ((val >> i) & 1) << (2 * i);
    }
    result
}

/// Split a chunk into sub-chunks of ≤ SPREAD_TABLE_BITS.
fn subchunks(bits: u32) -> Vec<u32> {
    if bits <= SPREAD_TABLE_BITS {
        vec![bits]
    } else {
        let mut v = vec![SPREAD_TABLE_BITS; (bits / SPREAD_TABLE_BITS) as usize];
        if bits % SPREAD_TABLE_BITS > 0 {
            v.push(bits % SPREAD_TABLE_BITS);
        }
        v
    }
}

/// One chunk of a SpreadWord, potentially sub-decomposed.
#[derive(Clone, Debug)]
pub(crate) struct SpreadChunk {
    pub total_bits:  u32,
    pub sub_values:  Vec<usize>,
    pub sub_spreads: Vec<usize>,
    pub sub_bits:    Vec<u32>,
}

/// A 32-bit word decomposed into rotation-aligned chunks with spread
/// values. Chunks are stored LSB-first.
#[derive(Clone, Debug)]
pub(crate) struct SpreadWord {
    /// Witness index of the packed 32-bit value
    pub packed: usize,
    /// Chunks, one per element in the chunk specification
    pub chunks: Vec<SpreadChunk>,
}

impl SpreadWord {
    /// Build SumTerms for the spread of a rotation.
    /// `start_chunk`: which chunk index begins the rotated value.
    pub fn spread_terms_for_rotation(&self, start_chunk: usize) -> Vec<SumTerm> {
        let n = self.chunks.len();
        let mut terms = Vec::new();
        let mut bit_offset: u32 = 0;

        for i in 0..n {
            let chunk_idx = (start_chunk + i) % n;
            let chunk = &self.chunks[chunk_idx];
            let mut sub_offset = bit_offset;
            for (j, &sub_bits) in chunk.sub_bits.iter().enumerate() {
                let coeff = FieldElement::from(1u64 << (2 * sub_offset));
                terms.push(SumTerm(Some(coeff), chunk.sub_spreads[j]));
                sub_offset += sub_bits;
            }
            bit_offset += chunk.total_bits;
        }
        terms
    }

    /// Build SumTerms for the spread of a right-shift.
    /// Drops the first `dropped_chunks` chunks (they get shifted out).
    pub fn spread_terms_for_shift(&self, dropped_chunks: usize) -> Vec<SumTerm> {
        let mut terms = Vec::new();
        let mut bit_offset: u32 = 0;

        for chunk in self.chunks.iter().skip(dropped_chunks) {
            let mut sub_offset = bit_offset;
            for (j, &sub_bits) in chunk.sub_bits.iter().enumerate() {
                let coeff = FieldElement::from(1u64 << (2 * sub_offset));
                terms.push(SumTerm(Some(coeff), chunk.sub_spreads[j]));
                sub_offset += sub_bits;
            }
            bit_offset += chunk.total_bits;
        }
        terms
    }

    /// Build SumTerms for the spread of the identity (un-rotated).
    pub fn spread_identity(&self) -> Vec<SumTerm> {
        self.spread_terms_for_rotation(0)
    }
}

/// Accumulates spread table lookups for batched LogUp constraint
/// generation.
pub(crate) struct SpreadAccumulator {
    /// (input_value, spread_output) pairs for LogUp queries
    pub lookups:      Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness)>,
    /// Cache: witness_idx → spread_witness_idx
    pub spread_cache: HashMap<usize, usize>,
    /// Sub-chunks with < SPREAD_TABLE_BITS that need range checking
    /// via the normal range check system. Maps bit_width → witness indices.
    pub range_checks: BTreeMap<u32, Vec<usize>>,
}

impl SpreadAccumulator {
    pub fn new() -> Self {
        Self {
            lookups:      Vec::new(),
            spread_cache: HashMap::new(),
            range_checks: BTreeMap::new(),
        }
    }
}

/// Decompose a packed u32 witness into rotation-aligned chunks, spread
/// each via the spread table. Returns a [SpreadWord].
pub(crate) fn decompose_to_spread_word(
    compiler: &mut NoirToR1CSCompiler,
    accum: &mut SpreadAccumulator,
    packed: usize,
    chunk_spec: &[u32],
) -> SpreadWord {
    let num_chunks = chunk_spec.len();

    // Step 1: Build flat sub-chunk list and track chunk boundaries.
    // For chunk_spec [2,11,9,10] this produces flat_bits [2, 8,3, 8,1, 8,2]
    // and chunk_sub_counts [1, 2, 2, 2] (how many sub-chunks per original
    // chunk).
    let mut flat_bits: Vec<u32> = Vec::new();
    let mut chunk_sub_counts: Vec<usize> = Vec::with_capacity(num_chunks);
    for &bits in chunk_spec {
        let subs = subchunks(bits);
        chunk_sub_counts.push(subs.len());
        flat_bits.extend(subs);
    }

    // Step 2: Single ChunkDecompose producing all sub-chunks directly
    // from the packed value.
    let sub_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::ChunkDecompose {
        output_start: sub_start,
        packed,
        chunk_bits: flat_bits.clone(),
    });

    // Step 3: Single flat recomposition constraint:
    // packed = Σ sub_i * 2^(cumulative_bit_offset_i)
    let mut recomp_terms: Vec<(FieldElement, usize)> =
        Vec::with_capacity(flat_bits.len());
    let mut bit_offset: u32 = 0;
    for (i, &bits) in flat_bits.iter().enumerate() {
        recomp_terms
            .push((FieldElement::from(1u64 << bit_offset), sub_start + i));
        bit_offset += bits;
    }
    compiler.r1cs.add_constraint(
        &recomp_terms,
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, packed)],
    );

    // Step 4: Spread each sub-chunk, range-check narrow ones, and group
    // back into SpreadChunks by original chunk boundaries.
    let mut chunks = Vec::with_capacity(num_chunks);
    let mut flat_idx = 0usize;
    for ci in 0..num_chunks {
        let n_subs = chunk_sub_counts[ci];
        let sub_bits_slice =
            &flat_bits[flat_idx..flat_idx + n_subs];

        let mut sub_values = Vec::with_capacity(n_subs);
        let mut sub_spreads = Vec::with_capacity(n_subs);
        for j in 0..n_subs {
            let val_idx = sub_start + flat_idx + j;
            let spread_idx = add_spread_witness(compiler, accum, val_idx);
            if sub_bits_slice[j] < SPREAD_TABLE_BITS {
                accum
                    .range_checks
                    .entry(sub_bits_slice[j])
                    .or_default()
                    .push(val_idx);
            }
            sub_values.push(val_idx);
            sub_spreads.push(spread_idx);
        }

        chunks.push(SpreadChunk {
            total_bits: chunk_spec[ci],
            sub_values,
            sub_spreads,
            sub_bits: sub_bits_slice.to_vec(),
        });
        flat_idx += n_subs;
    }

    SpreadWord { packed, chunks }
}

/// Create a spread witness for a value witness and add a lookup to the
/// accumulator.
fn add_spread_witness(
    compiler: &mut NoirToR1CSCompiler,
    accum: &mut SpreadAccumulator,
    value_idx: usize,
) -> usize {
    if let Some(&cached) = accum.spread_cache.get(&value_idx) {
        return cached;
    }
    let spread_idx = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::SpreadWitness(spread_idx, value_idx));
    accum.lookups.push((
        ConstantOrR1CSWitness::Witness(value_idx),
        ConstantOrR1CSWitness::Witness(spread_idx),
    ));
    accum.spread_cache.insert(value_idx, spread_idx);
    spread_idx
}

/// Result of a 2-way or 3-way spread decomposition.
pub(crate) struct SpreadDecompResult {
    /// Even-bit (XOR) byte values and spreads
    pub even_values:  Vec<usize>,
    pub even_spreads: Vec<usize>,
    /// Odd-bit (AND/MAJ) byte values and spreads
    pub odd_values:   Vec<usize>,
    pub odd_spreads:  Vec<usize>,
}

/// Decompose a spread sum into even (XOR) and odd (AND/MAJ) byte
/// components. SpreadBitExtract extracts even/odd bytes from the sum.
///
/// Single merged constraint:
/// Σ(coeff_i × input_spread_i) = 2·Σ(spread(odd_i)·4^(8i))
///                              + Σ(spread(even_i)·4^(8i))
pub(crate) fn spread_decompose(
    compiler: &mut NoirToR1CSCompiler,
    accum: &mut SpreadAccumulator,
    sum_terms: Vec<SumTerm>,
) -> SpreadDecompResult {
    // Create sum witness (used by SpreadBitExtract solver, not
    // directly constrained — the merged constraint below ties input
    // spread terms directly to the even/odd reconstruction).
    let sum_idx = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::Sum(sum_idx, sum_terms.clone()));
    // Combine coefficients for duplicate witness indices,
    // since R1CS set() overwrites rather than adds.
    let mut combined: HashMap<usize, FieldElement> = HashMap::new();
    for SumTerm(coeff, idx) in &sum_terms {
        *combined.entry(*idx).or_insert(FieldElement::zero()) += coeff.unwrap_or(FieldElement::ONE);
    }
    let az: Vec<(FieldElement, usize)> = combined
        .into_iter()
        .map(|(idx, coeff)| (coeff, idx))
        .collect();

    let byte_chunks = vec![8u32; 4];

    // Extract even bits (XOR) into 4 bytes
    let even_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::SpreadBitExtract {
        output_start: even_start,
        chunk_bits:   byte_chunks.clone(),
        spread_sum:   sum_idx,
        extract_even: true,
    });

    // Extract odd bits (AND/MAJ) into 4 bytes
    let odd_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::SpreadBitExtract {
        output_start: odd_start,
        chunk_bits:   byte_chunks,
        spread_sum:   sum_idx,
        extract_even: false,
    });

    // Spread each extracted byte and add lookups
    let mut even_spreads = Vec::with_capacity(4);
    let mut odd_spreads = Vec::with_capacity(4);
    for i in 0..4 {
        even_spreads.push(add_spread_witness(compiler, accum, even_start + i));
        odd_spreads.push(add_spread_witness(compiler, accum, odd_start + i));
    }

    let even_values: Vec<usize> = (even_start..even_start + 4).collect();
    let odd_values: Vec<usize> = (odd_start..odd_start + 4).collect();

    // Single constraint (input terms = even/odd reconstruction):
    // Σ(coeff_i × input_spread_i) = 2·Σ(spread(odd_i)·4^(8i))
    //                              + Σ(spread(even_i)·4^(8i))
    let two = FieldElement::from(2u64);
    let mut cz: Vec<(FieldElement, usize)> = Vec::with_capacity(8);
    for i in 0..4 {
        let base = FieldElement::from(1u64 << (16 * i)); // 4^(8i) = 2^(16i)
        cz.push((two * base, odd_spreads[i]));
        cz.push((base, even_spreads[i]));
    }
    compiler
        .r1cs
        .add_constraint(&az, &[(FieldElement::ONE, compiler.witness_one())], &cz);

    SpreadDecompResult {
        even_values,
        even_spreads,
        odd_values,
        odd_spreads,
    }
}

/// Pack 4 byte witnesses into a u32 field element with constraint.
pub(crate) fn pack_bytes(compiler: &mut NoirToR1CSCompiler, bytes: &[usize]) -> usize {
    assert_eq!(bytes.len(), 4);
    let packed_idx = compiler.num_witnesses();
    let mut terms = Vec::with_capacity(4);
    let mut constraint_terms = Vec::with_capacity(4);
    let mut multiplier = FieldElement::ONE;
    for &byte_idx in bytes {
        terms.push(SumTerm(Some(multiplier), byte_idx));
        constraint_terms.push((multiplier, byte_idx));
        multiplier *= FieldElement::from(256u64);
    }
    compiler.add_witness_builder(WitnessBuilder::Sum(packed_idx, terms));
    compiler.r1cs.add_constraint(
        &constraint_terms,
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, packed_idx)],
    );
    packed_idx
}

/// Build spread terms for NOT(x): spread(NOT x) = 0x5555...5555 -
/// spread(x). Returns SumTerms representing spread(NOT x).
pub(crate) fn spread_not_terms(
    compiler: &NoirToR1CSCompiler,
    spread_terms: &[SumTerm],
) -> Vec<SumTerm> {
    let mut result = Vec::with_capacity(spread_terms.len() + 1);
    // Add constant: 0x5555555555555555 * witness_one
    result.push(SumTerm(
        Some(FieldElement::from(SPREAD_ALL_ONES)),
        compiler.witness_one(),
    ));
    // Negate each spread term
    for SumTerm(coeff, idx) in spread_terms {
        let neg_coeff = coeff.unwrap_or(FieldElement::ONE).neg();
        result.push(SumTerm(Some(neg_coeff), *idx));
    }
    result
}

/// Reconstruct spread from byte-level spreads (e.g., after a
/// decomposition). Returns SumTerms.
pub(crate) fn spread_from_byte_spreads(spreads: &[usize]) -> Vec<SumTerm> {
    assert_eq!(spreads.len(), 4);
    spreads
        .iter()
        .enumerate()
        .map(|(i, &s)| SumTerm(Some(FieldElement::from(1u64 << (16 * i))), s))
        .collect()
}

/// U32 addition with spread-based range checking.
/// Computes: result = (Σ inputs + const_sum) mod 2^32
/// Returns a SpreadWord with the specified output chunk decomposition.
///
/// The addition result is range-checked by decomposing into chunks and
/// looking up each sub-chunk in the spread table.
/// The carry is range-checked by a spread table lookup.
pub(crate) fn add_u32_addition_spread(
    compiler: &mut NoirToR1CSCompiler,
    accum: &mut SpreadAccumulator,
    packed_inputs: &[usize],
    constants: &[u32],
    output_chunks: &[u32],
) -> SpreadWord {
    let const_sum: u64 = constants.iter().map(|&c| c as u64).sum();
    let const_field = FieldElement::from(const_sum);

    // Create result and carry witnesses
    let result_witness = compiler.num_witnesses();
    let carry_witness = result_witness + 1;

    let mut wb_inputs: Vec<ConstantOrR1CSWitness> = packed_inputs
        .iter()
        .map(|&w| ConstantOrR1CSWitness::Witness(w))
        .collect();
    for &c in constants {
        wb_inputs.push(ConstantOrR1CSWitness::Constant(FieldElement::from(
            c as u64,
        )));
    }

    compiler.add_witness_builder(WitnessBuilder::U32AdditionMulti(
        result_witness,
        carry_witness,
        wb_inputs,
    ));

    // Constraint: Σ inputs + const_sum = result + carry * 2^32
    let mut sum_lhs: Vec<(FieldElement, usize)> = packed_inputs
        .iter()
        .map(|&w| (FieldElement::ONE, w))
        .collect();
    if const_sum > 0 {
        sum_lhs.push((const_field, compiler.witness_one()));
    }
    let two_pow_32 = FieldElement::from(1u64 << 32);
    compiler
        .r1cs
        .add_constraint(&sum_lhs, &[(FieldElement::ONE, compiler.witness_one())], &[
            (FieldElement::ONE, result_witness),
            (two_pow_32, carry_witness),
        ]);

    // Range check carry via spread table lookup
    let carry_spread = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::SpreadWitness(carry_spread, carry_witness));
    accum.lookups.push((
        ConstantOrR1CSWitness::Witness(carry_witness),
        ConstantOrR1CSWitness::Witness(carry_spread),
    ));

    // Decompose result into output chunks (this provides range check)
    decompose_to_spread_word(compiler, accum, result_witness, output_chunks)
}

/// Build the complete spread table LogUp constraints.
/// Creates challenges, multiplicities, table-side inverses/quotients,
/// query-side inverses, and the grand sum equality constraint.
pub(crate) fn add_spread_table_constraints(
    compiler: &mut NoirToR1CSCompiler,
    accum: SpreadAccumulator,
) -> BTreeMap<u32, Vec<usize>> {
    let range_checks = accum.range_checks;

    if accum.lookups.is_empty() {
        return range_checks;
    }

    let table_size = 1u32 << SPREAD_TABLE_BITS;

    // Multiplicities: count how many times each input value is queried
    let mult_first = compiler.num_witnesses();
    let query_inputs: Vec<ConstantOrR1CSWitness> =
        accum.lookups.iter().map(|(input, _)| *input).collect();
    compiler.add_witness_builder(WitnessBuilder::MultiplicitiesForSpread(
        mult_first,
        SPREAD_TABLE_BITS,
        query_inputs,
    ));

    // Challenges: sz and rs
    let sz = compiler.add_witness_builder(WitnessBuilder::Challenge(compiler.num_witnesses()));
    let rs = compiler.add_witness_builder(WitnessBuilder::Challenge(compiler.num_witnesses()));

    // Query-side: for each lookup, compute 1/(sz - input - rs*spread)
    let query_summands: Vec<SumTerm> = accum
        .lookups
        .iter()
        .map(|(input, spread_output)| {
            // Denominator witness (solver helper, not constrained
            // in R1CS — the merged constraint below ties
            // sz - input - rs*spread directly to the inverse).
            let denom = compiler.add_witness_builder(WitnessBuilder::SpreadLookupDenominator(
                compiler.num_witnesses(),
                sz,
                rs,
                *input,
                *spread_output,
            ));

            // Build A-vector: sz - input - rs*spread
            let (input_coeff, input_idx) = input.to_tuple();
            let mut az: Vec<(FieldElement, usize)> =
                vec![(FieldElement::ONE, sz), (input_coeff.neg(), input_idx)];
            match spread_output {
                ConstantOrR1CSWitness::Constant(val) => {
                    az.push((val.neg(), rs));
                }
                ConstantOrR1CSWitness::Witness(w) => {
                    let prod = compiler.add_product(rs, *w);
                    az.push((FieldElement::ONE.neg(), prod));
                }
            }

            // Inverse of denominator
            let inverse = compiler
                .add_witness_builder(WitnessBuilder::Inverse(compiler.num_witnesses(), denom));

            // Single merged constraint:
            // (sz - input - rs*spread) × inverse = 1
            compiler
                .r1cs
                .add_constraint(&az, &[(FieldElement::ONE, inverse)], &[(
                    FieldElement::ONE,
                    compiler.witness_one(),
                )]);

            SumTerm(None, inverse)
        })
        .collect();

    let sum_for_queries = compiler.add_sum(query_summands);

    // Table-side: for each entry, compute multiplicity / denominator
    let table_summands: Vec<SumTerm> = (0..table_size)
        .map(|x| {
            let spread_x = compute_spread(x as u64);
            let multiplicity_idx = mult_first + x as usize;

            // Quotient = multiplicity / (sz - x - rs * spread(x))
            let quotient =
                compiler.add_witness_builder(WitnessBuilder::SpreadTableQuotient {
                    idx: compiler.num_witnesses(),
                    sz,
                    rs,
                    input_val: FieldElement::from(x),
                    spread_val: FieldElement::from(spread_x),
                    multiplicity: multiplicity_idx,
                });

            // Single constraint: denominator × quotient = multiplicity
            // denominator = sz - x - rs * spread(x)
            compiler.r1cs.add_constraint(
                &[
                    (FieldElement::ONE, sz),
                    (FieldElement::from(x).neg(), compiler.witness_one()),
                    (FieldElement::from(spread_x).neg(), rs),
                ],
                &[(FieldElement::ONE, quotient)],
                &[(FieldElement::ONE, multiplicity_idx)],
            );

            SumTerm(None, quotient)
        })
        .collect();

    let sum_for_table = compiler.add_sum(table_summands);

    // Grand sum equality: Σ query inverses = Σ table quotients
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, sum_for_queries)],
        &[(FieldElement::ONE, sum_for_table)],
    );

    range_checks
}
