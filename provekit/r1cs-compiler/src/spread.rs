use {
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    ark_ff::{Field, Zero},
    provekit_common::{
        witness::{compute_spread, ConstantOrR1CSWitness, SumTerm, WitnessBuilder},
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

/// Split a chunk into sub-chunks of ≤ `w` bits.
fn subchunks(bits: u32, w: u32) -> Vec<u32> {
    if bits <= w {
        vec![bits]
    } else {
        let mut v = vec![w; (bits / w) as usize];
        if bits % w > 0 {
            v.push(bits % w);
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
    /// Spread table width in bits (table has 2^table_bits entries)
    pub table_bits:   u32,
    /// (input_value, spread_output) pairs for LogUp queries
    pub lookups:      Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness)>,
    /// Cache: witness_idx → spread_witness_idx
    pub spread_cache: HashMap<usize, usize>,
    /// Sub-chunks with < table_bits that need range checking
    /// via the normal range check system. Maps bit_width → witness
    /// indices.
    pub range_checks: BTreeMap<u32, Vec<usize>>,
}

impl SpreadAccumulator {
    pub fn new(table_bits: u32) -> Self {
        Self {
            table_bits,
            lookups: Vec::new(),
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
    let w = accum.table_bits;

    // Step 1: Build flat sub-chunk list and track chunk boundaries.
    // For chunk_spec [2,11,9,10] with w=8 this produces
    // flat_bits [2, 8,3, 8,1, 8,2] and chunk_sub_counts [1, 2, 2, 2].
    let mut flat_bits: Vec<u32> = Vec::new();
    let mut chunk_sub_counts: Vec<usize> = Vec::with_capacity(num_chunks);
    for &bits in chunk_spec {
        let subs = subchunks(bits, w);
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
    let mut recomp_terms: Vec<(FieldElement, usize)> = Vec::with_capacity(flat_bits.len());
    let mut bit_offset: u32 = 0;
    for (i, &bits) in flat_bits.iter().enumerate() {
        recomp_terms.push((FieldElement::from(1u64 << bit_offset), sub_start + i));
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
        let sub_bits_slice = &flat_bits[flat_idx..flat_idx + n_subs];

        let mut sub_values = Vec::with_capacity(n_subs);
        let mut sub_spreads = Vec::with_capacity(n_subs);
        for j in 0..n_subs {
            let val_idx = sub_start + flat_idx + j;
            let spread_idx = add_spread_witness(compiler, accum, val_idx);
            if sub_bits_slice[j] < w {
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
    /// Even-bit (XOR) chunk values
    pub even_values: Vec<usize>,
    /// Odd-bit (AND/MAJ) chunk values
    pub odd_values:  Vec<usize>,
    /// Bit widths of the extraction chunks (subchunks(32, w))
    pub chunk_bits:  Vec<u32>,
}

/// Decompose a spread sum into even (XOR) and odd (AND/MAJ) chunk
/// components. SpreadBitExtract extracts even/odd chunks from the sum.
///
/// Single merged constraint:
/// Σ(coeff_i × input_spread_i) = 2·Σ(spread(odd_i)·4^offset_i)
///                              + Σ(spread(even_i)·4^offset_i)
pub(crate) fn spread_decompose(
    compiler: &mut NoirToR1CSCompiler,
    accum: &mut SpreadAccumulator,
    sum_terms: Vec<SumTerm>,
) -> SpreadDecompResult {
    let extract_chunks = subchunks(32, accum.table_bits);
    let n_chunks = extract_chunks.len();

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

    // Extract even bits (XOR) into chunks.
    // The sum is computed inline by the solver from sum_terms,
    // avoiding a phantom witness that would inflate the witness vector.
    let even_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::SpreadBitExtract {
        output_start: even_start,
        chunk_bits:   extract_chunks.clone(),
        sum_terms:    sum_terms.clone(),
        extract_even: true,
    });

    // Extract odd bits (AND/MAJ) into chunks
    let odd_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::SpreadBitExtract {
        output_start: odd_start,
        chunk_bits: extract_chunks.clone(),
        sum_terms,
        extract_even: false,
    });

    // Spread each extracted chunk and add lookups
    let mut even_spreads = Vec::with_capacity(n_chunks);
    let mut odd_spreads = Vec::with_capacity(n_chunks);
    for i in 0..n_chunks {
        let even_val = even_start + i;
        let odd_val = odd_start + i;
        even_spreads.push(add_spread_witness(compiler, accum, even_val));
        odd_spreads.push(add_spread_witness(compiler, accum, odd_val));
        // Range-check narrow remainder chunks
        if extract_chunks[i] < accum.table_bits {
            accum
                .range_checks
                .entry(extract_chunks[i])
                .or_default()
                .push(even_val);
            accum
                .range_checks
                .entry(extract_chunks[i])
                .or_default()
                .push(odd_val);
        }
    }

    let even_values: Vec<usize> = (even_start..even_start + n_chunks).collect();
    let odd_values: Vec<usize> = (odd_start..odd_start + n_chunks).collect();

    // Single constraint (input terms = even/odd reconstruction):
    // Σ(coeff_i × input_spread_i) = 2·Σ(spread(odd_i)·4^offset_i)
    //                              + Σ(spread(even_i)·4^offset_i)
    let two = FieldElement::from(2u64);
    let mut cz: Vec<(FieldElement, usize)> = Vec::with_capacity(2 * n_chunks);
    let mut bit_offset = 0u32;
    for (i, &bits) in extract_chunks.iter().enumerate() {
        let base = FieldElement::from(1u64 << (2 * bit_offset));
        cz.push((two * base, odd_spreads[i]));
        cz.push((base, even_spreads[i]));
        bit_offset += bits;
    }
    compiler
        .r1cs
        .add_constraint(&az, &[(FieldElement::ONE, compiler.witness_one())], &cz);

    SpreadDecompResult {
        even_values,
        odd_values,
        chunk_bits: extract_chunks,
    }
}

/// Pack chunk witnesses into a u32 field element with constraint.
/// `chunk_bits` specifies the bit-width of each chunk (must sum to 32).
pub(crate) fn pack_chunks(
    compiler: &mut NoirToR1CSCompiler,
    chunk_bits: &[u32],
    values: &[usize],
) -> usize {
    assert_eq!(chunk_bits.len(), values.len());
    let packed_idx = compiler.num_witnesses();
    let mut terms = Vec::with_capacity(values.len());
    let mut constraint_terms = Vec::with_capacity(values.len());
    let mut multiplier = FieldElement::ONE;
    for (i, &val_idx) in values.iter().enumerate() {
        terms.push(SumTerm(Some(multiplier), val_idx));
        constraint_terms.push((multiplier, val_idx));
        multiplier *= FieldElement::from(1u64 << chunk_bits[i]);
    }
    compiler.add_witness_builder(WitnessBuilder::Sum(packed_idx, terms));
    compiler.r1cs.add_constraint(
        &constraint_terms,
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, packed_idx)],
    );
    packed_idx
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

/// Decompose a compile-time constant u32 into a [SpreadWord] without
/// spread table lookups or range checks.
///
/// Chunk values and their spreads are pre-computed; spread witnesses
/// are pinned via direct equality constraints (`spread_w = spread(c)`).
/// Sub-chunk value witnesses are assigned by the solver but NOT
/// constrained (they are unused in downstream R1CS—only spread
/// witnesses appear in spread_decompose constraints).
///
/// Soundness: each spread witness is individually pinned to a specific
/// constant baked into the constraint system. The verifier checks the
/// pinning constraints; the prover cannot deviate.
pub(crate) fn decompose_constant_to_spread_word(
    compiler: &mut NoirToR1CSCompiler,
    packed_witness: usize,
    constant_value: u32,
    chunk_spec: &[u32],
    table_bits: u32,
) -> SpreadWord {
    let w = table_bits;
    let w_one = compiler.witness_one();
    let num_chunks = chunk_spec.len();

    // Build flat sub-chunk bit widths.
    let mut flat_bits: Vec<u32> = Vec::new();
    let mut chunk_sub_counts: Vec<usize> = Vec::with_capacity(num_chunks);
    for &bits in chunk_spec {
        let subs = subchunks(bits, w);
        chunk_sub_counts.push(subs.len());
        flat_bits.extend(subs);
    }

    // Pre-compute all sub-chunk values at compile time.
    let mut flat_values: Vec<u64> = Vec::with_capacity(flat_bits.len());
    let mut remaining = constant_value as u64;
    for &bits in &flat_bits {
        let mask = (1u64 << bits) - 1;
        flat_values.push(remaining & mask);
        remaining >>= bits;
    }

    // Verify decomposition round-trips at circuit-compilation time.
    // Catches any bug in subchunks() or mask/shift logic immediately.
    let mut recomposed: u64 = 0;
    let mut shift = 0u32;
    for (i, &bits) in flat_bits.iter().enumerate() {
        recomposed += flat_values[i] << shift;
        shift += bits;
    }
    assert_eq!(
        recomposed, constant_value as u64,
        "constant spread decomposition mismatch: {constant_value:#x} decomposed to {recomposed:#x}"
    );

    // Note: packed_witness is already constrained by the caller's add_sum.
    // Each sub-spread witness below is also pinned via add_sum to the
    // known constant spread value, so no additional R1CS constraint or
    // spread table lookup is needed for soundness.

    // Build SpreadChunks with pinned spread witnesses.
    // No ChunkDecompose needed — sub_values are never read by any
    // downstream R1CS constraint (only sub_spreads are used in
    // spread_decompose). We still populate sub_values with the
    // spread witness indices as placeholders to satisfy the struct.
    let mut chunks = Vec::with_capacity(num_chunks);
    let mut flat_idx = 0usize;

    for ci in 0..num_chunks {
        let n_subs = chunk_sub_counts[ci];
        let sub_bits_slice = &flat_bits[flat_idx..flat_idx + n_subs];
        let mut sub_spreads = Vec::with_capacity(n_subs);

        for j in 0..n_subs {
            let spread_val = compute_spread(flat_values[flat_idx + j]);

            // Spread witness pinned to known constant.
            // Replaces the spread table lookup that would normally
            // prove the (input, spread) pair membership.
            let spread_idx =
                compiler.add_sum(vec![SumTerm(Some(FieldElement::from(spread_val)), w_one)]);

            sub_spreads.push(spread_idx);
        }

        chunks.push(SpreadChunk {
            total_bits: chunk_spec[ci],
            // NB: sub_values normally holds chunk-value witness indices, but the constant
            // path doesn't create separate chunk-value witnesses. Set to spread indices
            // instead; this field is currently unused so the mismatch is harmless.
            sub_values: sub_spreads.clone(),
            sub_spreads,
            sub_bits: sub_bits_slice.to_vec(),
        });
        flat_idx += n_subs;
    }

    SpreadWord {
        packed: packed_witness,
        chunks,
    }
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

    let table_size = 1u32 << accum.table_bits;

    // Multiplicities: count how many times each input value is queried
    let mult_first = compiler.num_witnesses();
    let query_inputs: Vec<ConstantOrR1CSWitness> =
        accum.lookups.iter().map(|(input, _)| *input).collect();
    compiler.add_witness_builder(WitnessBuilder::MultiplicitiesForSpread(
        mult_first,
        accum.table_bits,
        query_inputs,
    ));

    // Challenges: sz and rs
    let sz = compiler.add_witness_builder(WitnessBuilder::Challenge(compiler.num_witnesses()));
    let rs = compiler.add_witness_builder(WitnessBuilder::Challenge(compiler.num_witnesses()));

    // Query-side: for each lookup, compute 1/(sz - input - rs*spread)
    let mut logup_summands: Vec<(FieldElement, usize)> = Vec::new();

    for (input, spread_output) in &accum.lookups {
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
        let inverse =
            compiler.add_witness_builder(WitnessBuilder::Inverse(compiler.num_witnesses(), denom));

        // Single merged constraint:
        // (sz - input - rs*spread) × inverse = 1
        compiler
            .r1cs
            .add_constraint(&az, &[(FieldElement::ONE, inverse)], &[(
                FieldElement::ONE,
                compiler.witness_one(),
            )]);

        // Query-side terms enter with negative coefficient
        logup_summands.push((FieldElement::ONE.neg(), inverse));
    }

    // Table-side: for each entry, compute multiplicity / denominator
    for x in 0..table_size {
        let spread_x = compute_spread(x as u64);
        let multiplicity_idx = mult_first + x as usize;

        // Quotient = multiplicity / (sz - x - rs * spread(x))
        let quotient = compiler.add_witness_builder(WitnessBuilder::SpreadTableQuotient {
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

        // Table-side terms enter with positive coefficient
        logup_summands.push((FieldElement::ONE, quotient));
    }

    // Fused multiset equality: (Σ table_quotients − Σ query_inverses) × 1 = 0
    compiler.r1cs.add_constraint(
        &logup_summands,
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::zero(), compiler.witness_one())],
    );

    range_checks
}

/// Estimate total witness cost for spread-based SHA256 at width `w`.
///
/// Accounts for: table cost (2×2^w + 2), inline witnesses per
/// compression, and 3 LogUp witnesses per lookup query.
///
/// `n_const_hash` compressions have constant initial hash values
/// (SHA256 IV), which use pinned spread witnesses instead of table
/// lookups — saving both inline witnesses and lookup overhead.
pub(crate) fn calculate_spread_witness_cost(w: u32, n_sha: usize, n_const_hash: usize) -> usize {
    let sc = |bits: u32| bits.div_ceil(w) as usize;
    let m_spec = |spec: &[u32]| -> usize { spec.iter().map(|&b| sc(b)).sum() };
    let n_sd = sc(32); // chunks per spread_decompose

    // Inline witnesses per operation type
    let decomp = |spec: &[u32]| 2 * m_spec(spec); // decompose_to_spread_word
    let decomp_const = |spec: &[u32]| m_spec(spec); // decompose_constant (spreads only)
    let sd = 4 * n_sd; // spread_decompose
    let pk = 1usize; // pack_chunks
    let add = |spec: &[u32]| 3 + 2 * m_spec(spec); // add_u32_addition_spread

    // Lookup entries per operation type
    let decomp_l = |spec: &[u32]| m_spec(spec);
    let sd_l = 2 * n_sd;
    let add_l = |spec: &[u32]| 1 + m_spec(spec);

    // --- Initial decompositions (non-constant hash path) ---
    // 16 inputs (always non-constant) + 8 hash values (non-constant)
    let init_inline = 16 * decomp(&BYTE_CHUNKS)
        + 2 * decomp(&BYTE_CHUNKS)
        + 3 * decomp(&SIGMA0_CHUNKS)
        + 3 * decomp(&SIGMA1_CHUNKS);
    let init_lookups = 16 * decomp_l(&BYTE_CHUNKS)
        + 2 * decomp_l(&BYTE_CHUNKS)
        + 3 * decomp_l(&SIGMA0_CHUNKS)
        + 3 * decomp_l(&SIGMA1_CHUNKS);

    // --- Initial decompositions (constant hash path) ---
    // 16 inputs (normal) + 8 hash values (constant: spreads only, no lookups)
    let init_const_inline = 16 * decomp(&BYTE_CHUNKS)
        + 2 * decomp_const(&BYTE_CHUNKS)
        + 3 * decomp_const(&SIGMA0_CHUNKS)
        + 3 * decomp_const(&SIGMA1_CHUNKS);
    let init_const_lookups = 16 * decomp_l(&BYTE_CHUNKS);

    // --- Shared per-compression cost (independent of hash constness) ---

    // Message schedule (48 rounds): σ₀ + σ₁ + addition(BYTE)
    let msg_inline = (decomp(&SMALL_SIGMA0_CHUNKS) + sd + pk)
        + (decomp(&SMALL_SIGMA1_CHUNKS) + sd + pk)
        + add(&BYTE_CHUNKS);
    let msg_lookups = (decomp_l(&SMALL_SIGMA0_CHUNKS) + sd_l)
        + (decomp_l(&SMALL_SIGMA1_CHUNKS) + sd_l)
        + add_l(&BYTE_CHUNKS);

    // Compression (64 rounds): Σ₁ + Ch + Σ₀ + Maj + 2 additions
    let comp_inline = (sd + pk) // Σ₁
        + (2 * sd + 2 * pk + 1) // Ch (2 spread_decompose + algebraic)
        + (sd + pk)             // Σ₀
        + (sd + pk)             // Maj
        + add(&SIGMA1_CHUNKS)   // new_e
        + add(&SIGMA0_CHUNKS); // new_a
    let comp_lookups =
        sd_l + 2 * sd_l + sd_l + sd_l + add_l(&SIGMA1_CHUNKS) + add_l(&SIGMA0_CHUNKS);

    // Final hash (8 additions)
    let final_inline = 8 * add(&BYTE_CHUNKS);
    let final_lookups = 8 * add_l(&BYTE_CHUNKS);

    let shared_inline = 48 * msg_inline + 64 * comp_inline + final_inline;
    let shared_lookups = 48 * msg_lookups + 64 * comp_lookups + final_lookups;

    // Non-constant and constant-hash compressions
    let n_normal = n_sha - n_const_hash;
    let normal_cost =
        n_normal * ((init_inline + shared_inline) + 3 * (init_lookups + shared_lookups));
    let const_cost = n_const_hash
        * ((init_const_inline + shared_inline) + 3 * (init_const_lookups + shared_lookups));

    // Table: 2×2^w (multiplicities + quotients) + 2 challenges
    let table = 2 * (1usize << w) + 2;

    table + normal_cost + const_cost
}

/// Find the spread table width in [3, 20] minimizing total witness
/// count for `n_sha` SHA256 compressions, of which `n_const_hash`
/// have constant initial hash values.
pub(crate) fn get_optimal_spread_width(n_sha: usize, n_const_hash: usize) -> u32 {
    (3u32..=20)
        .min_by_key(|&w| calculate_spread_witness_cost(w, n_sha, n_const_hash))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use {
        super::*, crate::noir_to_r1cs::NoirToR1CSCompiler, provekit_common::witness::compute_spread,
    };

    #[test]
    fn test_optimal_spread_width() {
        // n_const_hash=0 for backward-compatible worst-case estimate
        assert_eq!(get_optimal_spread_width(1, 0), 11);
        assert_eq!(get_optimal_spread_width(35, 0), 16);
    }

    #[test]
    fn constant_decomp_pins_correct_spread_values() {
        // Core soundness property: each sub-spread witness is pinned
        // to compute_spread(sub_chunk_value) via add_sum.
        let value: u32 = 0xcafe_babe;
        let mut compiler = NoirToR1CSCompiler::new();
        let w_one = compiler.witness_one();
        let packed = compiler.add_sum(vec![SumTerm(Some(FieldElement::from(value as u64)), w_one)]);

        let sw = decompose_constant_to_spread_word(&mut compiler, packed, value, &BYTE_CHUNKS, 8);

        let bytes = value.to_le_bytes();
        for (i, chunk) in sw.chunks.iter().enumerate() {
            let spread_idx = chunk.sub_spreads[0];
            match &compiler.witness_builders[spread_idx] {
                WitnessBuilder::Sum(idx, terms) => {
                    assert_eq!(*idx, spread_idx);
                    assert_eq!(terms.len(), 1);
                    let expected = compute_spread(bytes[i] as u64);
                    assert_eq!(
                        terms[0].0.unwrap(),
                        FieldElement::from(expected),
                        "chunk {i}: spread mismatch for byte {:#04x}",
                        bytes[i],
                    );
                }
                other => panic!("chunk {i}: expected Sum, got {other:?}"),
            }
        }
    }

    #[test]
    fn constant_decomp_multi_sub_chunk() {
        // SIGMA0_CHUNKS = [2, 11, 9, 10] at w=8 exercises multi-sub-chunk
        // decomposition: the 11-bit chunk splits into [8, 3] sub-chunks,
        // 9-bit into [8, 1], 10-bit into [8, 2].
        let value: u32 = 0xa5a5_a5a5;
        let mut compiler = NoirToR1CSCompiler::new();
        let w_one = compiler.witness_one();
        let packed = compiler.add_sum(vec![SumTerm(Some(FieldElement::from(value as u64)), w_one)]);

        let sw = decompose_constant_to_spread_word(
            &mut compiler,
            packed,
            value,
            &SIGMA0_CHUNKS, // [2, 11, 9, 10]
            8,
        );

        // Verify chunk structure
        assert_eq!(sw.chunks[0].sub_bits, vec![2]);
        assert_eq!(sw.chunks[1].sub_bits, vec![8, 3]);
        assert_eq!(sw.chunks[2].sub_bits, vec![8, 1]);
        assert_eq!(sw.chunks[3].sub_bits, vec![8, 2]);

        // Extract expected sub-chunk values by shifting through the constant
        let mut remaining = value as u64;
        for chunk in &sw.chunks {
            for (j, &bits) in chunk.sub_bits.iter().enumerate() {
                let mask = (1u64 << bits) - 1;
                let sub_val = remaining & mask;
                remaining >>= bits;

                let spread_idx = chunk.sub_spreads[j];
                match &compiler.witness_builders[spread_idx] {
                    WitnessBuilder::Sum(_, terms) => {
                        let expected = compute_spread(sub_val);
                        assert_eq!(
                            terms[0].0.unwrap(),
                            FieldElement::from(expected),
                            "sub-chunk value {sub_val:#x} ({bits} bits): spread mismatch",
                        );
                    }
                    other => panic!("expected Sum, got {other:?}"),
                }
            }
        }
        assert_eq!(remaining, 0, "all 32 bits should be consumed");
    }
}
