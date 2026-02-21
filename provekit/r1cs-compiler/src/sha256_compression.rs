use {
    crate::{
        noir_to_r1cs::NoirToR1CSCompiler,
        spread::{
            add_spread_table_constraints, add_u32_addition_spread,
            decompose_constant_to_spread_word, decompose_to_spread_word, pack_chunks,
            spread_decompose, SpreadAccumulator, SpreadWord, BYTE_CHUNKS, SIGMA0_CHUNKS,
            SIGMA1_CHUNKS, SMALL_SIGMA0_CHUNKS, SMALL_SIGMA1_CHUNKS,
        },
    },
    ark_ff::{Field, PrimeField},
    provekit_common::{
        witness::{ConstantOrR1CSWitness, SumTerm},
        FieldElement,
    },
    std::{collections::BTreeMap, ops::Neg},
};

/// SHA256 round constants K[0..63]
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// σ₀(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
/// Chunks: [3, 4, 11, 14] at boundaries [0, 3, 7, 18, 32]
/// ROTR7 → start_chunk=2, ROTR18 → start_chunk=3, SHR3 → drop chunk 0
fn add_small_sigma0(
    compiler: &mut NoirToR1CSCompiler,
    accum: &mut SpreadAccumulator,
    x_packed: usize,
) -> usize {
    let word = decompose_to_spread_word(compiler, accum, x_packed, &SMALL_SIGMA0_CHUNKS);

    let mut sum_terms = Vec::new();
    sum_terms.extend(word.spread_terms_for_rotation(2)); // ROTR7
    sum_terms.extend(word.spread_terms_for_rotation(3)); // ROTR18
    sum_terms.extend(word.spread_terms_for_shift(1)); // SHR3

    let result = spread_decompose(compiler, accum, sum_terms);
    pack_chunks(compiler, &result.chunk_bits, &result.even_values)
}

/// σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
/// Chunks: [10, 7, 2, 13] at boundaries [0, 10, 17, 19, 32]
/// ROTR17 → start_chunk=2, ROTR19 → start_chunk=3, SHR10 → drop chunk 0
fn add_small_sigma1(
    compiler: &mut NoirToR1CSCompiler,
    accum: &mut SpreadAccumulator,
    x_packed: usize,
) -> usize {
    let word = decompose_to_spread_word(compiler, accum, x_packed, &SMALL_SIGMA1_CHUNKS);

    let mut sum_terms = Vec::new();
    sum_terms.extend(word.spread_terms_for_rotation(2)); // ROTR17
    sum_terms.extend(word.spread_terms_for_rotation(3)); // ROTR19
    sum_terms.extend(word.spread_terms_for_shift(1)); // SHR10

    let result = spread_decompose(compiler, accum, sum_terms);
    pack_chunks(compiler, &result.chunk_bits, &result.even_values)
}

/// Σ₁(e) = ROTR⁶(e) ⊕ ROTR¹¹(e) ⊕ ROTR²⁵(e)
/// Uses cached e-type SpreadWord [6, 5, 14, 7]
/// ROTR6 → start_chunk=1, ROTR11 → start_chunk=2, ROTR25 → start_chunk=3
fn add_cap_sigma1_spread(
    compiler: &mut NoirToR1CSCompiler,
    accum: &mut SpreadAccumulator,
    e: &SpreadWord,
) -> usize {
    let mut sum_terms = Vec::new();
    sum_terms.extend(e.spread_terms_for_rotation(1)); // ROTR6
    sum_terms.extend(e.spread_terms_for_rotation(2)); // ROTR11
    sum_terms.extend(e.spread_terms_for_rotation(3)); // ROTR25

    let result = spread_decompose(compiler, accum, sum_terms);
    pack_chunks(compiler, &result.chunk_bits, &result.even_values)
}

/// Σ₀(a) = ROTR²(a) ⊕ ROTR¹³(a) ⊕ ROTR²²(a)
/// Uses cached a-type SpreadWord [2, 11, 9, 10]
/// ROTR2 → start_chunk=1, ROTR13 → start_chunk=2, ROTR22 → start_chunk=3
fn add_cap_sigma0_spread(
    compiler: &mut NoirToR1CSCompiler,
    accum: &mut SpreadAccumulator,
    a: &SpreadWord,
) -> usize {
    let mut sum_terms = Vec::new();
    sum_terms.extend(a.spread_terms_for_rotation(1)); // ROTR2
    sum_terms.extend(a.spread_terms_for_rotation(2)); // ROTR13
    sum_terms.extend(a.spread_terms_for_rotation(3)); // ROTR22

    let result = spread_decompose(compiler, accum, sum_terms);
    pack_chunks(compiler, &result.chunk_bits, &result.even_values)
}

/// Ch(e,f,g) = (e & f) ^ (NOT_e & g)
/// Algebraic identity: Ch = (e & f) + g - (e & g)
/// Proof: ~e&g = g - (e&g) bitwise (no borrows since e&g ≤ g), and
/// (e&f) and (~e&g) are disjoint, so their XOR = their sum (no carries).
/// Two 2-way decompositions + one linear constraint:
///   1. spread(e) + spread(f) → extract e&f (odd bits)
///   2. spread(e) + spread(g) → extract e&g (odd bits)
///   3. Ch = (e&f) + g - (e&g) (algebraic, no spread_decompose needed)
fn add_ch_spread(
    compiler: &mut NoirToR1CSCompiler,
    accum: &mut SpreadAccumulator,
    e: &SpreadWord,
    f: &SpreadWord,
    g: &SpreadWord,
) -> usize {
    // Step 1: spread(e) + spread(f) → e&f in odd bits
    let mut ef_sum = Vec::new();
    ef_sum.extend(e.spread_identity());
    ef_sum.extend(f.spread_identity());
    let ef_decomp = spread_decompose(compiler, accum, ef_sum);

    // Step 2: spread(e) + spread(g) → e&g in odd bits
    let mut eg_sum = Vec::new();
    eg_sum.extend(e.spread_identity());
    eg_sum.extend(g.spread_identity());
    let eg_decomp = spread_decompose(compiler, accum, eg_sum);

    // Pack e&f and e&g from odd bits
    let ef_and_packed = pack_chunks(compiler, &ef_decomp.chunk_bits, &ef_decomp.odd_values);
    let eg_and_packed = pack_chunks(compiler, &eg_decomp.chunk_bits, &eg_decomp.odd_values);

    // Step 3: Ch = (e&f) + g - (e&g) via linear constraint
    let ch_packed = compiler.add_sum(vec![
        SumTerm(Some(FieldElement::ONE), ef_and_packed),
        SumTerm(Some(FieldElement::ONE), g.packed),
        SumTerm(Some(FieldElement::ONE.neg()), eg_and_packed),
    ]);

    ch_packed
}

/// Maj(a,b,c): 3-way majority via spread
/// spread(a) + spread(b) + spread(c) = 2*spread(MAJ) + spread(XOR)
/// Extract MAJ from odd bits.
fn add_maj_spread(
    compiler: &mut NoirToR1CSCompiler,
    accum: &mut SpreadAccumulator,
    a: &SpreadWord,
    b: &SpreadWord,
    c: &SpreadWord,
) -> usize {
    let mut sum_terms = Vec::new();
    sum_terms.extend(a.spread_identity());
    sum_terms.extend(b.spread_identity());
    sum_terms.extend(c.spread_identity());

    let result = spread_decompose(compiler, accum, sum_terms);
    pack_chunks(compiler, &result.chunk_bits, &result.odd_values)
}

/// Message schedule expansion with spread.
/// Expands 16 packed u32 words → 64 packed u32 words.
/// σ₀ and σ₁ use chunk-aligned spread decomposition instead of
/// byte-level ROTR/SHR + XOR.
fn add_message_schedule_spread(
    compiler: &mut NoirToR1CSCompiler,
    accum: &mut SpreadAccumulator,
    input_packed: &[usize; 16],
) -> [usize; 64] {
    let mut w_packed = Vec::with_capacity(64);
    for &p in input_packed.iter() {
        w_packed.push(p);
    }

    for _ in 16..64 {
        let len = w_packed.len();
        let s1 = add_small_sigma1(compiler, accum, w_packed[len - 2]);
        let s0 = add_small_sigma0(compiler, accum, w_packed[len - 15]);

        // W[i] = σ₁(W[i-2]) + W[i-7] + σ₀(W[i-15]) + W[i-16]
        let result = add_u32_addition_spread(
            compiler,
            accum,
            &[s1, w_packed[len - 7], s0, w_packed[len - 16]],
            &[],
            &BYTE_CHUNKS,
        );
        w_packed.push(result.packed);
    }

    w_packed.try_into().unwrap()
}

/// SHA256 compression function using the spread trick.
/// - ROTR is zero-cost chunk permutation
/// - AND/XOR computed via spread addition + bit extraction
/// - Dynamic-width spread table (width chosen by cost model)
/// - Working variable caching: b,c reuse a-type chunks from previous rounds;
///   f,g reuse e-type chunks
pub(crate) fn add_sha256_compression(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    inputs_and_outputs: Vec<(
        Vec<ConstantOrR1CSWitness>,
        Vec<ConstantOrR1CSWitness>,
        Vec<usize>,
    )>,
    spread_table_bits: u32,
) -> BTreeMap<u32, Vec<usize>> {
    assert!(
        FieldElement::MODULUS_BIT_SIZE > 64,
        "Spread trick requires p >> 2^64; unsound for small fields like M31"
    );

    if inputs_and_outputs.is_empty() {
        return BTreeMap::new();
    }

    // Single shared accumulator across ALL SHA256 compressions
    let mut accum = SpreadAccumulator::new(spread_table_bits);

    for (inputs, hash_values, outputs) in inputs_and_outputs {
        assert_eq!(
            inputs.len(),
            16,
            "SHA256 requires exactly 16 input u32 words"
        );
        assert_eq!(
            hash_values.len(),
            8,
            "SHA256 requires exactly 8 initial hash values"
        );
        assert_eq!(
            outputs.len(),
            8,
            "SHA256 produces exactly 8 output u32 words"
        );

        // Extract packed witness indices, pinning constants.
        let w_one = r1cs_compiler.witness_one();
        let input_packed: [usize; 16] = inputs
            .iter()
            .map(|input| match input {
                ConstantOrR1CSWitness::Witness(idx) => *idx,
                ConstantOrR1CSWitness::Constant(val) => r1cs_compiler
                    .add_sum(vec![SumTerm(Some(*val), w_one)]),
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Track which hash values are constants for optimized
        // decomposition (no spread-table lookups needed).
        let hash_constant_u32: [Option<u32>; 8] = hash_values
            .iter()
            .map(|hv| match hv {
                ConstantOrR1CSWitness::Constant(val) => {
                    Some(val.into_bigint().0[0] as u32)
                }
                ConstantOrR1CSWitness::Witness(_) => None,
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let hash_packed: [usize; 8] = hash_values
            .iter()
            .map(|hv| match hv {
                ConstantOrR1CSWitness::Witness(idx) => *idx,
                ConstantOrR1CSWitness::Constant(val) => r1cs_compiler
                    .add_sum(vec![SumTerm(Some(*val), w_one)]),
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Range-check input words via byte decomposition.
        // Skip constants — known to be valid u32 at compile time.
        for (input, &packed) in inputs.iter().zip(input_packed.iter())
        {
            if matches!(input, ConstantOrR1CSWitness::Witness(_)) {
                decompose_to_spread_word(
                    r1cs_compiler,
                    &mut accum,
                    packed,
                    &BYTE_CHUNKS,
                );
            }
        }

        // Decompose initial hash values into chunk patterns needed for
        // first round:
        //   H[0..2] → a-type [2,11,9,10] (for Σ₀, Maj)
        //   H[3]    → byte [8,8,8,8]     (only used in addition)
        //   H[4..6] → e-type [6,5,14,7]  (for Σ₁, Ch)
        //   H[7]    → byte [8,8,8,8]     (only used in addition)
        // Constants use pinned spread witnesses instead of lookups.
        let a0 = decompose_maybe_constant(
            r1cs_compiler, &mut accum, hash_packed[0],
            hash_constant_u32[0], &SIGMA0_CHUNKS,
        );
        let b0 = decompose_maybe_constant(
            r1cs_compiler, &mut accum, hash_packed[1],
            hash_constant_u32[1], &SIGMA0_CHUNKS,
        );
        let c0 = decompose_maybe_constant(
            r1cs_compiler, &mut accum, hash_packed[2],
            hash_constant_u32[2], &SIGMA0_CHUNKS,
        );
        let d0 = decompose_maybe_constant(
            r1cs_compiler, &mut accum, hash_packed[3],
            hash_constant_u32[3], &BYTE_CHUNKS,
        );
        let e0 = decompose_maybe_constant(
            r1cs_compiler, &mut accum, hash_packed[4],
            hash_constant_u32[4], &SIGMA1_CHUNKS,
        );
        let f0 = decompose_maybe_constant(
            r1cs_compiler, &mut accum, hash_packed[5],
            hash_constant_u32[5], &SIGMA1_CHUNKS,
        );
        let g0 = decompose_maybe_constant(
            r1cs_compiler, &mut accum, hash_packed[6],
            hash_constant_u32[6], &SIGMA1_CHUNKS,
        );
        let h0 = decompose_maybe_constant(
            r1cs_compiler, &mut accum, hash_packed[7],
            hash_constant_u32[7], &BYTE_CHUNKS,
        );

        // Message schedule expansion
        let w = add_message_schedule_spread(r1cs_compiler, &mut accum, &input_packed);

        // Initialize working variables
        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;
        let mut e = e0;
        let mut f = f0;
        let mut g = g0;
        let mut h_word = h0;

        // 64 compression rounds
        for i in 0..64 {
            // Σ₁(e) — uses cached e-type chunks [6,5,14,7]
            let sigma1_packed = add_cap_sigma1_spread(r1cs_compiler, &mut accum, &e);

            // Ch(e,f,g) — uses cached e-type chunks
            let ch_packed = add_ch_spread(r1cs_compiler, &mut accum, &e, &f, &g);

            // Σ₀(a) — uses cached a-type chunks [2,11,9,10]
            let sigma0_packed = add_cap_sigma0_spread(r1cs_compiler, &mut accum, &a);

            // Maj(a,b,c) — uses cached a-type chunks
            let maj_packed = add_maj_spread(r1cs_compiler, &mut accum, &a, &b, &c);

            // new_e = d + h + Σ₁(e) + Ch + K[i] + W[i]
            // Decompose into e-type chunks for next round's Σ₁
            let new_e = add_u32_addition_spread(
                r1cs_compiler,
                &mut accum,
                &[d.packed, h_word.packed, sigma1_packed, ch_packed, w[i]],
                &[SHA256_K[i]],
                &SIGMA1_CHUNKS,
            );

            // new_a = h + Σ₁(e) + Ch + Σ₀(a) + Maj + K[i] + W[i]
            // Decompose into a-type chunks for next round's Σ₀
            let new_a = add_u32_addition_spread(
                r1cs_compiler,
                &mut accum,
                &[
                    h_word.packed,
                    sigma1_packed,
                    ch_packed,
                    sigma0_packed,
                    maj_packed,
                    w[i],
                ],
                &[SHA256_K[i]],
                &SIGMA0_CHUNKS,
            );

            // Shift working variables:
            // [new_a, a, b, c, new_e, e, f, g]
            h_word = g;
            g = f;
            f = e;
            e = new_e;
            d = c;
            c = b;
            b = a;
            a = new_a;
        }

        // Final hash: H'[i] = H[i] + working[i] (mod 2^32)
        let final_packed_vars = [
            a.packed,
            b.packed,
            c.packed,
            d.packed,
            e.packed,
            f.packed,
            g.packed,
            h_word.packed,
        ];

        for i in 0..8 {
            let final_word = add_u32_addition_spread(
                r1cs_compiler,
                &mut accum,
                &[hash_packed[i], final_packed_vars[i]],
                &[],
                &BYTE_CHUNKS,
            );

            // Constrain final packed result to match output witness
            r1cs_compiler.r1cs.add_constraint(
                &[(FieldElement::ONE, final_word.packed)],
                &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                &[(FieldElement::ONE, outputs[i])],
            );
        }
    }

    // Build spread table LogUp constraints once for ALL compressions
    add_spread_table_constraints(r1cs_compiler, accum)
}

/// Route hash-value decomposition through the constant-optimized path
/// when the value is known at compile time, falling back to the
/// standard spread-table-backed decomposition otherwise.
fn decompose_maybe_constant(
    compiler: &mut NoirToR1CSCompiler,
    accum: &mut SpreadAccumulator,
    packed: usize,
    constant_u32: Option<u32>,
    chunk_spec: &[u32],
) -> SpreadWord {
    if let Some(val) = constant_u32 {
        decompose_constant_to_spread_word(
            compiler,
            packed,
            val,
            chunk_spec,
            accum.table_bits,
        )
    } else {
        decompose_to_spread_word(compiler, accum, packed, chunk_spec)
    }
}
