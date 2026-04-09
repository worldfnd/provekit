// ProveKit Recursive Verifier -- Shared Types & Compile-Time Constants
//
// These constants are set for a SPECIFIC inner circuit. Changing the inner
// circuit (or its WHIR configuration) requires adjusting these values and
// recompiling.

// --- Protocol parameters (set per target inner circuit) ---
//
// Generated from noir_verifier_data.json for the acir_assert_zero test circuit.
// Inner circuit: 8 constraints, 10 witnesses -> m_0=3, m=13.

// log2(number of R1CS constraints)
pub global LOG_NUM_CONSTRAINTS: u32 = 3;
// log2(number of witness variables in the WHIR MLE)
pub global LOG_NUM_VARIABLES: u32 = 13;
// Number of WHIR middle folding rounds (excluding initial and final)
pub global NUM_WHIR_ROUNDS: u32 = 3;
// Folding factor per WHIR round
pub global FOLDING_FACTOR: u32 = 3;
// Number of in-domain queries per WHIR round
pub global MAX_QUERIES_PER_ROUND: u32 = 127;
// Merkle tree height = log2(codeword_length / interleaving_depth)
pub global TREE_HEIGHT: u32 = 9;
// Number of out-of-domain samples per WHIR round
pub global OOD_SAMPLES: u32 = 1;
// Reed-Solomon rate (log2 of inverse rate)
pub global LOG_INV_RATE: u32 = 2;
// Proof-of-work bits per round
pub global POW_BITS: u32 = 6;
// Maximum number of public inputs from the inner circuit
pub global MAX_PUBLIC_INPUTS: u32 = 0;
// Maximum non-zero entries per R1CS matrix
pub global MAX_MATRIX_CELLS: u32 = 100;
// Number of logup challenges (0 = single commitment mode)
pub global NUM_CHALLENGES: u32 = 0;
// Size of w1 (first witness segment)
pub global W1_SIZE: u32 = 10;
// Number of WHIR batch polynomials
pub global BATCH_SIZE: u32 = 1;

// --- zkWHIR blinding parameters ---

// OOD samples for the blinding commitment
pub global BLINDING_OOD_SAMPLES: u32 = 1;
// Number of blinding WHIR folding rounds
pub global BLINDING_WHIR_ROUNDS: u32 = 3;
// Blinding tree height
pub global BLINDING_TREE_HEIGHT: u32 = 8;
// Number of blinding polynomial vectors
pub global NUM_BLINDING_VECTORS: u32 = 14;
// Number of witness variables in the WHIR (mu = m = LOG_NUM_VARIABLES)
pub global NUM_WITNESS_VARIABLES: u32 = 13;
// Maximum queries for blinding WHIR rounds
pub global BLINDING_MAX_QUERIES: u32 = 127;
// Blinding fold size (same folding factor)
pub global BLINDING_FOLD_SIZE: u32 = 8;

// --- WHIR inner verification parameters ---
// Number of linear forms = 3 (evals_az/bz/cz) + 1 (blinding) = 4
// (No public_eval since MAX_PUBLIC_INPUTS=0)
pub global NUM_LINEAR_FORMS: u32 = 4;
// Number of w_folded evaluations = NUM_LINEAR_FORMS * BATCH_SIZE * (NUM_WITNESS_VARIABLES + 1)
pub global NUM_W_FOLDED_EVALS: u32 = 56;
// Final sumcheck polynomial size for the inner (blinded) WHIR
// = 1 << (m - initial_ff - NUM_WHIR_ROUNDS * ff) = 1 << (13 - 3 - 3*3) = 1 << 1 = 2
pub global FINAL_POLY_SIZE: u32 = 2;
// Final sumcheck polynomial size for the blinding WHIR
// = 1 << (blinding_m - blinding_ff - BLINDING_WHIR_ROUNDS * blinding_ff)
pub global BLINDING_FINAL_POLY_SIZE: u32 = 1;

// --- Derived constants ---

// 2^folding_factor -- number of leaf elements per Merkle query
pub global FOLD_SIZE: u32 = 8; // 1 << FOLDING_FACTOR
// Number of sumcheck rounds in the Spartan sumcheck (= LOG_NUM_CONSTRAINTS)
pub global SUMCHECK_ROUNDS: u32 = LOG_NUM_CONSTRAINTS;
// Cubic polynomial degree + 1 (coefficients per sumcheck round)
pub global CUBIC_POLY_SIZE: u32 = 4;
// Final WHIR sumcheck rounds for the inner (blinded) WHIR
// = m - initial_ff - NUM_WHIR_ROUNDS * ff = 13 - 3 - 3*3 = 1
pub global FINAL_SUMCHECK_ROUNDS: u32 = 1;
// Final WHIR sumcheck rounds for the blinding WHIR
pub global BLINDING_FINAL_SUMCHECK_ROUNDS: u32 = 0;
// Minimum-1 array size for per-round data (avoids zero-sized arrays in main).
pub global ROUND_ARRAY_SIZE: u32 = if NUM_WHIR_ROUNDS == 0 { 1 } else { NUM_WHIR_ROUNDS };
pub global BLINDING_ROUND_ARRAY_SIZE: u32 = if BLINDING_WHIR_ROUNDS == 0 { 1 } else { BLINDING_WHIR_ROUNDS };
// Same for final sumcheck arrays
pub global FINAL_SC_ARRAY_SIZE: u32 = if FINAL_SUMCHECK_ROUNDS == 0 { 1 } else { FINAL_SUMCHECK_ROUNDS };
pub global BLINDING_FINAL_SC_ARRAY_SIZE: u32 = if BLINDING_FINAL_SUMCHECK_ROUNDS == 0 { 1 } else { BLINDING_FINAL_SUMCHECK_ROUNDS };
pub global BLINDING_FINAL_POLY_ARRAY_SIZE: u32 = if BLINDING_FINAL_POLY_SIZE == 0 { 1 } else { BLINDING_FINAL_POLY_SIZE };

// --- STIR challenge parameters ---
// Bytes per STIR index = ceil(TREE_HEIGHT / 8).
// For TREE_HEIGHT=9: ceil(9/8) = 2 bytes per index.
pub global STIR_BYTES_PER_INDEX: u32 = (TREE_HEIGHT + 7) / 8;
pub global BLINDING_STIR_BYTES_PER_INDEX: u32 = (BLINDING_TREE_HEIGHT + 7) / 8;

// Total STIR bytes squeezed per opening = in_domain_samples * bytes_per_index.
pub global STIR_TOTAL_BYTES: u32 = MAX_QUERIES_PER_ROUND * STIR_BYTES_PER_INDEX;
pub global BLINDING_STIR_TOTAL_BYTES: u32 = BLINDING_MAX_QUERIES * BLINDING_STIR_BYTES_PER_INDEX;

// Upper bound for squeeze_stir_challenges loop iterations.
// Must be >= max(STIR_TOTAL_BYTES, BLINDING_STIR_TOTAL_BYTES) across all openings.
// 127 queries * 2 bytes = 254; round up to 256.
pub global MAX_STIR_BYTES: u32 = 256;

// Number of constraint RLC terms for the inner WHIR.
pub global INNER_WHIR_CONSTRAINT_COUNT: u32 = OOD_SAMPLES + NUM_LINEAR_FORMS;
// Constraint count for the blinding WHIR.
pub global BLINDING_WHIR_CONSTRAINT_COUNT: u32 = BLINDING_OOD_SAMPLES + NUM_LINEAR_FORMS;

// Interleaving depth of the IRS commitment.
pub global INTERLEAVING_DEPTH: u32 = FOLD_SIZE; // = 1 << FOLDING_FACTOR

// Number of gammas in the zkWHIR per-gamma loop.
pub global MAX_GAMMAS: u32 = MAX_QUERIES_PER_ROUND * INTERLEAVING_DEPTH;

// --- SHA256 constants ---

pub global SHA256_BLOCK_SIZE: u32 = 64;
pub global SHA256_DIGEST_SIZE: u32 = 32;
pub global SHA256_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// --- Sparse matrix representation ---

pub struct MatrixCell {
    pub row: u32,
    pub col: u32,
    pub val: Field,
}

// --- Field element <-> bytes conversion utilities ---

// Convert a field element to 32-byte little-endian representation.
// This matches arkworks' into_bigint().to_bytes_le().
pub fn field_to_bytes_le(f: Field) -> [u8; 32] {
    f.to_le_bytes()
}

// Convert 32 bytes (little-endian) to a field element.
// Assumes the value is already reduced mod p.
pub fn bytes_le_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    let mut pow: Field = 1;
    for i in 0..32 {
        result += (bytes[i] as Field) * pow;
        pow *= 256;
    }
    result
}

// Convert a u64 to 8 bytes big-endian (for spongefish SHO internal counters,
// which use usize::to_be_bytes()).
pub fn u64_to_be_bytes(val: u64) -> [u8; 8] {
    let mut out: [u8; 8] = [0; 8];
    out[0] = ((val >> 56) & 0xFF) as u8;
    out[1] = ((val >> 48) & 0xFF) as u8;
    out[2] = ((val >> 40) & 0xFF) as u8;
    out[3] = ((val >> 32) & 0xFF) as u8;
    out[4] = ((val >> 24) & 0xFF) as u8;
    out[5] = ((val >> 16) & 0xFF) as u8;
    out[6] = ((val >> 8) & 0xFF) as u8;
    out[7] = (val & 0xFF) as u8;
    out
}

// Convert a u64 to 8 bytes little-endian (for WHIR transcript messages,
// matching the U64 codec's to_le_bytes() in whir/transcript/codecs.rs).
pub fn u64_to_le_bytes(val: u64) -> [u8; 8] {
    let mut out: [u8; 8] = [0; 8];
    out[0] = (val & 0xFF) as u8;
    out[1] = ((val >> 8) & 0xFF) as u8;
    out[2] = ((val >> 16) & 0xFF) as u8;
    out[3] = ((val >> 24) & 0xFF) as u8;
    out[4] = ((val >> 32) & 0xFF) as u8;
    out[5] = ((val >> 40) & 0xFF) as u8;
    out[6] = ((val >> 48) & 0xFF) as u8;
    out[7] = ((val >> 56) & 0xFF) as u8;
    out
}

// Convert a u32 to 4 bytes big-endian.
pub fn u32_to_be_bytes(val: u32) -> [u8; 4] {
    let mut out: [u8; 4] = [0; 4];
    out[0] = ((val >> 24) & 0xFF) as u8;
    out[1] = ((val >> 16) & 0xFF) as u8;
    out[2] = ((val >> 8) & 0xFF) as u8;
    out[3] = (val & 0xFF) as u8;
    out
}

// --- Field element reduction from 64 bytes ---

// 2^256 mod BN254 scalar field p
// Used to reduce a 512-bit integer (from 64 squeezed bytes) to a field element.
// value = low_256 + high_256 * TWO_POW_256
pub global TWO_POW_256: Field = 6350874878119819312338956282401532410528162663560392320966563075034087161851;

// Convert 64 bytes (little-endian) to a field element via modular reduction.
// This matches spongefish's from_le_bytes_mod_order on 64 bytes:
//   result = (low_32_as_integer + high_32_as_integer * 2^256) mod p
pub fn bytes_le_to_field_wide(bytes: [u8; 64]) -> Field {
    let mut low_bytes: [u8; 32] = [0; 32];
    let mut high_bytes: [u8; 32] = [0; 32];
    for i in 0..32 {
        low_bytes[i] = bytes[i];
        high_bytes[i] = bytes[32 + i];
    }
    let low = bytes_le_to_field(low_bytes);
    let high = bytes_le_to_field(high_bytes);
    low + high * TWO_POW_256
}

// --- Cubic polynomial evaluation ---

// Evaluate a degree-3 polynomial at point x:
//   p(x) = c[0] + c[1]*x + c[2]*x^2 + c[3]*x^3
pub fn eval_cubic_poly(coeffs: [Field; 4], x: Field) -> Field {
    // Horner's method: ((c[3]*x + c[2])*x + c[1])*x + c[0]
    let mut result = coeffs[3];
    result = result * x + coeffs[2];
    result = result * x + coeffs[1];
    result = result * x + coeffs[0];
    result
}
