// ProveKit Recursive Verifier -- Shared Types & Compile-Time Constants
//
// These constants are set for a SPECIFIC inner circuit. Changing the inner
// circuit (or its WHIR configuration) requires adjusting these values and
// recompiling. `generate-noir-inputs` auto-syncs these constants.

// --- Protocol parameters (set per target inner circuit) ---

// log2(number of R1CS constraints)
pub global LOG_NUM_CONSTRAINTS: u32 = 1;
// log2(number of witness variables in the WHIR MLE)
pub global LOG_NUM_VARIABLES: u32 = 13;
// Number of WHIR middle folding rounds (excluding initial and final)
pub global NUM_WHIR_ROUNDS: u32 = 3;
// Folding factor per WHIR round
pub global FOLDING_FACTOR: u32 = 3;
// Number of in-domain queries per WHIR round
pub global MAX_QUERIES_PER_ROUND: u32 = 127;
// Merkle tree height = log2(codeword_length / interleaving_depth)
pub global TREE_HEIGHT: u32 = 12;
// Number of out-of-domain samples per WHIR round
pub global OOD_SAMPLES: u32 = 1;
// Reed-Solomon rate (log2 of inverse rate)
pub global LOG_INV_RATE: u32 = 0;
// Proof-of-work bits per round
pub global POW_BITS: u32 = 6;
// Maximum number of public inputs from the inner circuit
pub global MAX_PUBLIC_INPUTS: u32 = 0;
// Maximum non-zero entries per R1CS matrix
pub global MAX_MATRIX_CELLS: u32 = 3;
// Number of logup challenges (0 = single commitment mode)
pub global NUM_CHALLENGES: u32 = 0;
// Size of w1 (first witness segment)
pub global W1_SIZE: u32 = 5;
// Number of WHIR batch polynomials
pub global BATCH_SIZE: u32 = 1;

// --- zkWHIR blinding parameters ---

// OOD samples for the blinding commitment
pub global BLINDING_OOD_SAMPLES: u32 = 1;
// Number of blinding WHIR folding rounds
pub global BLINDING_WHIR_ROUNDS: u32 = 3;
// Blinding tree height
pub global BLINDING_TREE_HEIGHT: u32 = 11;
// Number of blinding polynomial vectors
pub global NUM_BLINDING_VECTORS: u32 = 14;
// Number of witness variables in the WHIR (mu = m = LOG_NUM_VARIABLES)
pub global NUM_WITNESS_VARIABLES: u32 = 13;
// Maximum queries for blinding WHIR rounds
pub global BLINDING_MAX_QUERIES: u32 = 127;
// Blinding fold size (same folding factor)
pub global BLINDING_FOLD_SIZE: u32 = 8;
// Full blinding Merkle leaf row width = NUM_BLINDING_VECTORS * BLINDING_FOLD_SIZE
pub global BLINDING_MERKLE_LEAF_SIZE: u32 = NUM_BLINDING_VECTORS * BLINDING_FOLD_SIZE;

// --- WHIR inner verification parameters ---
// Number of linear forms = 3 (evals_az/bz/cz) + 1 (blinding) = 4
pub global NUM_LINEAR_FORMS: u32 = 4;
// Number of w_folded evaluations = NUM_LINEAR_FORMS * BATCH_SIZE * (NUM_WITNESS_VARIABLES + 1)
pub global NUM_W_FOLDED_EVALS: u32 = 56;
// Final sumcheck polynomial size for the inner (blinded) WHIR
pub global FINAL_POLY_SIZE: u32 = 2;
// Final sumcheck polynomial size for the blinding WHIR
pub global BLINDING_FINAL_POLY_SIZE: u32 = 1;

// --- Derived constants ---

// 2^folding_factor -- number of leaf elements per Merkle query
pub global FOLD_SIZE: u32 = 8; // 1 << FOLDING_FACTOR
// Number of sumcheck rounds in the Spartan sumcheck (= LOG_NUM_CONSTRAINTS)
pub global SUMCHECK_ROUNDS: u32 = LOG_NUM_CONSTRAINTS;
// Cubic polynomial degree + 1 (coefficients per sumcheck round)
pub global CUBIC_POLY_SIZE: u32 = 4;
// Final WHIR sumcheck rounds for the inner (blinded) WHIR
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
pub global STIR_BYTES_PER_INDEX: u32 = (TREE_HEIGHT + 7) / 8;
pub global BLINDING_STIR_BYTES_PER_INDEX: u32 = (BLINDING_TREE_HEIGHT + 7) / 8;
pub global STIR_TOTAL_BYTES: u32 = MAX_QUERIES_PER_ROUND * STIR_BYTES_PER_INDEX;
pub global BLINDING_STIR_TOTAL_BYTES: u32 = BLINDING_MAX_QUERIES * BLINDING_STIR_BYTES_PER_INDEX;

// Upper bound for squeeze_stir_challenges loop iterations.
// Must be >= max(STIR_TOTAL_BYTES, BLINDING_STIR_TOTAL_BYTES).
pub global MAX_STIR_BYTES: u32 = 254;

// Number of constraint RLC terms for the inner WHIR.
pub global INNER_WHIR_CONSTRAINT_COUNT: u32 = 5;
// Constraint count for the blinding WHIR.
pub global BLINDING_WHIR_CONSTRAINT_COUNT: u32 = 5;

// Interleaving depth of the IRS commitment.
pub global INTERLEAVING_DEPTH: u32 = 8; // = 1 << FOLDING_FACTOR

// Number of gammas in the zkWHIR per-gamma loop.
pub global MAX_GAMMAS: u32 = 1016;

// --- Sparse matrix representation ---

pub struct MatrixCell {
    pub row: u32,
    pub col: u32,
    pub val: Field,
}

// --- Precomputed powers of 256: POW256[i] = 256^i ---
//
// Used by bytes_le_to_field for byte decomposition and reconstruction of
// field elements. Hash-independent.
pub global POW256: [Field; 32] = [
    1,
    256,
    65536,
    16777216,
    4294967296,
    1099511627776,
    281474976710656,
    72057594037927936,
    18446744073709551616,
    4722366482869645213696,
    1208925819614629174706176,
    309485009821345068724781056,
    79228162514264337593543950336,
    20282409603651670423947251286016,
    5192296858534827628530496329220096,
    1329227995784915872903807060280344576,
    340282366920938463463374607431768211456,
    87112285931760246646623899502532662132736,
    22300745198530623141535718272648361505980416,
    5708990770823839524233143877797980545530986496,
    1461501637330902918203684832716283019655932542976,
    374144419156711147060143317175368453031918731001856,
    95780971304118053647396689196894323976171195136475136,
    24519928653854221733733552434404946937899825954937634816,
    6277101735386680763835789423207666416102355444464034512896,
    1606938044258990275541962092341162602522202993782792835301376,
    411376139330301510538742295639337626245683966408394965837152256,
    105312291668557186697918027683670432318895095400549111254310977536,
    26959946667150639794667015087019630673637144422540572481103610249216,
    6901746346790563787434755862277025452451108972170386555162524223799296,
    1766847064778384329583297500742918515827483896875618958121606201292619776,
    452312848583266388373324160190187140051835877600158453279131187530910662656,
];

// --- Field element <-> bytes conversion utilities ---

pub fn field_to_bytes_le(f: Field) -> [u8; 32] {
    f.to_le_bytes()
}

pub fn bytes_le_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result += (bytes[i] as Field) * POW256[i];
    }
    result
}

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

// --- Field element reduction from 64 bytes ---

// 2^256 mod BN254 scalar field p.
pub global TWO_POW_256: Field = 6350874878119819312338956282401532410528162663560392320966563075034087161851;

// Convert 64 bytes (little-endian) to a field element via modular reduction.
// Matches spongefish's from_le_bytes_mod_order on 64 bytes.
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
    let mut result = coeffs[3];
    result = result * x + coeffs[2];
    result = result * x + coeffs[1];
    result = result * x + coeffs[0];
    result
}
