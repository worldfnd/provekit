// ProveKit Recursive Verifier -- Shared Types & Compile-Time Constants
//
// These constants are set for a SPECIFIC inner circuit. Changing the inner
// circuit (or its WHIR configuration) requires adjusting these values and
// recompiling.

// --- Protocol parameters (set per target inner circuit) ---

// NOTE: These are SMALL test parameters for initial compilation.
// For a real inner circuit, increase to match the WHIR configuration.

// log2(number of R1CS constraints)
pub global LOG_NUM_CONSTRAINTS: u32 = 5;
// log2(number of witness variables)
pub global LOG_NUM_VARIABLES: u32 = 5;
// Number of WHIR folding rounds (excluding final)
pub global NUM_WHIR_ROUNDS: u32 = 1;
// Folding factor per WHIR round
pub global FOLDING_FACTOR: u32 = 3;
// Number of in-domain queries per WHIR round
pub global MAX_QUERIES_PER_ROUND: u32 = 3;
// Merkle tree height (log2 of codeword length)
pub global TREE_HEIGHT: u32 = 5;
// Number of out-of-domain samples per WHIR round
pub global OOD_SAMPLES: u32 = 1;
// Reed-Solomon rate (log2 of inverse rate)
pub global LOG_INV_RATE: u32 = 2;
// Proof-of-work bits per round
pub global POW_BITS: u32 = 10;
// Maximum number of public inputs from the inner circuit
pub global MAX_PUBLIC_INPUTS: u32 = 4;
// Maximum non-zero entries per R1CS matrix
pub global MAX_MATRIX_CELLS: u32 = 100;
// Number of logup challenges (0 = single commitment mode)
pub global NUM_CHALLENGES: u32 = 0;
// Size of w1 (first witness segment)
pub global W1_SIZE: u32 = 32;
// Number of WHIR batch polynomials
pub global BATCH_SIZE: u32 = 1;

// --- zkWHIR blinding parameters ---
// The blinding commitment has its own WHIR config, potentially with
// different round count and tree height (usually smaller).

// OOD samples for the blinding commitment
pub global BLINDING_OOD_SAMPLES: u32 = 1;
// Number of blinding WHIR folding rounds
pub global BLINDING_WHIR_ROUNDS: u32 = 1;
// Blinding tree height
pub global BLINDING_TREE_HEIGHT: u32 = 5;
// Number of blinding polynomial vectors = num_polynomials * (num_witness_variables + 1)
// For single commitment mode with LOG_NUM_VARIABLES=5: 1 * (5 + 1) = 6
pub global NUM_BLINDING_VECTORS: u32 = 6;
// Number of witness variables in the blinding WHIR (mu)
pub global NUM_WITNESS_VARIABLES: u32 = 5;
// Maximum queries for blinding WHIR rounds
pub global BLINDING_MAX_QUERIES: u32 = 3;
// Blinding fold size (same folding factor)
pub global BLINDING_FOLD_SIZE: u32 = 8;

// --- WHIR inner verification parameters ---
// Number of linear forms = (public_inputs ? 1 : 0) + 3 (evals) + 1 (blinding) = 5
pub global NUM_LINEAR_FORMS: u32 = 5;
// Number of w_folded evaluations = NUM_LINEAR_FORMS * 1 * (NUM_WITNESS_VARIABLES + 1)
pub global NUM_W_FOLDED_EVALS: u32 = 30;
// Final sumcheck polynomial size (coefficients sent in clear at end of WHIR)
pub global FINAL_POLY_SIZE: u32 = 8;

// --- Derived constants ---

// 2^folding_factor -- number of leaf elements per Merkle query
pub global FOLD_SIZE: u32 = 8; // 1 << FOLDING_FACTOR
// Number of sumcheck rounds in the Spartan sumcheck (= LOG_NUM_CONSTRAINTS)
pub global SUMCHECK_ROUNDS: u32 = LOG_NUM_CONSTRAINTS;
// Cubic polynomial degree + 1 (coefficients per sumcheck round)
pub global CUBIC_POLY_SIZE: u32 = 4;

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

// Convert a u64 to 8 bytes big-endian (for spongefish counters, which use
// usize::to_be_bytes() and usize is 8 bytes on 64-bit).
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
