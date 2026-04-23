// ProveKit Recursive Verifier -- Shared Types & Compile-Time Constants
//
// These constants are set for a SPECIFIC inner circuit. Changing the inner
// circuit (or its WHIR configuration) requires adjusting these values and
// recompiling. `generate-noir-inputs` auto-syncs these constants.

// --- Protocol parameters (set per target inner circuit) ---

// log2(number of R1CS constraints)
pub global LOG_NUM_CONSTRAINTS: u32 = 19;
// log2(number of witness variables in the WHIR MLE)
pub global LOG_NUM_VARIABLES: u32 = 19;
// Number of WHIR middle folding rounds (excluding initial and final)
pub global NUM_WHIR_ROUNDS: u32 = 5;
// Folding factor per WHIR round
pub global FOLDING_FACTOR: u32 = 3;
// Number of in-domain queries per WHIR round
pub global MAX_QUERIES_PER_ROUND: u32 = 127;
// Merkle tree height = log2(codeword_length / interleaving_depth)
pub global TREE_HEIGHT: u32 = 18;
// Number of out-of-domain samples per WHIR round
pub global OOD_SAMPLES: u32 = 1;
// Reed-Solomon rate (log2 of inverse rate)
pub global LOG_INV_RATE: u32 = 0;
// Proof-of-work bits per round
pub global POW_BITS: u32 = 9;
// Maximum number of public inputs from the inner circuit
pub global MAX_PUBLIC_INPUTS: u32 = 4;
// Maximum non-zero entries per R1CS matrix
pub global MAX_MATRIX_CELLS: u32 = 4500496;
// Number of logup challenges (0 = single commitment mode)
pub global NUM_CHALLENGES: u32 = 0;
// Size of w1 (first witness segment)
pub global W1_SIZE: u32 = 267272;
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
pub global NUM_BLINDING_VECTORS: u32 = 20;
// Number of witness variables in the WHIR (mu = m = LOG_NUM_VARIABLES)
pub global NUM_WITNESS_VARIABLES: u32 = 19;
// Maximum queries for blinding WHIR rounds
pub global BLINDING_MAX_QUERIES: u32 = 127;
// Blinding fold size (same folding factor)
pub global BLINDING_FOLD_SIZE: u32 = 8;
// Full blinding Merkle leaf row width = NUM_BLINDING_VECTORS * BLINDING_FOLD_SIZE
pub global BLINDING_MERKLE_LEAF_SIZE: u32 = NUM_BLINDING_VECTORS * BLINDING_FOLD_SIZE;

// OOD answer counts for the initial commitments. For each of the `*_OOD_SAMPLES`
// out-of-domain points, the prover sends one evaluation per polynomial vector
// (`BATCH_SIZE` for the blinded commit, `NUM_BLINDING_VECTORS` for the blinding
// commit). See `whir::protocols::irs_commit::receive_commitment`:
//     oods_matrix = prover_messages_vec(out_domain_samples * num_vectors)
pub global INITIAL_OOD_COUNT: u32 = OOD_SAMPLES * BATCH_SIZE;
pub global BLINDING_INITIAL_OOD_COUNT: u32 = BLINDING_OOD_SAMPLES * NUM_BLINDING_VECTORS;

// --- WHIR inner verification parameters ---
// Number of linear forms = 3 (evals_az/bz/cz) + 1 (blinding) = 4
pub global NUM_LINEAR_FORMS: u32 = 5;
// Number of w_folded evaluations = NUM_LINEAR_FORMS * BATCH_SIZE * (NUM_WITNESS_VARIABLES + 1)
pub global NUM_W_FOLDED_EVALS: u32 = 100;
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
pub global MAX_STIR_BYTES: u32 = 381;

// Number of constraint RLC terms for the inner WHIR.
pub global INNER_WHIR_CONSTRAINT_COUNT: u32 = 6;
// Constraint count for the blinding WHIR.
pub global BLINDING_WHIR_CONSTRAINT_COUNT: u32 = 6;

// Interleaving depth of the IRS commitment.
pub global INTERLEAVING_DEPTH: u32 = 8; // = 1 << FOLDING_FACTOR

// Number of gammas in the zkWHIR per-gamma loop.
pub global MAX_GAMMAS: u32 = 1016;

// --- BN254 NTT constants for in-circuit gamma coset expansion ---
//
// Layout for the initial IRS commitment (ProveKit uses its own `RSFr` NTT
// engine; see provekit/common/src/ntt.rs). Values derive directly from
// TREE_HEIGHT and INTERLEAVING_DEPTH.
//   IRS_CODEWORD_LENGTH = 2^TREE_HEIGHT
//     (== codeword_length in whir::irs_commit::Config; matches Merkle leaf count)
//   FULL_DOMAIN_SIZE    = IRS_CODEWORD_LENGTH * INTERLEAVING_DEPTH = 2^(TREE_HEIGHT+3)
//
// OMEGA_FULL = ntt::generator(FULL_DOMAIN_SIZE)
//            = TWO_ADIC_ROOT_OF_UNITY^(2^(TWO_ADICITY - log2(FULL_DOMAIN_SIZE)))
// (see Fr::get_root_of_unity in ark-ff; ProveKit's RSFr::generator calls it).
// For TREE_HEIGHT = 18 (FULL_DOMAIN_SIZE = 2^21), this is:
pub global OMEGA_FULL: Field =
    13536764371732269273912573961853310557438878140379554347802702086337840854307;

// ZETA_POWERS[j] = OMEGA_FULL^(IRS_CODEWORD_LENGTH * j) for j in 0..INTERLEAVING_DEPTH.
// zeta = OMEGA_FULL^IRS_CODEWORD_LENGTH is a primitive INTERLEAVING_DEPTH-th root
// of unity (= primitive 8th root of unity for INTERLEAVING_DEPTH = 8).
// Used in coset expansion: gamma_{q,j} = OMEGA_FULL^rev_idx_q * ZETA_POWERS[j].
pub global ZETA_POWERS: [Field; 8] = [
    1,
    19540430494807482326159819597004422086093766032135589407132600596362845576832,
    21888242871839275217838484774961031246007050428528088939761107053157389710902,
    13274704216607947843011480449124596415239537050559949017414504948711435969894,
    21888242871839275222246405745257275088548364400416034343698204186575808495616,
    2347812377031792896086586148252853002454598368280444936565603590212962918785,
    4407920970296243842541313971887945403937097133418418784715,
    8613538655231327379234925296132678673308827349856085326283699237864372525723,
];

// Full IRS codeword length (num_leaves passed to challenge_indices);
// STIR query indices are in [0, IRS_CODEWORD_LENGTH).
pub global IRS_CODEWORD_LENGTH: u32 = 1 << TREE_HEIGHT;

// ProveKit uses the `provekit_ntt` feature (see provekit/common/Cargo.toml),
// which swaps in the `RSFr` NTT engine. Its `evaluation_points` bit-reverses
// each raw index before raising the codeword-length generator to that power:
//   alpha = RSFr::generator(IRS_CODEWORD_LENGTH)^bit_reverse(idx, TREE_HEIGHT)
// so query_index(alpha, omega_powers) = bit_reverse(idx, TREE_HEIGHT), and the
// coset_offset used in all_gammas is OMEGA_FULL^bit_reverse(idx, TREE_HEIGHT).

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

// --- Field exponentiation by u32 ---

// Compute base^exp via 32-round repeated squaring.
// Works for any exp in [0, 2^32); result for exp = 0 is 1.
pub fn pow_u32(base: Field, exp: u32) -> Field {
    let mut result: Field = 1;
    let mut base_pow = base;
    let mut remaining = exp;
    for _ in 0..32 {
        if remaining & 1 == 1 {
            result = result * base_pow;
        }
        base_pow = base_pow * base_pow;
        remaining = remaining >> 1;
    }
    result
}

// Bit-reverse the low `bits` of x. For x < 2^bits, returns the bit-reversal
// of x within that window. Bounded loop at 32 to cover u32 exponents.
pub fn bit_reverse_u32(x: u32, bits: u32) -> u32 {
    let mut r: u32 = 0;
    let mut v = x;
    for i in 0..32 {
        if (i as u32) < bits {
            r = (r << 1) | (v & 1);
            v = v >> 1;
        }
    }
    r
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
