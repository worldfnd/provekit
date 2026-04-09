// WHIR Commitment Verification
//
// Implements the WHIR (Weights over Hypercube with Iterative Reduction)
// verification protocol.
//
// Reference:
//   whir/src/protocols/sumcheck.rs (quadratic sumcheck)
//   whir/src/protocols/whir.rs (Config::verify)
//   provekit/verifier/src/whir_r1cs.rs (WhirR1CSScheme::verify)

use crate::transcript::SHO;

// --- WHIR Quadratic Sumcheck ---
//
// Each round (from whir/protocols/sumcheck.rs verify()):
//   1. Read c0 (field) -- prover_message
//   2. Read c2 (field) -- prover_message
//   3. Derive c1 = sum - 2*c0 - c2
//   4. [Optional: per-round PoW -- squeeze 32 + absorb 8 LE nonce]
//   5. Squeeze folding_randomness (field) -- verifier_message
//   6. Update sum = (c2 * r + c1) * r + c0

// Run WHIR sumcheck WITHOUT per-round PoW.
// Used when round_pow difficulty is 0 (threshold == u64::MAX).
pub fn run_whir_sumcheck<let FF: u32>(
    sho: &mut SHO,
    sum: Field,
    round_coeffs: [[Field; 2]; FF],
) -> ([Field; FF], Field) {
    let mut current_sum = sum;
    let mut folding_randomness: [Field; FF] = [0; FF];

    for i in 0..FF {
        let c0 = round_coeffs[i][0];
        let c2 = round_coeffs[i][1];

        sho.absorb_field(c0);
        sho.absorb_field(c2);

        let r: Field = sho.squeeze_field();
        folding_randomness[i] = r;

        let c1 = current_sum - c0 - c0 - c2;
        current_sum = (c2 * r + c1) * r + c0;
    }

    (folding_randomness, current_sum)
}

// Run WHIR sumcheck WITH per-round PoW.
// Used when round_pow difficulty > 0 (threshold < u64::MAX).
pub fn run_whir_sumcheck_with_pow<let FF: u32>(
    sho: &mut SHO,
    sum: Field,
    round_coeffs: [[Field; 2]; FF],
    pow_nonces: [u64; FF],
) -> ([Field; FF], Field) {
    let mut current_sum = sum;
    let mut folding_randomness: [Field; FF] = [0; FF];

    for i in 0..FF {
        let c0 = round_coeffs[i][0];
        let c2 = round_coeffs[i][1];

        sho.absorb_field(c0);
        sho.absorb_field(c2);

        check_pow(sho, pow_nonces[i]);

        let r: Field = sho.squeeze_field();
        folding_randomness[i] = r;

        let c1 = current_sum - c0 - c0 - c2;
        current_sum = (c2 * r + c1) * r + c0;
    }

    (folding_randomness, current_sum)
}

// --- Multivariate polynomial evaluation (fold computation) ---

// Evaluate a multilinear polynomial at a point.
//
// coefs: 2^k evaluations over {0,1}^k
// vars: k variables
//
// Iterative folding: at each step, halve the array using
//   new[j] = old[j] * (1-r) + old[half+j] * r
pub fn multivar_poly<let N: u32, let K: u32>(
    coefs: [Field; N],
    vars: [Field; K],
) -> Field {
    let mut current: [Field; N] = coefs;
    let mut len: u32 = N;

    for i in 0..K {
        let var_idx = K - 1 - i;
        let r = vars[var_idx];
        let half = len / 2;
        for j in 0..N {
            if (j as u32) < half {
                current[j] = current[j] * (1 - r) + current[half + j] * r;
            }
        }
        len = half;
    }

    current[0]
}

// Compute fold: evaluate each query's leaf values at the folding randomness.
pub fn compute_fold<let N_QUERIES: u32, let LEAF_SIZE: u32, let FF: u32>(
    leaves: [[Field; LEAF_SIZE]; N_QUERIES],
    folding_randomness: [Field; FF],
    n_queries: u32,
) -> [Field; N_QUERIES] {
    let mut result: [Field; N_QUERIES] = [0; N_QUERIES];
    for i in 0..N_QUERIES {
        if (i as u32) < n_queries {
            result[i] = multivar_poly(leaves[i], folding_randomness);
        }
    }
    result
}

// --- Expand from univariate ---

// Expand a univariate point x into multivariate [x^(2^(k-1)), ..., x^2, x].
pub fn expand_from_univariate<let K: u32>(base: Field) -> [Field; K] {
    let mut result: [Field; K] = [0; K];
    let mut acc = base;
    for i in 0..K {
        result[K - 1 - i] = acc;
        acc = acc * acc;
    }
    result
}

// --- EQ polynomial evaluation ---

// EQ(coords, point) = prod_i (coords[i]*point[i] + (1-coords[i])*(1-point[i]))
pub fn eq_poly<let K: u32>(coords: [Field; K], point: [Field; K]) -> Field {
    let mut acc: Field = 1;
    for i in 0..K {
        acc *= coords[i] * point[i] + (1 - coords[i]) * (1 - point[i]);
    }
    acc
}

// --- Dot product ---

pub fn dot_product<let N: u32>(a: [Field; N], b: [Field; N], n: u32) -> Field {
    let mut result: Field = 0;
    for i in 0..N {
        if (i as u32) < n {
            result += a[i] * b[i];
        }
    }
    result
}

// --- Combination randomness generation ---

// geometric_challenge: squeeze a base and compute powers [1, r, r^2, ...].
//
// IMPORTANT: The WHIR library (geometric_challenge.rs) returns vec![F::ONE]
// for count <= 1 with ZERO transcript operations. Only squeeze when count >= 2.
pub fn generate_combination_randomness<let N: u32>(
    sho: &mut SHO,
    n: u32,
) -> [Field; N] {
    let mut powers: [Field; N] = [0; N];
    if n <= 1 {
        if N > 0 {
            powers[0] = 1;
        }
    } else {
        let r: Field = sho.squeeze_field();
        let mut acc: Field = 1;
        for i in 0..N {
            if (i as u32) < n {
                powers[i] = acc;
                acc *= r;
            }
        }
    }
    powers
}

// --- PoW check ---

// Proof-of-work transcript replay: squeeze 32-byte challenge, absorb 8-byte LE nonce.
//
// In spongefish-pow, the verifier:
//   1. Squeezes 32 bytes of PoW challenge (verifier_message)
//   2. Reads 8-byte nonce from the prover (prover_message<U64>)
//   3. Verifies H(challenge || nonce) has enough leading zeros
//
// The nonce is encoded as LITTLE-ENDIAN per the U64 codec (whir/transcript/codecs.rs).
// We replay the transcript operations and trust the Rust verifier validated the PoW.
pub fn check_pow(sho: &mut SHO, nonce: u64) {
    let _challenge = sho.squeeze_32();
    let nonce_bytes = crate::types::u64_to_le_bytes(nonce);
    sho.absorb(nonce_bytes);
}

// --- STIR challenge indices ---

// Generate STIR challenge indices by squeezing bytes from the transcript.
//
// The WHIR library (challenge_indices.rs) squeezes individual u8 bytes:
//   byte_count = ceil(log2(folded_domain_size)) / 8
//   total_bytes = byte_count * num_queries
//   Each index is assembled from byte_count LE bytes, reduced mod folded_domain_size.
//
// For the circuit, we squeeze the correct number of raw bytes to keep
// the transcript in sync. The actual index values are provided as hints
// (Merkle proof positions) and verified via Merkle proofs.
//
// BYTES_PER_INDEX must match the WHIR config: ceil(log2(folded_domain_size)) / 8.
pub fn squeeze_stir_challenges(
    sho: &mut SHO,
    num_queries: u32,
    bytes_per_index: u32,
) {
    let total_bytes = num_queries * bytes_per_index;
    for _i in 0..crate::types::MAX_STIR_BYTES {
        if (_i as u32) < total_bytes {
            let _byte = sho.squeeze_1();
        }
    }
}

// --- Univariate polynomial evaluation ---

// Evaluate a univariate polynomial (coefficient form) at multiple points.
pub fn univar_poly_eval<let N_COEFFS: u32, let N_POINTS: u32>(
    coefficients: [Field; N_COEFFS],
    points: [Field; N_POINTS],
    n_coeffs: u32,
    n_points: u32,
) -> [Field; N_POINTS] {
    let mut results: [Field; N_POINTS] = [0; N_POINTS];
    for j in 0..N_POINTS {
        if (j as u32) < n_points {
            let mut acc: Field = 0;
            for i in 0..N_COEFFS {
                if (i as u32) < n_coeffs {
                    acc = acc * points[j] + coefficients[n_coeffs - 1 - i];
                }
            }
            results[j] = acc;
        }
    }
    results
}
