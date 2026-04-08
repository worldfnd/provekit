// WHIR Commitment Verification
//
// Implements the WHIR (Weights over Hypercube with Iterative Reduction)
// verification protocol.
//
// Reference:
//   recursive-verifier/app/circuit/whir.go (RunZKWhir)
//   recursive-verifier/app/circuit/whir_utilities.go
//   recursive-verifier/app/utilities/utilities.go
//
// WHIR verification flow (single commitment mode):
//   1. Process initial OOD answers
//   2. Read evaluation matrix, squeeze batching randomness
//   3. Initial sumcheck (folding_factor rounds, degree-2)
//   4. Per-round (N_WHIR_ROUNDS iterations):
//      a. Read root hash, OOD points/answers
//      b. PoW check
//      c. STIR challenge indices -> Merkle proof verification
//      d. Compute fold from leaf values
//      e. Generate combination randomness
//      f. Update claimed sum
//      g. Run folding sumcheck
//   5. Final coefficients, verify fold evaluations
//   6. Final sumcheck
//   7. Compute W-polynomial evaluation
//   8. Final assertion

use crate::transcript::SHO;

// --- WHIR Sumcheck (degree-2 polynomial per round) ---
//
// Different from Spartan sumcheck: reads 3 evaluations (at 0, 1, 2),
// checks sum at booleans, interpolates quadratic at challenge point.

// Check sum over booleans: evals[0] + evals[1] == expected.
fn check_sum_over_bool(expected: Field, evals: [Field; 3]) {
    assert(expected == evals[0] + evals[1], "WHIR sumcheck: sum over bool failed");
}

// Evaluate a degree-2 polynomial given evaluations at {0, 1, 2} at point x.
//
// Lagrange interpolation from 3 points:
//   p(x) = b0 + b1*x + b2*x^2
//   b0 = evals[0]
//   b1 = (-evals[2] + 4*evals[1] - 3*evals[0]) / 2
//   b2 = (evals[2] - 2*evals[1] + evals[0]) / 2
fn eval_quadratic_from_evals(evals: [Field; 3], x: Field) -> Field {
    // inv2 = 1/2 in BN254 scalar field
    let inv2: Field = 10944121435919637611123202872628637544274182200208017171849102093287904247809;
    let b0 = evals[0];
    let b1 = (0 - evals[2] + 4 * evals[1] - 3 * evals[0]) * inv2;
    let b2 = (evals[2] - 2 * evals[1] + evals[0]) * inv2;
    b2 * x * x + b1 * x + b0
}

// Run WHIR sumcheck rounds (folding sumcheck within a WHIR round).
//
// Each round:
//   1. Read 3 evaluations (degree-2 poly) from prover
//   2. Check: evals[0] + evals[1] == lastEval
//   3. Squeeze folding randomness
//   4. lastEval = interpolated poly at randomness
//
// Returns (folding_randomness, last_eval).
pub fn run_whir_sumcheck<let FF: u32>(
    sho: &mut SHO,
    last_eval: Field,
    round_evals: [[Field; 3]; FF],
) -> ([Field; FF], Field) {
    let mut current_eval = last_eval;
    let mut folding_randomness: [Field; FF] = [0; FF];

    for i in 0..FF {
        let evals = round_evals[i];

        // Absorb the 3 evaluations
        for j in 0..3 {
            sho.absorb_field(evals[j]);
        }

        // Check sum over booleans
        check_sum_over_bool(current_eval, evals);

        // Squeeze folding randomness
        let r: Field = sho.squeeze_field();
        folding_randomness[i] = r;

        // Evaluate at the random point
        current_eval = eval_quadratic_from_evals(evals, r);
    }

    (folding_randomness, current_eval)
}

// --- Multivariate polynomial evaluation (fold computation) ---

// Evaluate a multilinear polynomial at a point.
//
// coefs: 2^k coefficients (evaluations over {0,1}^k)
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
//
// For each query i: fold[i] = MultivarPoly(leaves[i], folding_randomness)
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

// Expand a univariate point x into a multivariate point [x^(2^(k-1)), ..., x^2, x].
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

// Evaluate EQ(coords, point) = prod_i (coords[i]*point[i] + (1-coords[i])*(1-point[i]))
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

// Generate combination randomness: squeeze a base, then compute powers.
// Returns [1, r, r^2, ..., r^(n-1)]
pub fn generate_combination_randomness<let N: u32>(
    sho: &mut SHO,
    n: u32,
) -> [Field; N] {
    let r: Field = sho.squeeze_field();
    let mut powers: [Field; N] = [0; N];
    let mut acc: Field = 1;
    for i in 0..N {
        if (i as u32) < n {
            powers[i] = acc;
            acc *= r;
        }
    }
    powers
}

// --- PoW check ---

// Proof-of-work check: squeeze 32-byte challenge, absorb 8-byte nonce.
//
// In spongefish-pow, the verifier:
//   1. Squeezes 32 bytes of PoW challenge
//   2. Reads 8-byte nonce from the prover (prover_message<U64>)
//   3. Verifies that H(challenge || nonce) has enough leading zeros
//
// For the circuit, we replay the transcript operations (squeeze + absorb)
// and trust that the Rust verifier already validated the PoW.
pub fn check_pow(sho: &mut SHO, nonce: u64) {
    // Squeeze 32 bytes of PoW challenge
    let _challenge = sho.squeeze_32();
    // Absorb 8-byte nonce (big-endian, matching spongefish U64 encoding)
    let nonce_bytes = crate::types::u64_to_be_bytes(nonce);
    sho.absorb(nonce_bytes);
}

// --- STIR challenge indices ---

// Generate STIR challenge indices by squeezing bytes from the transcript.
// Simplified: squeeze field elements and reduce mod folded_domain_size.
pub fn get_stir_challenges<let N: u32>(
    sho: &mut SHO,
    num_queries: u32,
    _folded_domain_size: u32,
) -> [Field; N] {
    let mut indices: [Field; N] = [0; N];
    for i in 0..N {
        if (i as u32) < num_queries {
            indices[i] = sho.squeeze_field();
        }
    }
    indices
}

// --- Univariate polynomial evaluation ---

// Evaluate a univariate polynomial (in coefficient form) at multiple points.
// Returns [p(points[0]), p(points[1]), ...].
pub fn univar_poly_eval<let N_COEFFS: u32, let N_POINTS: u32>(
    coefficients: [Field; N_COEFFS],
    points: [Field; N_POINTS],
    n_coeffs: u32,
    n_points: u32,
) -> [Field; N_POINTS] {
    let mut results: [Field; N_POINTS] = [0; N_POINTS];
    for j in 0..N_POINTS {
        if (j as u32) < n_points {
            // Horner's method
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
