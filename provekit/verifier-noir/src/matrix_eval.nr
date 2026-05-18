//! R1CS sparse matrix evaluation against the eq polynomial over the boolean
//! hypercube.
//!
//! Used to compute the per-witness "alphas" weights that the integrated
//! verifier passes to WHIR's low-degree-test verifier: for each of A, B, C,
//!
//!   alphas_M[j] = sum over rows i of (eq(alpha, i) * M[i, j])
//!
//! The codegen tool (Phase 2C) emits the sparse matrices for the inner R1CS
//! as Noir constants in `matrices.nr`; `main.nr` calls `multiply_matrix_by_eq`
//! three times (once each for A, B, C) with the codegen-emitted triples.
//!
//! Cross-implementation KAT lives in
//! `provekit/verifier-noir-test/tests/matrix_eval_kat.rs`.

/// One non-zero entry of a sparse matrix.
pub struct SparseTriple {
    pub row: u32,
    pub col: u32,
    pub val: Field,
}

/// Compute the boolean-hypercube evaluations of `eq(alpha, x)` for all
/// `x in {0,1}^LOG_N`.
///
/// Index `k` of the returned array corresponds to the hypercube point where
/// `alpha[j]` takes the value of bit `(LOG_N - 1 - j)` of `k`. That is,
/// `alpha[0]` is the MSB of the index, matching the Rust reference at
/// `provekit/common/src/utils/sumcheck.rs::eval_eq`.
///
/// INVARIANT: `N == 1 << LOG_N` (asserted at call sites; Noir doesn't allow
/// this as a where-clause yet).
///
/// Entries past `_truncate_to` are still computed but ignored by callers
/// that only need the first `num_constraints` rows.
pub fn eq_hypercube_evals<let LOG_N: u32, let N: u32>(
    alpha: [Field; LOG_N],
    _truncate_to: u32,
) -> [Field; N] {
    let mut result: [Field; N] = [0; N];
    result[0] = 1;
    let mut size: u32 = 1;
    for i in 0..LOG_N {
        // Process alpha coordinates in REVERSE so alpha[0] ends up as the MSB
        // of the hypercube index, matching Rust's `eval_eq` convention.
        let alpha_i = alpha[LOG_N - 1 - i];
        for j in 0..size {
            let v = result[j];
            let v_alpha = v * alpha_i;
            result[j + size] = v_alpha;
            result[j] = v - v_alpha; // = v * (1 - alpha_i)
        }
        size *= 2;
    }
    result
}

/// Compute `M^T . eq_evals` over the boolean hypercube, where M is given as
/// a list of sparse (row, col, val) triples.
pub fn multiply_matrix_by_eq<let TRIPLES: u32, let NUM_ROWS: u32, let NUM_COLS: u32>(
    triples: [SparseTriple; TRIPLES],
    eq_evals: [Field; NUM_ROWS],
) -> [Field; NUM_COLS] {
    let mut result: [Field; NUM_COLS] = [0; NUM_COLS];
    for k in 0..TRIPLES {
        let t = triples[k];
        result[t.col] += eq_evals[t.row] * t.val;
    }
    result
}

// --- in-circuit KAT ---
//
// The 3x4 test R1CS A matrix (from provekit/common/src/utils/sumcheck.rs::make_test_r1cs):
//
//   A = [[1, 2, 0, 0],
//        [0, 0, 3, 0],
//        [1, 0, 0, 1]]   // 5 non-zero entries total
//
// with alpha = [2, 3] (LOG_N=2 -> hypercube size 4, truncated to 3 rows).
// Expected: M^T . eq_alpha = [-2, 4, -9, -4] (4 elements, columns 0..3).
global A_TEST_TRIPLES: [SparseTriple; 5] = [
    SparseTriple { row: 0, col: 0, val: 1 },
    SparseTriple { row: 0, col: 1, val: 2 },
    SparseTriple { row: 1, col: 2, val: 3 },
    SparseTriple { row: 2, col: 0, val: 1 },
    SparseTriple { row: 2, col: 3, val: 1 },
];
// Values computed by hand: A^T . eq([2,3], [(0,0), (0,1), (1,0)]) on the test matrix.
//   col 0 = 1*2 + 1*(-4) = -2
//   col 1 = 2*2          =  4
//   col 2 = 3*(-3)       = -9
//   col 3 = 1*(-4)       = -4
// Frozen as a KAT; see provekit/verifier-noir-test/tests/matrix_eval_kat.rs
// for the cross-impl guarantee.
global EXPECTED_A_AT_ALPHA: [Field; 4] = [
    21888242871839275222246405745257275088548364400416034343698204186575808495615,
    4,
    21888242871839275222246405745257275088548364400416034343698204186575808495608,
    21888242871839275222246405745257275088548364400416034343698204186575808495613,
];

#[test]
fn matrix_eval_a_at_alpha_matches_frozen_kat() {
    let alpha: [Field; 2] = [2, 3];
    let eq4 = eq_hypercube_evals::<2, 4>(alpha, 3);
    // truncate to 3 (entry 3 is the "vertex (1,1)" which is unused for this 3-row test).
    let eq3: [Field; 3] = [eq4[0], eq4[1], eq4[2]];

    let result = multiply_matrix_by_eq::<5, 3, 4>(A_TEST_TRIPLES, eq3);
    assert(result == EXPECTED_A_AT_ALPHA);
}
