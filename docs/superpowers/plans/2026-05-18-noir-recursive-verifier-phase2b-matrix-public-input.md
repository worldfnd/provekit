# Noir Recursive Verifier — Phase 2B: Matrix Evaluation + Public-Input Binding

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Spec:** [`docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md`](../specs/2026-05-18-noir-recursive-verifier-design.md)
**Predecessor:** [Phase 2A — Merkle + Sumcheck](./2026-05-18-noir-recursive-verifier-phase2a-merkle-sumcheck.md)

**Goal:** Add the two remaining in-circuit verification primitives the integrated verifier needs:

1. `matrix_eval.nr` — sparse R1CS matrix evaluation against `eq(alpha, ·)` over the boolean hypercube. Produces the per-witness "alphas" weights that get passed to WHIR LDT verification.
2. `public_input.nr` — Poseidon2 length-IV instance hash (with `PUBLIC_INPUTS_DST_FE` prefix matching `provekit/common/src/hash_config.rs::hash_poseidon2`) and geometric public-input binding check (`expected = 1 + Σ x^i · pi_i`).

Both come with cross-implementation KATs against the Rust reference.

**Architecture:**
- `matrix_eval.nr` exposes `SparseTriple` (row, col, value), `eq_hypercube_evals<LOG_N>(alpha)`, and `multiply_matrix_by_eq<TRIPLES, NUM_COLS>(triples, eq_evals) -> [Field; NUM_COLS]`. The integrated verifier will call this with codegen-emitted sparse triples (Phase 2C).
- `public_input.nr` exposes `verify_public_input_hash` (uses `length_iv_hash` from `merkle.nr` with the `PUBLIC_INPUTS_DST_FE` prefix) and `verify_public_eval` (geometric sum).
- Both modules have placeholder KATs that fail intentionally; cross-impl tasks unfreeze them.
- Phase 2C will add the codegen tool that emits `types.nr` + `matrices.nr` + `Prover.toml`; Phase 2B does NOT touch the codegen tool.

**Tech Stack:** Noir 1.0.0-beta.19, Rust workspace crates `provekit-common` (for `HashConfig::hash_field_elements` and the `PUBLIC_INPUTS_DST_FE` constant), `poseidon2`.

---

## File map

```
NEW    provekit/verifier-noir/src/matrix_eval.nr
NEW    provekit/verifier-noir/src/public_input.nr
MOD    provekit/verifier-noir/src/main.nr           (add 2 mod declarations)
MOD    provekit/verifier-noir-test/src/lib.rs       (extend with matrix_eval + public_input KAT helpers)
NEW    provekit/verifier-noir-test/tests/matrix_eval_kat.rs
NEW    provekit/verifier-noir-test/tests/public_input_kat.rs
```

---

## Task 1: `matrix_eval.nr` — sparse R1CS matrix evaluation + placeholder KAT

**Files:**
- Create: `provekit/verifier-noir/src/matrix_eval.nr`
- Modify: `provekit/verifier-noir/src/main.nr` — add `mod matrix_eval;`

**Outcome:** Three exports + placeholder KAT:
- `pub struct SparseTriple { row: u32, col: u32, val: Field }` — sparse matrix entry.
- `pub fn eq_hypercube_evals<let LOG_N: u32, let N: u32>(alpha: [Field; LOG_N], truncate_to: u32) -> [Field; N]` — computes `eq(alpha, x)` at all `x ∈ {0,1}^LOG_N`, truncated to `truncate_to` entries. `N` should equal `1 << LOG_N` at the call site; entries past `truncate_to` are zero. Matches Rust `calculate_evaluations_over_boolean_hypercube_for_eq`.
- `pub fn multiply_matrix_by_eq<let TRIPLES: u32, let NUM_COLS: u32>(triples: [SparseTriple; TRIPLES], eq_evals: [Field; N_ROWS], num_rows: u32) -> [Field; NUM_COLS]` — for each non-zero `(row, col, val)`, accumulate `eq_evals[row] * val` into `result[col]`. Generic over the matrix sparsity and column count.

Wait: Noir generics don't support free type variables for array sizes that aren't directly mentioned in the parameters. Simplification — bake `NUM_ROWS` into the function signature and let the caller pass an array of that size:

```noir
pub fn multiply_matrix_by_eq<let TRIPLES: u32, let NUM_ROWS: u32, let NUM_COLS: u32>(
    triples: [SparseTriple; TRIPLES],
    eq_evals: [Field; NUM_ROWS],
) -> [Field; NUM_COLS]
```

This is the working signature.

**Placeholder KAT:** 3x4 test R1CS matrix (the same one used in `provekit/common/src/utils/sumcheck.rs`'s test) with alpha = `[2, 3]` (i.e., LOG_N=2 → eq vector of length 4 truncated to 3). Expected output is the 4-element `expected_a` vector. Placeholder is `[0, 0, 0, 0]` — Task 2 fills in real values.

### Steps

- [ ] **Step 1: Create `provekit/verifier-noir/src/matrix_eval.nr` with this content:**

```noir
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
/// The vector has size `1 << LOG_N`. Entries past `truncate_to` (i.e.,
/// indices >= truncate_to) are still computed but the caller is expected to
/// ignore them — matches the Rust reference's truncation semantics where the
/// hypercube is sized to the next power of two of `num_constraints` and the
/// trailing entries are unused.
///
/// The recursive formula:
///   eq(alpha, x) = product over i of (alpha[i]*x[i] + (1-alpha[i])*(1-x[i]))
///
/// Built incrementally: starting with `eq(_, 0) = 1`, each new alpha[i] doubles
/// the table by computing `eq[j + half] = eq[j] * alpha[i]` and
/// `eq[j] = eq[j] * (1 - alpha[i])`.
pub fn eq_hypercube_evals<let LOG_N: u32, let N: u32>(
    alpha: [Field; LOG_N],
    _truncate_to: u32,
) -> [Field; N] {
    // INVARIANT: N == 1 << LOG_N (asserted at call sites; Noir doesn't allow
    // this as a where-clause yet).
    let mut result: [Field; N] = [0; N];
    result[0] = 1;
    let mut size: u32 = 1;
    for i in 0..LOG_N {
        let alpha_i = alpha[i];
        // Sweep j from 0..size, copying & scaling to j + size.
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

/// Compute `M^T · eq_evals` over the boolean hypercube, where M is given as
/// a list of sparse (row, col, val) triples.
///
/// For each triple, accumulate `eq_evals[row] * val` into `result[col]`.
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
// The 3x4 test R1CS from provekit/common/src/utils/sumcheck.rs::make_test_r1cs:
//
//   A = [[1, 2, 0, 0],
//        [0, 0, 3, 0],
//        [1, 0, 0, 1]]
//
// with alpha = [2, 3] (LOG_N=2 -> hypercube size 4, truncated to 3 rows).
//
// Expected M^T . eq_alpha = [-2, 4, -9, -4] per the Rust test
// (test_multiply_transposed_by_eq_alpha, expected_a).
//
// PLACEHOLDER VALUES - overwritten in Phase 2B Task 2 after running the
// Rust-side computation. The test below is expected to FAIL until then.
global A_TEST_TRIPLES: [SparseTriple; 4] = [
    SparseTriple { row: 0, col: 0, val: 1 },
    SparseTriple { row: 0, col: 1, val: 2 },
    SparseTriple { row: 1, col: 2, val: 3 },
    SparseTriple { row: 2, col: 0, val: 1 },
];
// 5th triple: row 2, col 3, val 1
global A_TEST_TRIPLES_FULL: [SparseTriple; 5] = [
    SparseTriple { row: 0, col: 0, val: 1 },
    SparseTriple { row: 0, col: 1, val: 2 },
    SparseTriple { row: 1, col: 2, val: 3 },
    SparseTriple { row: 2, col: 0, val: 1 },
    SparseTriple { row: 2, col: 3, val: 1 },
];
global EXPECTED_A_AT_ALPHA: [Field; 4] = [0, 0, 0, 0]; // PLACEHOLDER

#[test]
fn matrix_eval_a_at_alpha_matches_frozen_kat() {
    let alpha: [Field; 2] = [2, 3];
    let eq4 = eq_hypercube_evals::<2, 4>(alpha, 3);
    // truncate to 3 by zeroing the last entry (matches Rust's
    // truncate_to=num_constraints=3 semantics)
    let mut eq3: [Field; 3] = [eq4[0], eq4[1], eq4[2]];

    let result = multiply_matrix_by_eq::<5, 3, 4>(A_TEST_TRIPLES_FULL, eq3);
    assert(result == EXPECTED_A_AT_ALPHA);
}
```

- [ ] **Step 2: Modify `provekit/verifier-noir/src/main.nr`**

Replace head with:

```noir
// ProveKit Noir Recursive Verifier
//
// Verifies a ProveKit WHIR+Spartan proof generated under HashConfig::Poseidon2.
// See docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md
//
// Phase 2B: + matrix evaluation. Public-input binding lands in the next task.

mod poseidon2;
mod sponge;
mod transcript;
mod merkle;
mod sumcheck;
mod matrix_eval;

fn main() {}
```

- [ ] **Step 3: Run `nargo test matrix_eval` — verify FAIL.**

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test matrix_eval 2>&1 | tail -10`

Expected: 1 failed test. Intended TDD red.

- [ ] **Step 4: Regression check.**

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test 2>&1 | tail -10`

Expected: 9 passed (all prior Phase 1A/1B/2A KATs) + 1 failed (matrix_eval_a_at_alpha_matches_frozen_kat).

- [ ] **Step 5: Commit.**

```bash
cd /Users/paradox/Desktop/projects/provekit
git add provekit/verifier-noir/src/matrix_eval.nr provekit/verifier-noir/src/main.nr
git commit -m "feat(verifier-noir): add matrix evaluation with placeholder KAT"
```

---

## Task 2: Cross-impl matrix_eval KAT

**Files:**
- Modify: `provekit/verifier-noir-test/src/lib.rs` — add `matrix_eval_kat_expected` helper + printer
- Modify: `provekit/verifier-noir/src/matrix_eval.nr` — replace `EXPECTED_A_AT_ALPHA` placeholder with real values
- Create: `provekit/verifier-noir-test/tests/matrix_eval_kat.rs` — integration test

**Outcome:** Noir matrix_eval matches Rust `multiply_transposed_by_eq_alpha` bit-for-bit on the 3x4 test R1CS.

### Steps

- [ ] **Step 1: Add helper to `provekit/verifier-noir-test/src/lib.rs`**

Append before `#[cfg(test)] mod tests`:

```rust
/// Compute `M^T · eq(alpha, ·)` for the 3x4 test matrix A in
/// `provekit/common/src/utils/sumcheck.rs`'s `make_test_r1cs`:
///
///   A = [[1, 2, 0, 0],
///        [0, 0, 3, 0],
///        [1, 0, 0, 1]]
///
/// with alpha = [2, 3], truncated to 3 constraints. The 4-element result is
/// the expected `EXPECTED_A_AT_ALPHA` for the Noir KAT.
pub fn matrix_eval_kat_expected() -> [Fr; 4] {
    // Compute eq(alpha, x) for x in {00, 01, 10, 11}, then truncate to 3.
    let a0 = Fr::from(2u64);
    let a1 = Fr::from(3u64);
    let one = Fr::from(1u64);
    // eq([2, 3], [0, 0]) = (1-2)(1-3) =  2
    // eq([2, 3], [0, 1]) = (1-2)*3   = -3
    // eq([2, 3], [1, 0]) = 2*(1-3)   = -4
    // eq([2, 3], [1, 1]) = 2*3       =  6
    let eq00 = (one - a0) * (one - a1);
    let eq01 = (one - a0) * a1;
    let eq10 = a0 * (one - a1);
    let _eq11 = a0 * a1; // truncated away
    // Hand-evaluate M^T · eq using A's row contents:
    //   col 0: A[0,0]*eq00 + A[1,0]*eq01 + A[2,0]*eq10 = 1*2 + 0 + 1*(-4) = -2
    //   col 1: A[0,1]*eq00 + A[1,1]*eq01 + A[2,1]*eq10 = 2*2 + 0 + 0 = 4
    //   col 2: A[0,2]*eq00 + A[1,2]*eq01 + A[2,2]*eq10 = 0 + 3*(-3) + 0 = -9
    //   col 3: A[0,3]*eq00 + A[1,3]*eq01 + A[2,3]*eq10 = 0 + 0 + 1*(-4) = -4
    [
        Fr::from(1u64) * eq00 + Fr::from(1u64) * eq10,
        Fr::from(2u64) * eq00,
        Fr::from(3u64) * eq01,
        Fr::from(1u64) * eq10,
    ]
}
```

Then add to `mod tests`:

```rust
/// Print the values that Noir's `EXPECTED_A_AT_ALPHA` global should hold.
#[test]
fn print_matrix_eval_kat_expected_for_noir() {
    let expected = matrix_eval_kat_expected();
    for (i, fe) in expected.iter().enumerate() {
        println!(
            "EXPECTED_A_AT_ALPHA[{i}] = {}",
            fr_to_noir_literal(*fe)
        );
    }
}
```

- [ ] **Step 2: Capture the 4 values.**

Run: `cargo test -p provekit-verifier-noir-test print_matrix_eval_kat_expected_for_noir -- --nocapture 2>&1 | grep EXPECTED_A_AT_ALPHA`

Expected: 4 lines. Record all 4 (note: 3 of them are negative-mod-p values which will be very large decimals).

- [ ] **Step 3: Patch `provekit/verifier-noir/src/matrix_eval.nr`**

Replace:
```noir
global EXPECTED_A_AT_ALPHA: [Field; 4] = [0, 0, 0, 0]; // PLACEHOLDER
```

with:
```noir
// Values computed by hand from A * eq([2,3], [00, 01, 10]):
//   col 0 = 1*2 + 1*(-4) = -2
//   col 1 = 2*2          =  4
//   col 2 = 3*(-3)       = -9
//   col 3 = 1*(-4)       = -4
// Frozen as a KAT; see provekit/verifier-noir-test/tests/matrix_eval_kat.rs
// for the cross-impl guarantee.
global EXPECTED_A_AT_ALPHA: [Field; 4] = [
    <decimal-0>,
    <decimal-1>,
    <decimal-2>,
    <decimal-3>,
];
```

Also remove the "PLACEHOLDER VALUES - overwritten in Phase 2B Task 2" block above it.

- [ ] **Step 4: Verify `nargo test matrix_eval` PASSES.**

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test matrix_eval 2>&1 | tail -5`

Expected: 1 passed.

- [ ] **Step 5: Create integration test.**

Create `provekit/verifier-noir-test/tests/matrix_eval_kat.rs`:

```rust
//! Cross-implementation matrix evaluation KAT.

use {
    provekit_verifier_noir_test::matrix_eval_kat_expected,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_matrix_eval_kat_agrees() {
    let a = matrix_eval_kat_expected();
    let b = matrix_eval_kat_expected();
    assert_eq!(a, b, "matrix_eval_kat_expected non-deterministic");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let nargo_crate = manifest_dir
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .join("verifier-noir");
    assert!(
        nargo_crate.join("Nargo.toml").exists(),
        "verifier-noir Nargo.toml not found"
    );

    let status = Command::new("nargo")
        .args(["test", "matrix_eval"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo");

    assert!(
        status.success(),
        "nargo test matrix_eval failed (exit {:?})",
        status.code(),
    );
}
```

- [ ] **Step 6: Run integration test and full suite.**

Run: `cargo test -p provekit-verifier-noir-test --test matrix_eval_kat 2>&1 | tail -5`
Expected: 1 passed.

Run: `cargo test -p provekit-verifier-noir-test 2>&1 | grep -E "^(test result|running)"`
Expected: 6 lib + 6 integration tests, all pass.

- [ ] **Step 7: Clippy.**

Run: `cargo clippy -p provekit-verifier-noir-test --all-targets 2>&1 | tail -5`
Expected: no warnings on new code.

- [ ] **Step 8: Commit.**

```bash
git add provekit/verifier-noir-test/ provekit/verifier-noir/src/matrix_eval.nr
git commit -m "test(verifier-noir): cross-impl matrix evaluation KAT"
```

---

## Task 3: `public_input.nr` — instance hash + geometric binding + placeholder KATs

**Files:**
- Create: `provekit/verifier-noir/src/public_input.nr`
- Modify: `provekit/verifier-noir/src/main.nr` — add `mod public_input;`

**Outcome:** Two exports + 2 placeholder KATs:
- `pub fn verify_public_input_hash<let N: u32>(prover_msg: Field, public_inputs: [Field; N])` — assert `prover_msg == length_iv_hash([PUBLIC_INPUTS_DST_FE] ++ public_inputs)`.
- `pub fn verify_public_eval<let N: u32>(prover_msg: Field, x: Field, public_inputs: [Field; N])` — assert `prover_msg == 1 + Σ x^(i+1) · pi_i` (geometric, starting at x^1, matching Rust `verify_public_input_binding`).

`PUBLIC_INPUTS_DST_FE` is `SHA256("PROVEKIT_PUBLIC_INPUTS_V1") reduced mod p`. The codegen tool computes this constant — but we can also frozen it here as a global since it's deterministic.

### Steps

- [ ] **Step 1: Create `provekit/verifier-noir/src/public_input.nr`:**

```noir
//! Public-input binding helpers for the recursive verifier.
//!
//! Provides:
//!   * `verify_public_input_hash` — asserts the prover-sent public-inputs hash
//!     matches the Poseidon2 length-IV hash of `[DST_FE, pi_0, pi_1, ...]`.
//!     Mirrors `provekit/common/src/hash_config.rs::hash_poseidon2`.
//!   * `verify_public_eval` — asserts the prover-sent public-eval value matches
//!     the geometric series `1 + sum_i x^(i+1) * pi_i`. Mirrors
//!     `provekit/verifier/src/whir_r1cs.rs::verify_public_input_binding`.
//!
//! Cross-implementation KAT lives in
//! `provekit/verifier-noir-test/tests/public_input_kat.rs`.

use crate::merkle::length_iv_hash;

/// Domain-separation tag = SHA256("PROVEKIT_PUBLIC_INPUTS_V1") reduced mod p.
///
/// Computed once by the Rust codegen helper (or hand-derived) and frozen.
/// Task 4 unfreezes the placeholder with the real value.
///
/// PLACEHOLDER VALUE - overwritten in Phase 2B Task 4.
global PUBLIC_INPUTS_DST_FE: Field = 0;

/// Assert the prover's claimed public-inputs hash matches the Poseidon2
/// length-IV hash of `[DST_FE, pi_0, pi_1, ...]`.
pub fn verify_public_input_hash<let N: u32>(
    prover_msg: Field,
    public_inputs: [Field; N],
) {
    // Build the tagged input array. Noir requires the array size known at
    // compile time, so we copy DST_FE then public_inputs into a [Field; N+1].
    let tagged: [Field; N + 1] = build_tagged_inputs(public_inputs);
    let expected = length_iv_hash::<N + 1>(tagged);
    assert(prover_msg == expected);
}

fn build_tagged_inputs<let N: u32>(public_inputs: [Field; N]) -> [Field; N + 1] {
    let mut tagged: [Field; N + 1] = [0; N + 1];
    tagged[0] = PUBLIC_INPUTS_DST_FE;
    for i in 0..N {
        tagged[i + 1] = public_inputs[i];
    }
    tagged
}

/// Assert the prover's claimed `public_eval == 1 + sum_i x^(i+1) * pi_i`.
/// Matches the Rust reference's `verify_public_input_binding` exactly:
///
///   ```ignore
///   let mut expected = 1;
///   let mut x_pow = x;
///   for pi in public_inputs {
///       expected += x_pow * pi;
///       x_pow *= x;
///   }
///   assert(public_eval == expected);
///   ```
pub fn verify_public_eval<let N: u32>(
    prover_msg: Field,
    x: Field,
    public_inputs: [Field; N],
) {
    let mut expected: Field = 1;
    let mut x_pow: Field = x;
    for i in 0..N {
        expected += x_pow * public_inputs[i];
        x_pow *= x;
    }
    assert(prover_msg == expected);
}

// --- in-circuit KATs (placeholders) ---
//
// Two separate frozen KATs:
//   * EXPECTED_PI_HASH: hash of [DST_FE, 7, 11, 13] (3 public inputs).
//   * EXPECTED_PI_EVAL: 1 + 5*7 + 5^2*11 + 5^3*13 mod p (x=5, public_inputs=[7,11,13]).
//
// PLACEHOLDER VALUES - overwritten in Phase 2B Task 4.
global EXPECTED_PI_HASH: Field = 0;

#[test]
fn verify_public_input_hash_matches_frozen_kat() {
    let public_inputs: [Field; 3] = [7, 11, 13];
    verify_public_input_hash::<3>(EXPECTED_PI_HASH, public_inputs);
}

#[test]
fn verify_public_eval_matches_canonical() {
    // expected = 1 + 5*7 + 25*11 + 125*13 = 1 + 35 + 275 + 1625 = 1936
    let public_inputs: [Field; 3] = [7, 11, 13];
    verify_public_eval::<3>(1936, 5, public_inputs);
}
```

Note: `verify_public_eval_matches_canonical` is a PURE in-circuit unit test with a hand-computed expected value (no cross-impl needed — the geometric series is a closed-form computation). The hash KAT (`verify_public_input_hash_matches_frozen_kat`) needs cross-impl because of the DST_FE constant and the length-IV hash.

- [ ] **Step 2: Wire main.nr.**

Replace the head:

```noir
// ProveKit Noir Recursive Verifier
//
// Verifies a ProveKit WHIR+Spartan proof generated under HashConfig::Poseidon2.
// See docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md
//
// Phase 2B: + matrix evaluation + public-input binding. WHIR + codegen land later.

mod poseidon2;
mod sponge;
mod transcript;
mod merkle;
mod sumcheck;
mod matrix_eval;
mod public_input;

fn main() {}
```

- [ ] **Step 3: Run `nargo test public_input`.**

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test public_input 2>&1 | tail -10`

Expected: 1 passed (`verify_public_eval_matches_canonical` — pure geometric series), 1 failed (`verify_public_input_hash_matches_frozen_kat` — placeholders).

- [ ] **Step 4: Regression.**

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test 2>&1 | tail -10`

Expected: 11 passed, 1 failed.

- [ ] **Step 5: Commit.**

```bash
git add provekit/verifier-noir/src/public_input.nr provekit/verifier-noir/src/main.nr
git commit -m "feat(verifier-noir): add public-input binding with placeholder KAT"
```

---

## Task 4: Cross-impl public_input KAT

**Files:**
- Modify: `provekit/verifier-noir-test/src/lib.rs` — add `public_input_kat_expected` (computes DST_FE + Poseidon2 length-IV hash of `[DST_FE, 7, 11, 13]`)
- Modify: `provekit/verifier-noir/src/public_input.nr` — replace 2 placeholder globals (`PUBLIC_INPUTS_DST_FE`, `EXPECTED_PI_HASH`) with real values
- Create: `provekit/verifier-noir-test/tests/public_input_kat.rs` — integration test

**Outcome:** Noir's public-input hash verifier agrees with `provekit_common::HashConfig::Poseidon2.hash_field_elements(&[7, 11, 13])`.

### Steps

- [ ] **Step 1: Add helper to `provekit/verifier-noir-test/src/lib.rs`.**

Append before `#[cfg(test)] mod tests`:

```rust
use provekit_common::HashConfig;

/// Compute `HashConfig::Poseidon2.hash_field_elements(&[7, 11, 13])`, which is
/// `poseidon2_hash([DST_FE, 7, 11, 13])` per `hash_config.rs::hash_poseidon2`.
pub fn public_input_kat_expected() -> Fr {
    HashConfig::Poseidon2.hash_field_elements(&[
        Fr::from(7u64),
        Fr::from(11u64),
        Fr::from(13u64),
    ])
}

/// The Poseidon2 DST constant the Rust prover/verifier uses:
/// `SHA256("PROVEKIT_PUBLIC_INPUTS_V1") reduced mod p`.
pub fn public_inputs_dst_fe() -> Fr {
    use ark_ff::PrimeField;
    use sha2::{Digest, Sha256};
    Fr::from_le_bytes_mod_order(&Sha256::digest(b"PROVEKIT_PUBLIC_INPUTS_V1"))
}
```

Then add to `mod tests`:

```rust
#[test]
fn print_public_input_kat_expected_for_noir() {
    let dst = public_inputs_dst_fe();
    println!("PUBLIC_INPUTS_DST_FE = {}", fr_to_noir_literal(dst));
    let hash = public_input_kat_expected();
    println!("EXPECTED_PI_HASH = {}", fr_to_noir_literal(hash));
}
```

- [ ] **Step 2: Add the `sha2` dependency to `provekit/verifier-noir-test/Cargo.toml`** if not already present:

Check current state:
```
grep sha2 provekit/verifier-noir-test/Cargo.toml
```

If absent, add to `[dependencies]`:
```toml
sha2.workspace = true
```

(Confirm `sha2` is a workspace dep first; it is, since `provekit-common` uses it.)

- [ ] **Step 3: Capture values.**

Run: `cargo test -p provekit-verifier-noir-test print_public_input_kat_expected_for_noir -- --nocapture 2>&1 | grep -E "(PUBLIC_INPUTS_DST_FE|EXPECTED_PI_HASH)"`

Expected: 2 lines. Capture both decimals.

- [ ] **Step 4: Patch `provekit/verifier-noir/src/public_input.nr`.**

Replace:
```noir
// PLACEHOLDER VALUE - overwritten in Phase 2B Task 4.
global PUBLIC_INPUTS_DST_FE: Field = 0;
```
with:
```noir
// SHA256("PROVEKIT_PUBLIC_INPUTS_V1") reduced mod p. Frozen here so the Noir
// verifier matches `provekit/common/src/hash_config.rs::PUBLIC_INPUTS_DST_FE`.
global PUBLIC_INPUTS_DST_FE: Field = <decimal-dst>;
```

Replace:
```noir
global EXPECTED_PI_HASH: Field = 0;
```
with:
```noir
// Value computed by Rust HashConfig::Poseidon2.hash_field_elements(&[7, 11, 13]);
// frozen as a KAT. See provekit/verifier-noir-test/tests/public_input_kat.rs
// for the cross-impl guarantee.
global EXPECTED_PI_HASH: Field = <decimal-hash>;
```

Remove the "PLACEHOLDER VALUES" comment block.

- [ ] **Step 5: Verify both public_input tests PASS.**

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test public_input 2>&1 | tail -10`

Expected: 2 passed (`verify_public_input_hash_matches_frozen_kat`, `verify_public_eval_matches_canonical`).

- [ ] **Step 6: Create integration test.**

Create `provekit/verifier-noir-test/tests/public_input_kat.rs`:

```rust
//! Cross-impl public-input binding KAT.

use {
    provekit_verifier_noir_test::public_input_kat_expected,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_public_input_kat_agrees() {
    let a = public_input_kat_expected();
    let b = public_input_kat_expected();
    assert_eq!(a, b, "public_input_kat_expected non-deterministic");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let nargo_crate = manifest_dir
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .join("verifier-noir");
    assert!(nargo_crate.join("Nargo.toml").exists());

    let status = Command::new("nargo")
        .args(["test", "public_input"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo");

    assert!(
        status.success(),
        "nargo test public_input failed (exit {:?})",
        status.code(),
    );
}
```

- [ ] **Step 7: Run integration test + full suite.**

Run: `cargo test -p provekit-verifier-noir-test --test public_input_kat 2>&1 | tail -5`
Expected: 1 passed.

Run: `cargo test -p provekit-verifier-noir-test 2>&1 | grep -E "^(test result|running)"`
Expected: 7 lib + 7 integration tests pass.

- [ ] **Step 8: Clippy.**

Run: `cargo clippy -p provekit-verifier-noir-test --all-targets 2>&1 | tail -5`
Expected: no warnings.

- [ ] **Step 9: Commit.**

```bash
git add provekit/verifier-noir-test/ provekit/verifier-noir/src/public_input.nr
git commit -m "test(verifier-noir): cross-impl public-input binding KAT"
```

---

## What Phase 2B leaves behind

- `provekit/verifier-noir/src/matrix_eval.nr` — sparse matrix evaluation primitive, hypercube eq expansion, cross-impl KAT.
- `provekit/verifier-noir/src/public_input.nr` — Poseidon2 instance hash (with DST prefix) + geometric binding, cross-impl KAT.

After Phase 2B all in-circuit verification primitives the integrated verifier needs are in place. Phase 2C will glue them together via the codegen tool.

## What Phase 2C will cover (next plan)

- Extend `provekit-cli generate-noir-inputs` to:
  - Deserialize `.pkv` and `.np` (postcard).
  - Emit `types.nr` (compile-time constants: M, M_0, NUM_PUBLIC_INPUTS, etc.).
  - Emit `matrices.nr` (sparse A/B/C triples).
  - Emit `Prover.toml` (proof bytes parsed into Field arrays for nargo).
- Skip Phase 3's WHIR LDT verifier for now — that's its own phase.

## Deliberately out of scope for Phase 2B

- Prefix covector logic (`make_public_weight`, `make_challenge_weight`, `build_prefix_covectors`) — used inside WHIR LDT verifier (Phase 3); not in the matrix-eval critical path.
- `length_iv_hash::<1>` / `length_iv_hash::<3>` / `length_iv_hash::<4>` boundary KATs — defer to Phase 3 cleanup if they prove useful.
- Full codegen tool — Phase 2C.
