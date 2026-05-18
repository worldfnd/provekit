# Noir Recursive Verifier — Phase 2A: Merkle Hash + Sumcheck

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** [`docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md`](../specs/2026-05-18-noir-recursive-verifier-design.md)
**Predecessor:** [Phase 1B — Sponge + Transcript](./2026-05-18-noir-recursive-verifier-phase1b-sponge-transcript.md)

**Goal:** Add the in-circuit Poseidon2 length-IV one-shot hash (`merkle.nr`) used by WHIR's Merkle commitments, plus the Spartan sumcheck verifier (`sumcheck.nr`). Both come with cross-implementation KATs against the Rust reference.

**Architecture:**
- `merkle.nr` exposes `length_iv_hash<let N: u32>(inputs: [Field; N]) -> Field` matching `poseidon2::hash::poseidon2_hash`. The hash is a SEPARATE construction from the duplex sponge: cache `RATE=3` inputs, ADD (not overwrite) into the rate region of state initialized with `IV = N * 2^64` in `state[3]`, permute on overflow, ADD remaining cache and final permute, return `state[0]`.
- `sumcheck.nr` exposes pure `eval_cubic_poly`/`calculate_eq` helpers plus `run_sumcheck_verifier(transcript, sum_g, h_polys, blinding_eval) -> SumcheckResult` that mirrors `provekit/verifier/src/whir_r1cs.rs::run_sumcheck_verifier`.
- Both modules have placeholder KATs (Phase 1A/1B pattern) that fail intentionally until the cross-impl tasks paste in real values.

**Tech Stack:** Noir 1.0.0-beta.19 (`std::hash::poseidon2_permutation`, generics via `let N: u32`), Rust workspace crates `poseidon2::hash::poseidon2_hash` + custom Rust sumcheck transcript replay (no spongefish API for setting arbitrary state, so we replay both prover and verifier in Rust).

---

## Why a separate hash function for Merkle (vs the duplex sponge)?

`poseidon2_hash` (one-shot, used by Merkle) and `Poseidon2Sponge` (duplex, used by Fiat-Shamir) are **different constructions**:

| Construct | Init state | Absorption | When permutes |
|---|---|---|---|
| `Poseidon2Sponge` (duplex) | `[0; 4]` | **Overwrite** rate lane: `state[i] = input` | When `absorb_pos == RATE`, before write; on first squeeze |
| `poseidon2_hash` (one-shot) | `state[3] = N · 2^64` | **Add** into rate lane: `state[i] += cache[i]` | After cache fills RATE; final permute after all inputs |

The Noir stdlib's `Poseidon2::hash(inputs, len)` matches `poseidon2_hash`, not the duplex sponge. WHIR's Merkle engine uses `poseidon2_hash_bytes` which is the byte-encoded one-shot variant. So `merkle.nr`'s length-IV hash is a **new** primitive distinct from `sponge.nr`.

---

## File map

```
NEW    provekit/verifier-noir/src/merkle.nr
NEW    provekit/verifier-noir/src/sumcheck.nr
MOD    provekit/verifier-noir/src/main.nr           (add 2 mod declarations)
MOD    provekit/verifier-noir-test/src/lib.rs       (extend with merkle + sumcheck KAT helpers)
NEW    provekit/verifier-noir-test/tests/merkle_kat.rs
NEW    provekit/verifier-noir-test/tests/sumcheck_kat.rs
```

---

## Task 1: `merkle.nr` — Poseidon2 length-IV hash + placeholder KAT

**Files:**
- Create: `provekit/verifier-noir/src/merkle.nr`
- Modify: `provekit/verifier-noir/src/main.nr` — add `mod merkle;`

**Outcome:** A `length_iv_hash<let N: u32>(inputs: [Field; N]) -> Field` function mirroring `poseidon2::hash::poseidon2_hash`. Placeholder KAT for `N=2` fails intentionally; Task 2 unfreezes.

### Steps

- [ ] **Step 1: Create `provekit/verifier-noir/src/merkle.nr` with this content:**

```noir
//! Poseidon2 length-IV one-shot hash used by WHIR's Merkle tree.
//!
//! Distinct from the duplex sponge in `sponge.nr`:
//!   * state[3] is initialized to `N * 2^64` (length-domain-separation IV)
//!   * inputs are ADDED (not overwritten) into rate lanes
//!   * a final permute fires after the last absorbed input
//!
//! Mirrors `poseidon2::hash::poseidon2_hash` from the workspace `poseidon2`
//! crate, which itself matches Noir stdlib's `Poseidon2::hash(inputs, len)`.
//!
//! Cross-implementation KAT lives in
//! `provekit/verifier-noir-test/tests/merkle_kat.rs`.

use crate::poseidon2::permute;

global HASH_RATE: u32 = 3;

/// `2^64` as a Field constant. Used as a multiplier on the message length to
/// derive the capacity-lane IV.
global TWO_POW_64: Field = 0x10000000000000000;

/// One-shot Poseidon2 hash with length-domain-separation in the capacity lane.
///
/// `IV = N * 2^64` is placed in `state[3]`. Inputs are absorbed in chunks of
/// `HASH_RATE = 3`, ADDED into the rate lanes (state[0..3]). Permute fires
/// when the chunk fills RATE; the final partial chunk is ADDed and a final
/// permute runs unconditionally. Output is `state[0]`.
pub fn length_iv_hash<let N: u32>(inputs: [Field; N]) -> Field {
    let iv = (N as Field) * TWO_POW_64;
    let mut state: [Field; 4] = [0, 0, 0, iv];
    let mut cache: [Field; 3] = [0, 0, 0];
    let mut cache_size: u32 = 0;

    for i in 0..N {
        if cache_size == HASH_RATE {
            // Cache full: ADD into state, permute, clear cache.
            state[0] += cache[0];
            state[1] += cache[1];
            state[2] += cache[2];
            cache = [0, 0, 0];
            cache_size = 0;
            state = permute(state);
        }
        cache[cache_size] = inputs[i];
        cache_size += 1;
    }

    // Final: ADD remaining cache lanes into state, permute, output state[0].
    // Unrolled to honor `cache_size`'s remaining value without per-lane branches.
    if cache_size > 0 {
        state[0] += cache[0];
    }
    if cache_size > 1 {
        state[1] += cache[1];
    }
    if cache_size > 2 {
        state[2] += cache[2];
    }
    state = permute(state);
    state[0]
}

// --- in-circuit KAT ---
//
// EXPECTED_HASH_2 freezes length_iv_hash([1, 2]) per the Rust
// `poseidon2::hash::poseidon2_hash` reference. Task 2 replaces this
// placeholder with the real value.
//
// PLACEHOLDER VALUE - overwritten in Phase 2A Task 2 after running the
// Rust-side computation. The test below is expected to FAIL until then.
global EXPECTED_HASH_2: Field = 0;

#[test]
fn length_iv_hash_2_matches_frozen_kat() {
    let out = length_iv_hash::<2>([1, 2]);
    assert(out == EXPECTED_HASH_2);
}
```

- [ ] **Step 2: Modify `provekit/verifier-noir/src/main.nr` to declare the module.**

Current content (after Phase 1B):

```noir
// ProveKit Noir Recursive Verifier
//
// Verifies a ProveKit WHIR+Spartan proof generated under HashConfig::Poseidon2.
// See docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md
//
// Phase 1B: + duplex sponge + transcript. Verification logic lands in later phases.

mod poseidon2;
mod sponge;
mod transcript;

fn main() {}
```

Replace with:

```noir
// ProveKit Noir Recursive Verifier
//
// Verifies a ProveKit WHIR+Spartan proof generated under HashConfig::Poseidon2.
// See docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md
//
// Phase 2A: + Poseidon2 length-IV hash. Sumcheck lands in the next task.

mod poseidon2;
mod sponge;
mod transcript;
mod merkle;

fn main() {}
```

- [ ] **Step 3: Run `nargo test length_iv_hash` and verify FAIL.**

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test length_iv_hash 2>&1 | tail -10`

Expected: 1 failed test. Placeholder `0` doesn't match real Poseidon2 hash output. Intended TDD red.

- [ ] **Step 4: Regression-check the existing tests.**

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test 2>&1 | tail -10`

Expected: 3 passed (poseidon2, sponge, transcript) + 1 failed (length_iv_hash). The 3 Phase 1A/1B KATs must still pass.

- [ ] **Step 5: Commit.**

```bash
cd /Users/paradox/Desktop/projects/provekit
git add provekit/verifier-noir/src/merkle.nr provekit/verifier-noir/src/main.nr
git commit -m "feat(verifier-noir): add Poseidon2 length-IV hash with placeholder KAT"
```

Conventional Commits. NO `Co-Authored-By: Claude` trailer.

---

## Task 2: Cross-impl merkle KAT — turn placeholder green

**Files:**
- Modify: `provekit/verifier-noir-test/src/lib.rs` — add `merkle_kat_expected()` helper + `print_merkle_kat_expected_for_noir` test
- Modify: `provekit/verifier-noir/src/merkle.nr` — replace placeholder `EXPECTED_HASH_2` with real value
- Create: `provekit/verifier-noir-test/tests/merkle_kat.rs` — integration test shells out to `nargo test length_iv_hash`

**Outcome:** Noir `length_iv_hash::<2>([1, 2])` matches Rust `poseidon2::hash::poseidon2_hash(&[Fr::from(1), Fr::from(2)])`. Cross-impl integration test passes.

### Steps

- [ ] **Step 1: Extend `provekit/verifier-noir-test/src/lib.rs` with the merkle KAT helper.**

Read the file first to confirm current state. Append (do NOT remove anything) BEFORE the `#[cfg(test)] mod tests` block:

```rust
/// Run the canonical merkle KAT (`length_iv_hash([1, 2])` in Noir terms)
/// through the Rust `poseidon2::hash::poseidon2_hash` reference.
pub fn merkle_kat_expected() -> Fr {
    poseidon2::hash::poseidon2_hash(&[Fr::from(1u64), Fr::from(2u64)])
}
```

Add to the `#[cfg(test)] mod tests` block (alongside existing `print_*_for_noir` tests):

```rust
/// Print the field element that Noir's `EXPECTED_HASH_2` global should hold.
#[test]
fn print_merkle_kat_expected_for_noir() {
    let expected = merkle_kat_expected();
    println!("EXPECTED_HASH_2 = {}", fr_to_noir_literal(expected));
}
```

- [ ] **Step 2: Capture the expected value.**

Run: `cargo test -p provekit-verifier-noir-test print_merkle_kat_expected_for_noir -- --nocapture 2>&1 | grep EXPECTED_HASH_2`

Expected: one line `EXPECTED_HASH_2 = <decimal>`. Capture it.

- [ ] **Step 3: Patch `provekit/verifier-noir/src/merkle.nr` with the real value.**

Replace the placeholder block. Current:

```noir
// PLACEHOLDER VALUE - overwritten in Phase 2A Task 2 after running the
// Rust-side computation. The test below is expected to FAIL until then.
global EXPECTED_HASH_2: Field = 0;
```

Replace with (substituting the captured decimal):

```noir
// Value computed by Rust `poseidon2::hash::poseidon2_hash` on `[1, 2]`;
// frozen as a KAT. See provekit/verifier-noir-test/tests/merkle_kat.rs
// for the cross-impl guarantee.
global EXPECTED_HASH_2: Field = <decimal-from-step-2>;
```

- [ ] **Step 4: Verify `nargo test length_iv_hash` now PASSES.**

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test length_iv_hash 2>&1 | tail -5`

Expected: 1 passed. If it fails, the decimal was captured/pasted wrongly — redo steps 2-3.

- [ ] **Step 5: Create the Cargo-side cross-impl integration test.**

Create `provekit/verifier-noir-test/tests/merkle_kat.rs`:

```rust
//! Cross-implementation Poseidon2 length-IV hash KAT.
//!
//! 1. Compute `poseidon2_hash([1, 2])` via the Rust `poseidon2` workspace crate.
//! 2. Shell out to `nargo test length_iv_hash` in the sibling Noir crate.
//!    That test asserts Noir's `length_iv_hash::<2>([1, 2])` matches the
//!    frozen `EXPECTED_HASH_2` global.
//! 3. Passing means both implementations agree on this KAT input.

use {
    provekit_verifier_noir_test::merkle_kat_expected,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_merkle_kat_agrees() {
    let a = merkle_kat_expected();
    let b = merkle_kat_expected();
    assert_eq!(a, b, "Rust poseidon2_hash is non-deterministic on the KAT");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let nargo_crate = manifest_dir
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .join("verifier-noir");
    assert!(
        nargo_crate.join("Nargo.toml").exists(),
        "verifier-noir Nargo.toml not found at {}",
        nargo_crate.display()
    );

    let status = Command::new("nargo")
        .args(["test", "length_iv_hash"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo - is it on PATH?");

    assert!(
        status.success(),
        "nargo test length_iv_hash failed (exit code {:?}). \
         The Noir length-IV hash disagreed with the Rust poseidon2_hash output \
         on input [1, 2]. Re-run Phase 2A Task 2 step 2 to regenerate the \
         expected value.",
        status.code(),
    );
}
```

- [ ] **Step 6: Run the cross-impl test.**

Run: `cargo test -p provekit-verifier-noir-test --test merkle_kat 2>&1 | tail -5`

Expected: 1 passed.

- [ ] **Step 7: Full regression check.**

Run: `cargo test -p provekit-verifier-noir-test 2>&1 | grep -E "^(test result|running)"`

Expected: All binaries pass — lib tests (4 printers now: kat, sponge_kat, transcript_kat, merkle_kat) + cross-impl tests (poseidon2, sponge, transcript, merkle = 4 integration tests).

- [ ] **Step 8: Clippy check.**

Run: `cargo clippy -p provekit-verifier-noir-test --all-targets 2>&1 | tail -10`

Expected: no warnings on new code.

- [ ] **Step 9: Commit.**

```bash
cd /Users/paradox/Desktop/projects/provekit
git add provekit/verifier-noir-test/ provekit/verifier-noir/src/merkle.nr
git commit -m "test(verifier-noir): cross-impl Poseidon2 length-IV hash KAT"
```

Conventional Commits. NO Claude trailer.

---

## Task 3: `sumcheck.nr` — Spartan sumcheck verifier + placeholder KATs

**Files:**
- Create: `provekit/verifier-noir/src/sumcheck.nr`
- Modify: `provekit/verifier-noir/src/main.nr` — add `mod sumcheck;`

**Outcome:** Three exports:
- `pub fn eval_cubic_poly(poly: [Field; 4], point: Field) -> Field` — Horner's method.
- `pub fn calculate_eq<let N: u32>(r: [Field; N], alpha: [Field; N]) -> Field` — product over `r[i]·α[i] + (1-r[i])·(1-α[i])`.
- `pub fn run_sumcheck_verifier<let M0: u32>(transcript, sum_g, h_polys, blinding_eval) -> SumcheckResult<M0>` — mirrors `provekit/verifier/src/whir_r1cs.rs::run_sumcheck_verifier`.

Plus two placeholder KATs:
- `eval_cubic_poly` test with known coefficients and a known point — uses literal expected output (NO cross-impl required for pure functions; Noir test alone is sufficient).
- `calculate_eq` test with known r and alpha — same.
- A `run_sumcheck_verifier` placeholder KAT with a stubbed `EXPECTED_SUMCHECK_F_AT_ALPHA` global that Task 4 fills in via Rust replay.

### Steps

- [ ] **Step 1: Create `provekit/verifier-noir/src/sumcheck.nr` with this content:**

```noir
//! Spartan sumcheck verifier.
//!
//! Mirrors `provekit/verifier/src/whir_r1cs.rs::run_sumcheck_verifier`:
//!
//!   1. Squeeze `M0` initial challenges `r`.
//!   2. Absorb the prover's claimed sum `sum_g`.
//!   3. Squeeze the batching challenge `rho`; set `saved = rho * sum_g`.
//!   4. For each of `M0` rounds:
//!        a. Absorb the cubic polynomial `h_i` (4 coefficients).
//!        b. Squeeze the round challenge `alpha_i`.
//!        c. Assert `h_i(0) + h_i(1) == saved`.
//!        d. Update `saved = h_i(alpha_i)`.
//!   5. Absorb `blinding_eval`.
//!   6. Return `(r, alpha, blinding_eval, f_at_alpha)` where
//!      `f_at_alpha = saved - rho * blinding_eval`.
//!
//! Cross-implementation KAT lives in
//! `provekit/verifier-noir-test/tests/sumcheck_kat.rs`.

use crate::transcript::Transcript;

/// Evaluate a cubic polynomial via Horner's method.
/// `poly = [c0, c1, c2, c3]` represents `c0 + c1·x + c2·x² + c3·x³`.
pub fn eval_cubic_poly(poly: [Field; 4], point: Field) -> Field {
    poly[0] + point * (poly[1] + point * (poly[2] + point * poly[3]))
}

/// Multilinear extension of the equality polynomial:
/// `eq(r, alpha) = ∏_i (r[i]·α[i] + (1 - r[i])·(1 - α[i]))`.
pub fn calculate_eq<let N: u32>(r: [Field; N], alpha: [Field; N]) -> Field {
    let mut acc: Field = 1;
    for i in 0..N {
        acc *= r[i] * alpha[i] + (1 - r[i]) * (1 - alpha[i]);
    }
    acc
}

/// Result of a successful sumcheck verification.
pub struct SumcheckResult<let M0: u32> {
    pub r: [Field; M0],
    pub alpha: [Field; M0],
    pub blinding_eval: Field,
    pub f_at_alpha: Field,
}

/// Verify a Spartan sumcheck against a Fiat-Shamir transcript.
///
/// `h_polys[i]` is the cubic polynomial sent by the prover in round i;
/// `sum_g` is the claimed initial sum; `blinding_eval` is the final
/// blinding evaluation hint. All come from the proof bytes parsed by the
/// codegen tool.
pub fn run_sumcheck_verifier<let M0: u32>(
    transcript: &mut Transcript,
    sum_g: Field,
    h_polys: [[Field; 4]; M0],
    blinding_eval: Field,
) -> SumcheckResult<M0> {
    // Phase 1: squeeze initial challenges r.
    let mut r: [Field; M0] = [0; M0];
    for i in 0..M0 {
        r[i] = transcript.squeeze_field();
    }

    // Phase 2: absorb sum, squeeze rho, initialize saved.
    transcript.absorb_field(sum_g);
    let rho = transcript.squeeze_field();
    let mut saved = rho * sum_g;

    // Phase 3: per-round challenge derivation + soundness checks.
    let mut alpha: [Field; M0] = [0; M0];
    for i in 0..M0 {
        let h_i = h_polys[i];
        for j in 0..4 {
            transcript.absorb_field(h_i[j]);
        }
        let alpha_i = transcript.squeeze_field();
        alpha[i] = alpha_i;

        let h_at_zero = eval_cubic_poly(h_i, 0);
        let h_at_one = eval_cubic_poly(h_i, 1);
        assert(saved == h_at_zero + h_at_one);

        saved = eval_cubic_poly(h_i, alpha_i);
    }

    // Phase 4: absorb blinding hint, derive f_at_alpha.
    transcript.absorb_field(blinding_eval);
    let f_at_alpha = saved - rho * blinding_eval;

    SumcheckResult { r, alpha, blinding_eval, f_at_alpha }
}

// --- in-circuit unit tests for pure functions ---

#[test]
fn eval_cubic_poly_horner() {
    // p(x) = 1 + 2x + 3x² + 4x³; p(2) = 1 + 4 + 12 + 32 = 49.
    let out = eval_cubic_poly([1, 2, 3, 4], 2);
    assert(out == 49);
}

#[test]
fn calculate_eq_boolean_identity() {
    // eq(r, r) where r is boolean = 1.
    let r: [Field; 3] = [0, 1, 0];
    let alpha: [Field; 3] = [0, 1, 0];
    assert(calculate_eq(r, alpha) == 1);
}

#[test]
fn calculate_eq_boolean_orthogonal() {
    // eq(r, r̄) where r̄ flips every bit = 0.
    let r: [Field; 3] = [0, 1, 0];
    let alpha: [Field; 3] = [1, 0, 1];
    assert(calculate_eq(r, alpha) == 0);
}

#[test]
fn calculate_eq_non_boolean() {
    // r = [2, 3], alpha = [4, 5]
    // term0 = 2*4 + (-1)*(-3) = 8 + 3 = 11
    // term1 = 3*5 + (-2)*(-4) = 15 + 8 = 23
    // product = 253
    let r: [Field; 2] = [2, 3];
    let alpha: [Field; 2] = [4, 5];
    assert(calculate_eq(r, alpha) == 253);
}

// --- in-circuit sumcheck KAT (placeholder) ---
//
// Canonical Phase 2A sumcheck KAT:
//   transcript = fresh
//   sum_g = 12
//   M0 = 2; h_polys = constructed by the Rust replay so each round's
//                     soundness assertion passes.
//   blinding_eval = 7
// EXPECTED_SUMCHECK_F_AT_ALPHA freezes the final f_at_alpha.
// Task 4 replaces the placeholder.
//
// PLACEHOLDER VALUE - overwritten in Phase 2A Task 4 after running the
// Rust-side computation. The test below is expected to FAIL until then.
global EXPECTED_SUMCHECK_F_AT_ALPHA: Field = 0;
global SUMCHECK_KAT_SUM_G: Field = 12;
global SUMCHECK_KAT_BLINDING_EVAL: Field = 7;
// h_polys are also chosen by the Rust replay to make round assertions pass;
// frozen here so Noir and Rust feed identical cubic coefficients.
// PLACEHOLDER VALUES - Task 4 overwrites both rows.
global SUMCHECK_KAT_H_POLYS: [[Field; 4]; 2] = [
    [0, 0, 0, 0],
    [0, 0, 0, 0],
];

#[test]
fn sumcheck_verifier_matches_frozen_kat() {
    let mut t = Transcript::new();
    let result = run_sumcheck_verifier::<2>(
        &mut t,
        SUMCHECK_KAT_SUM_G,
        SUMCHECK_KAT_H_POLYS,
        SUMCHECK_KAT_BLINDING_EVAL,
    );
    assert(result.f_at_alpha == EXPECTED_SUMCHECK_F_AT_ALPHA);
}
```

- [ ] **Step 2: Wire the module into main.nr.**

Modify `provekit/verifier-noir/src/main.nr` so the head matches:

```noir
// ProveKit Noir Recursive Verifier
//
// Verifies a ProveKit WHIR+Spartan proof generated under HashConfig::Poseidon2.
// See docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md
//
// Phase 2A: + Poseidon2 length-IV hash + Spartan sumcheck. Matrix eval + WHIR land later.

mod poseidon2;
mod sponge;
mod transcript;
mod merkle;
mod sumcheck;

fn main() {}
```

- [ ] **Step 3: Run `nargo test sumcheck` — expect mixed pass/fail.**

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test sumcheck 2>&1 | tail -20`

Expected: 4 passes (`eval_cubic_poly_horner`, `calculate_eq_boolean_identity`, `calculate_eq_boolean_orthogonal`, `calculate_eq_non_boolean`) + 1 fail (`sumcheck_verifier_matches_frozen_kat` — but note: it may fail at the SOUNDNESS assertion `saved == h(0) + h(1)` since h_polys are all zeros, BEFORE reaching the final `f_at_alpha` assert. Either failure point is acceptable for TDD red — Task 4 fixes it).

- [ ] **Step 4: Regression check.**

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test 2>&1 | tail -10`

Expected: 7 passed (poseidon2, sponge, transcript, length_iv_hash, eval_cubic_poly_horner, calculate_eq_boolean_identity, calculate_eq_boolean_orthogonal, calculate_eq_non_boolean — wait that's 8), 1 failed (sumcheck_verifier_matches_frozen_kat).

Actually count: 1 (poseidon2) + 1 (sponge) + 1 (transcript) + 1 (merkle/length_iv_hash) + 4 (sumcheck pure) = 8 passed + 1 failed (sumcheck KAT).

- [ ] **Step 5: Commit.**

```bash
cd /Users/paradox/Desktop/projects/provekit
git add provekit/verifier-noir/src/sumcheck.nr provekit/verifier-noir/src/main.nr
git commit -m "feat(verifier-noir): add sumcheck verifier with placeholder KAT"
```

Conventional Commits. NO Claude trailer.

---

## Task 4: Cross-impl sumcheck KAT — turn placeholder green

**Files:**
- Modify: `provekit/verifier-noir-test/src/lib.rs` — add a Rust sumcheck transcript constructor + verifier replay helper
- Modify: `provekit/verifier-noir/src/sumcheck.nr` — replace 3 placeholder globals with real values
- Create: `provekit/verifier-noir-test/tests/sumcheck_kat.rs` — integration test shells out to `nargo test sumcheck_verifier_matches_frozen_kat`

**Outcome:** A Rust helper that:
1. Constructs a valid sumcheck transcript: starting with `sum_g = 12`, M0=2 rounds. Each round picks `h_i = [saved/2, 0, 0, 0]` (constant polynomial with `h_i(0) + h_i(1) = saved`) so the soundness assertion passes; the round challenge `alpha_i` is squeezed from the transcript to advance `saved = h_i(alpha_i) = saved/2`.
2. Runs the same verifier logic in Rust to compute `f_at_alpha`.
3. Returns `(h_polys, f_at_alpha)`.

The Noir-side test feeds the same `h_polys` and `sum_g` and `blinding_eval`; if both verifiers agree, both produce the same `f_at_alpha` (which is then frozen as `EXPECTED_SUMCHECK_F_AT_ALPHA`).

### Steps

- [ ] **Step 1: Extend `provekit/verifier-noir-test/src/lib.rs` with the sumcheck constructor + replay.**

Append (do NOT remove anything) BEFORE the `#[cfg(test)] mod tests` block:

```rust
/// Build a valid 2-round Spartan sumcheck transcript with `sum_g = 12`,
/// `blinding_eval = 7`, using the convention `h_i = [saved/2, 0, 0, 0]`
/// (constant polynomial whose two boolean-hypercube evaluations both equal
/// half the running saved value, so `h_i(0) + h_i(1) == saved` always).
///
/// Returns the two `h_polys` rows (each `[c0, c1, c2, c3]`) AND the
/// `f_at_alpha` the verifier should compute. Both Noir and the Rust replay
/// consume the same `(sum_g, h_polys, blinding_eval)`; they must agree on
/// `f_at_alpha`.
pub fn sumcheck_kat_construct() -> ([[Fr; 4]; 2], Fr) {
    // Mirror Noir `Transcript::new()` and the run_sumcheck_verifier sequence
    // via `lane_sponge_replay` (lane-grain over `poseidon2_permutation`).
    // We can't use `Poseidon2Sponge` directly because we need both squeeze
    // and absorb interleaved with mid-stream computation.
    let sum_g = Fr::from(12u64);
    let blinding_eval = Fr::from(7u64);

    // Simulate Transcript::new() => fresh lane sponge.
    let mut state = [Fr::from(0u64); 4];
    let mut absorb_pos: u32 = 0;
    let mut squeeze_pos: u32 = 3; // RATE

    const M0: usize = 2;

    // Phase 1: squeeze M0 challenges (`r`).
    let mut r = [Fr::from(0u64); M0];
    for slot in r.iter_mut() {
        *slot = squeeze_one(&mut state, &mut absorb_pos, &mut squeeze_pos);
    }

    // Phase 2: absorb sum_g.
    absorb_one(&mut state, &mut absorb_pos, &mut squeeze_pos, sum_g);

    // Phase 3: squeeze rho, init saved = rho * sum_g.
    let rho = squeeze_one(&mut state, &mut absorb_pos, &mut squeeze_pos);
    let mut saved = rho * sum_g;

    // Phase 4: per-round h_polys + assertions.
    let mut h_polys = [[Fr::from(0u64); 4]; M0];
    let two_inv = Fr::from(2u64).inverse().unwrap();
    for round in 0..M0 {
        // Pick h_i = [saved * (1/2), 0, 0, 0] => constant polynomial,
        // h_i(0) + h_i(1) = saved/2 + saved/2 = saved. Soundness check passes.
        let c0 = saved * two_inv;
        h_polys[round] = [c0, Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)];

        // Absorb the 4 coefficients.
        for j in 0..4 {
            absorb_one(&mut state, &mut absorb_pos, &mut squeeze_pos, h_polys[round][j]);
        }

        // Squeeze alpha_i, update saved = h_i(alpha_i) = c0 (constant poly).
        let _alpha_i = squeeze_one(&mut state, &mut absorb_pos, &mut squeeze_pos);
        saved = c0; // h_i(alpha_i) = c0 since c1,c2,c3 are zero.
    }

    // Phase 5: absorb blinding_eval.
    absorb_one(&mut state, &mut absorb_pos, &mut squeeze_pos, blinding_eval);

    // f_at_alpha = saved - rho * blinding_eval.
    let f_at_alpha = saved - rho * blinding_eval;

    (h_polys, f_at_alpha)
}

const SUMCHECK_RATE: u32 = 3;

fn absorb_one(state: &mut [Fr; 4], absorb_pos: &mut u32, squeeze_pos: &mut u32, fe: Fr) {
    *squeeze_pos = SUMCHECK_RATE;
    if *absorb_pos == SUMCHECK_RATE {
        *state = poseidon2::permutation::poseidon2_permutation(state);
        *absorb_pos = 0;
    }
    state[*absorb_pos as usize] = fe;
    *absorb_pos += 1;
}

fn squeeze_one(state: &mut [Fr; 4], absorb_pos: &mut u32, squeeze_pos: &mut u32) -> Fr {
    *absorb_pos = 0;
    if *squeeze_pos == SUMCHECK_RATE {
        *squeeze_pos = 0;
        *state = poseidon2::permutation::poseidon2_permutation(state);
    }
    let out = state[*squeeze_pos as usize];
    *squeeze_pos += 1;
    out
}
```

Then add to the `#[cfg(test)] mod tests` block:

```rust
/// Print the values that Noir's sumcheck KAT globals should hold.
#[test]
fn print_sumcheck_kat_expected_for_noir() {
    let (h_polys, f_at_alpha) = sumcheck_kat_construct();
    for (round, row) in h_polys.iter().enumerate() {
        for (j, c) in row.iter().enumerate() {
            println!(
                "SUMCHECK_KAT_H_POLYS[{round}][{j}] = {}",
                fr_to_noir_literal(*c)
            );
        }
    }
    println!(
        "EXPECTED_SUMCHECK_F_AT_ALPHA = {}",
        fr_to_noir_literal(f_at_alpha)
    );
}
```

- [ ] **Step 2: Capture all 9 expected values.**

Run: `cargo test -p provekit-verifier-noir-test print_sumcheck_kat_expected_for_noir -- --nocapture 2>&1 | grep -E "SUMCHECK"`

Expected: 8 lines `SUMCHECK_KAT_H_POLYS[round][j] = <decimal>` + 1 line `EXPECTED_SUMCHECK_F_AT_ALPHA = <decimal>`. Capture all 9 values.

- [ ] **Step 3: Patch `provekit/verifier-noir/src/sumcheck.nr` with the real values.**

Replace these three placeholder globals:

```noir
global EXPECTED_SUMCHECK_F_AT_ALPHA: Field = 0;
global SUMCHECK_KAT_SUM_G: Field = 12;
global SUMCHECK_KAT_BLINDING_EVAL: Field = 7;
global SUMCHECK_KAT_H_POLYS: [[Field; 4]; 2] = [
    [0, 0, 0, 0],
    [0, 0, 0, 0],
];
```

Replace `EXPECTED_SUMCHECK_F_AT_ALPHA` with the captured decimal. Leave `SUMCHECK_KAT_SUM_G = 12` and `SUMCHECK_KAT_BLINDING_EVAL = 7` (those are inputs to the construction, not outputs). Replace `SUMCHECK_KAT_H_POLYS` with the 8 captured decimals:

```noir
global EXPECTED_SUMCHECK_F_AT_ALPHA: Field = <decimal-from-step-2>;
global SUMCHECK_KAT_SUM_G: Field = 12;
global SUMCHECK_KAT_BLINDING_EVAL: Field = 7;
// Values constructed by the Rust replay so each round's soundness check
// (h_i(0) + h_i(1) == saved) holds. See
// provekit/verifier-noir-test/tests/sumcheck_kat.rs for the cross-impl
// guarantee.
global SUMCHECK_KAT_H_POLYS: [[Field; 4]; 2] = [
    [<decimal>, <decimal>, <decimal>, <decimal>],
    [<decimal>, <decimal>, <decimal>, <decimal>],
];
```

Also update the placeholder comment block above the globals to remove the stale "PLACEHOLDER VALUE" text and "Task 4 overwrites" line.

- [ ] **Step 4: Verify `nargo test sumcheck` now fully PASSES.**

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test sumcheck 2>&1 | tail -10`

Expected: 5 passed (4 pure-function tests + 1 sumcheck KAT). If the sumcheck KAT still fails, two possible causes:
- The 9 decimals were captured/pasted wrongly. Re-do steps 2-3.
- The Noir verifier's transcript flow disagrees with the Rust replay (a real bug — investigate before continuing).

- [ ] **Step 5: Create `provekit/verifier-noir-test/tests/sumcheck_kat.rs`.**

```rust
//! Cross-implementation sumcheck KAT.
//!
//! 1. Construct a valid 2-round Spartan sumcheck transcript in Rust:
//!    `sum_g = 12`, `blinding_eval = 7`, `h_i = [saved/2, 0, 0, 0]` each round.
//!    The Rust replay derives the expected `f_at_alpha`.
//! 2. Shell out to `nargo test sumcheck_verifier_matches_frozen_kat`.
//!    That test runs the same `(sum_g, h_polys, blinding_eval)` through
//!    Noir's `run_sumcheck_verifier` and asserts `f_at_alpha` matches.
//! 3. Passing means both implementations agree on this synthetic transcript.

use {
    provekit_verifier_noir_test::sumcheck_kat_construct,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_sumcheck_kat_agrees() {
    let (h_polys_a, f_a) = sumcheck_kat_construct();
    let (h_polys_b, f_b) = sumcheck_kat_construct();
    assert_eq!(h_polys_a, h_polys_b, "sumcheck_kat_construct non-deterministic on h_polys");
    assert_eq!(f_a, f_b, "sumcheck_kat_construct non-deterministic on f_at_alpha");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let nargo_crate = manifest_dir
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .join("verifier-noir");
    assert!(
        nargo_crate.join("Nargo.toml").exists(),
        "verifier-noir Nargo.toml not found at {}",
        nargo_crate.display()
    );

    let status = Command::new("nargo")
        .args(["test", "sumcheck_verifier_matches_frozen_kat"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo - is it on PATH?");

    assert!(
        status.success(),
        "nargo test sumcheck_verifier_matches_frozen_kat failed (exit code {:?}). \
         The Noir sumcheck verifier disagreed with the Rust replay on the canonical KAT. \
         Re-run Phase 2A Task 4 step 2 to regenerate the expected values.",
        status.code(),
    );
}
```

- [ ] **Step 6: Run the cross-impl test.**

Run: `cargo test -p provekit-verifier-noir-test --test sumcheck_kat 2>&1 | tail -10`

Expected: 1 passed.

- [ ] **Step 7: Full regression check.**

Run: `cargo test -p provekit-verifier-noir-test 2>&1 | grep -E "^(test result|running)"`

Expected: all binaries pass. lib (5 printers: poseidon2, sponge, transcript, merkle, sumcheck) + 5 integration tests (poseidon2_kat, sponge_kat, transcript_kat, merkle_kat, sumcheck_kat). 10 tests total, all passing.

- [ ] **Step 8: Clippy.**

Run: `cargo clippy -p provekit-verifier-noir-test --all-targets 2>&1 | tail -10`

Expected: no warnings on new code.

- [ ] **Step 9: Commit.**

```bash
cd /Users/paradox/Desktop/projects/provekit
git add provekit/verifier-noir-test/ provekit/verifier-noir/src/sumcheck.nr
git commit -m "test(verifier-noir): cross-impl sumcheck KAT (Rust replay vs Noir)"
```

Conventional Commits. NO Claude trailer.

---

## What Phase 2A leaves behind

- `provekit/verifier-noir/src/merkle.nr` — Poseidon2 length-IV hash matching `poseidon2_hash`, with cross-impl KAT.
- `provekit/verifier-noir/src/sumcheck.nr` — `eval_cubic_poly`, `calculate_eq`, `run_sumcheck_verifier`, with cross-impl KAT against a Rust replay.
- `provekit/verifier-noir-test/src/lib.rs` extended with merkle + sumcheck KAT helpers.

## What Phase 2B will cover (next plan)

- `matrix_eval.nr` — sparse A/B/C evaluation: read codegen-emitted matrices, compute `az_at_alpha`/`bz_at_alpha`/`cz_at_alpha` via transposed-matrix · `eq(alpha, ·)`.
- `public_input.nr` — Poseidon2 instance hash with DST prefix + geometric public-eval binding check.
- Codegen emitter foundations: extend `provekit-cli generate-noir-inputs` to actually deserialize `.pkv` and dump scheme constants to stdout (full types.nr/matrices.nr/Prover.toml emission happens in Phase 2C).

## What's deliberately out of scope for Phase 2A

- Path verification for Merkle tree (`verify_path`) — used only by `whir.nr` (Phase 3); not needed until then.
- `length_iv_hash` for arbitrary `N` beyond what the v0 inner circuit needs — the generic version is enough; per-N constant folding is the Noir compiler's job.
- Full codegen tool logic — Phase 2B/2C.
- WHIR LDT verification — Phase 3.
- One-wrap recursion + perf measurement — Phase 4.
