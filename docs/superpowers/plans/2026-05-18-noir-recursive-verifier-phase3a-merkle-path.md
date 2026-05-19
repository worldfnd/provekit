# Noir Recursive Verifier — Phase 3A: Merkle Path Verification

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Spec:** [`docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md`](../specs/2026-05-18-noir-recursive-verifier-design.md)
**Predecessor:** [Phase 2C — Codegen Tool](./2026-05-18-noir-recursive-verifier-phase2c-codegen.md)

**Goal:** Add Merkle authentication-path verification to `merkle.nr` so Phase 3B's `whir.nr` can verify WHIR's Merkle openings. Small, self-contained addition layered on the Phase 2A length-IV hash.

**Architecture:**
- `verify_merkle_path<let LEAF_SIZE, let TREE_HEIGHT>(leaf: [Field; LEAF_SIZE], siblings: [Field; TREE_HEIGHT], index: u32, root: Field)` — hashes the leaf via `length_iv_hash`, then iterates up the tree pair-hashing with siblings (order determined by bit of index), asserts final == root.
- WHIR's Merkle uses `poseidon2_hash_bytes` for both leaf hashing (over `leaf_size` field elements) and internal nodes (pair-hash over 2 field elements). Both are length-IV hashes — we use `length_iv_hash` for both.

**Tech Stack:** Noir 1.0.0-beta.19, Rust workspace `poseidon2::poseidon2_hash`.

---

## File map

```
MOD    provekit/verifier-noir/src/merkle.nr            (add verify_merkle_path + placeholder KAT)
MOD    provekit/verifier-noir-test/src/lib.rs          (add merkle_path_kat_expected helper)
NEW    provekit/verifier-noir-test/tests/merkle_path_kat.rs   (cross-impl integration test)
```

---

## Task 1: Add `verify_merkle_path` + placeholder KAT

**Files:**
- Modify: `provekit/verifier-noir/src/merkle.nr`

**Outcome:** New `pub fn verify_merkle_path<...>(leaf, siblings, index, root)` that hashes leaf → walks up tree with siblings → asserts root match. Plus a placeholder KAT for a 4-leaf tree (height=2) with leaf at index 1 that fails intentionally.

### Step 1: Read current `merkle.nr` state

Current file exposes:
- `length_iv_hash<let N: u32>(inputs: [Field; N]) -> Field`
- `EXPECTED_HASH_2: Field` and `length_iv_hash_2_matches_frozen_kat` test
- `HASH_RATE`, `TWO_POW_64` globals

### Step 2: Add `verify_merkle_path` to `merkle.nr`

Append after the existing `length_iv_hash` function definition (before the `// --- in-circuit KAT ---` comment):

```noir
/// Verify a Merkle authentication path.
///
/// 1. Hash the leaf via `length_iv_hash::<LEAF_SIZE>(leaf)`.
/// 2. For each level i in 0..TREE_HEIGHT:
///    - Read bit i of `index` (lowest bit is the leaf-level pairing).
///    - If bit i == 0: parent = length_iv_hash::<2>([current, siblings[i]]).
///    - If bit i == 1: parent = length_iv_hash::<2>([siblings[i], current]).
/// 3. Assert the final parent equals `root`.
///
/// Matches WHIR's Merkle tree construction (binary, leaf-grain via
/// `poseidon2_hash_bytes` which equals `length_iv_hash` for field-aligned input).
pub fn verify_merkle_path<let LEAF_SIZE: u32, let TREE_HEIGHT: u32>(
    leaf: [Field; LEAF_SIZE],
    siblings: [Field; TREE_HEIGHT],
    index: u32,
    root: Field,
) {
    let mut current = length_iv_hash::<LEAF_SIZE>(leaf);
    let mut idx = index;
    for i in 0..TREE_HEIGHT {
        let sibling = siblings[i];
        let bit = idx & 1;
        let pair: [Field; 2] = if bit == 0 {
            [current, sibling]
        } else {
            [sibling, current]
        };
        current = length_iv_hash::<2>(pair);
        idx >>= 1;
    }
    assert(current == root);
}
```

### Step 3: Add placeholder Merkle path KAT

Append to the in-circuit KAT block at the end of `merkle.nr`:

```noir
// --- in-circuit Merkle path KAT (placeholder) ---
//
// 4-leaf tree (TREE_HEIGHT = 2), leaves = [Field; 1] each.
//
//   leaves: [L0, L1, L2, L3] = [[1], [2], [3], [4]]
//   level-1 hashes:
//     h01 = length_iv_hash([length_iv_hash([1]), length_iv_hash([2])])
//     h23 = length_iv_hash([length_iv_hash([3]), length_iv_hash([4])])
//   root = length_iv_hash([h01, h23])
//
//   We verify the path to leaf index 1 (= L1 = [2]):
//     siblings[0] = length_iv_hash([1])   (sibling at leaf level)
//     siblings[1] = h23                   (sibling at level 1)
//
// EXPECTED_PATH_ROOT is the frozen root value. Task 2 unfreezes it.
//
// PLACEHOLDER VALUES - overwritten in Phase 3A Task 2.
global EXPECTED_PATH_ROOT: Field = 0;
global EXPECTED_PATH_SIBLINGS: [Field; 2] = [0, 0];

#[test]
fn verify_merkle_path_matches_frozen_kat() {
    let leaf: [Field; 1] = [2];
    let index: u32 = 1;
    verify_merkle_path::<1, 2>(leaf, EXPECTED_PATH_SIBLINGS, index, EXPECTED_PATH_ROOT);
}
```

### Step 4: Run `nargo test merkle` — verify mixed pass/fail

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test merkle 2>&1 | tail -15`

Expected: 1 passed (`length_iv_hash_2_matches_frozen_kat` from Phase 2A) + 1 failed (`verify_merkle_path_matches_frozen_kat` — placeholder root won't match). Intended TDD red.

### Step 5: Full regression

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test 2>&1 | tail -10`

Expected: 12 passed + 1 failed (new merkle path KAT).

### Step 6: Commit

```bash
cd /Users/paradox/Desktop/projects/provekit
git add provekit/verifier-noir/src/merkle.nr
git commit -m "feat(verifier-noir): add Merkle path verification with placeholder KAT"
```

Conventional Commits. NO `Co-Authored-By: Claude` trailer.

---

## Task 2: Cross-impl Merkle path KAT

**Files:**
- Modify: `provekit/verifier-noir-test/src/lib.rs` — add `merkle_path_kat_expected()` (computes the root + siblings for a 4-leaf tree)
- Modify: `provekit/verifier-noir/src/merkle.nr` — replace `EXPECTED_PATH_ROOT` and `EXPECTED_PATH_SIBLINGS` placeholders with real values
- Create: `provekit/verifier-noir-test/tests/merkle_path_kat.rs` — integration test shelling out to `nargo test verify_merkle_path`

**Outcome:** Noir `verify_merkle_path` agrees with a Rust reference: hash leaves with `poseidon2_hash`, build a 2-level tree, verify path to index 1.

### Step 1: Add helper to `lib.rs`

Append (before `#[cfg(test)] mod tests`):

```rust
/// Build a 4-leaf Merkle tree using `poseidon2_hash` and return
/// `(siblings_along_path_to_index_1, root)`.
///
///   leaves = [[1], [2], [3], [4]]
///   leaf_hash_i = poseidon2_hash([leaf_i])
///   h01 = poseidon2_hash([leaf_hash_0, leaf_hash_1])
///   h23 = poseidon2_hash([leaf_hash_2, leaf_hash_3])
///   root = poseidon2_hash([h01, h23])
///
/// Path to leaf index 1:
///   siblings[0] = leaf_hash_0 (the other child at the leaf level)
///   siblings[1] = h23         (the other child at level 1)
pub fn merkle_path_kat_expected() -> ([Fr; 2], Fr) {
    use poseidon2::poseidon2_hash;

    let leaf0 = poseidon2_hash(&[Fr::from(1u64)]);
    let leaf1 = poseidon2_hash(&[Fr::from(2u64)]);
    let leaf2 = poseidon2_hash(&[Fr::from(3u64)]);
    let leaf3 = poseidon2_hash(&[Fr::from(4u64)]);

    let h01 = poseidon2_hash(&[leaf0, leaf1]);
    let h23 = poseidon2_hash(&[leaf2, leaf3]);
    let root = poseidon2_hash(&[h01, h23]);

    let siblings = [leaf0, h23];
    (siblings, root)
}
```

Then add to `#[cfg(test)] mod tests`:

```rust
#[test]
fn print_merkle_path_kat_expected_for_noir() {
    let (siblings, root) = merkle_path_kat_expected();
    println!("EXPECTED_PATH_SIBLINGS[0] = {}", fr_to_noir_literal(siblings[0]));
    println!("EXPECTED_PATH_SIBLINGS[1] = {}", fr_to_noir_literal(siblings[1]));
    println!("EXPECTED_PATH_ROOT = {}", fr_to_noir_literal(root));
}
```

### Step 2: Capture the 3 values

Run:

```bash
cargo test -p provekit-verifier-noir-test print_merkle_path_kat_expected_for_noir -- --nocapture 2>&1 | grep -E "(EXPECTED_PATH_SIBLINGS|EXPECTED_PATH_ROOT)"
```

Expected: 3 lines (`SIBLINGS[0]`, `SIBLINGS[1]`, `ROOT`). Capture all.

### Step 3: Patch `merkle.nr`

Replace:

```noir
// PLACEHOLDER VALUES - overwritten in Phase 3A Task 2.
global EXPECTED_PATH_ROOT: Field = 0;
global EXPECTED_PATH_SIBLINGS: [Field; 2] = [0, 0];
```

With (substituting the 3 captured decimals):

```noir
// Values computed by Rust `poseidon2_hash` over a 4-leaf tree (leaves = [[1],[2],[3],[4]]);
// path to leaf index 1. Frozen as a KAT. See
// provekit/verifier-noir-test/tests/merkle_path_kat.rs for the cross-impl guarantee.
global EXPECTED_PATH_ROOT: Field = <decimal-root>;
global EXPECTED_PATH_SIBLINGS: [Field; 2] = [
    <decimal-siblings-0>,
    <decimal-siblings-1>,
];
```

Also remove any stale "PLACEHOLDER VALUES" comment text in the block.

### Step 4: Verify `nargo test verify_merkle_path` passes

Run: `cd /Users/paradox/Desktop/projects/provekit/provekit/verifier-noir && nargo test verify_merkle_path 2>&1 | tail -5`

Expected: 1 passed.

### Step 5: Create integration test `provekit/verifier-noir-test/tests/merkle_path_kat.rs`

```rust
//! Cross-implementation Merkle path verification KAT.

use {
    provekit_verifier_noir_test::merkle_path_kat_expected,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_merkle_path_kat_agrees() {
    let a = merkle_path_kat_expected();
    let b = merkle_path_kat_expected();
    assert_eq!(a, b, "merkle_path_kat_expected non-deterministic");

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
        .args(["test", "verify_merkle_path"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo");

    assert!(
        status.success(),
        "nargo test verify_merkle_path failed (exit {:?})",
        status.code(),
    );
}
```

### Step 6: Run integration test + regression

Run: `cargo test -p provekit-verifier-noir-test --test merkle_path_kat 2>&1 | tail -5`
Expected: 1 passed.

Run: `cargo test -p provekit-verifier-noir-test 2>&1 | grep -E "^(test result|running)"`
Expected: 8 lib + 9 integration tests pass.

### Step 7: Clippy

Run: `cargo clippy -p provekit-verifier-noir-test --all-targets 2>&1 | tail -5`
Expected: no warnings on new code.

### Step 8: Commit

```bash
cd /Users/paradox/Desktop/projects/provekit
git add provekit/verifier-noir-test/ provekit/verifier-noir/src/merkle.nr
git commit -m "test(verifier-noir): cross-impl Merkle path verification KAT"
```

Conventional Commits. NO Claude trailer.

---

## What Phase 3A leaves behind

- `verify_merkle_path<LEAF_SIZE, TREE_HEIGHT>(leaf, siblings, index, root)` in merkle.nr, cross-impl-KAT'd against Rust `poseidon2_hash` building a 4-leaf tree.

## What Phase 3B will cover (next plan)

- Extend transcript with `squeeze_bytes_n` (sub-lane byte squeezing for WHIR query indices).
- Add `whir.nr` — WHIR LDT verifier (commitments, sumcheck per round, OOD samples, STIR fold, query phase, final claim).

## Deliberately out of scope for Phase 3A

- WHIR LDT itself — Phase 3B.
- Integrated main.nr — Phase 3D.
- Prover.toml codegen — Phase 3D (alongside main.nr).
- End-to-end `nargo execute` — Phase 3E.
