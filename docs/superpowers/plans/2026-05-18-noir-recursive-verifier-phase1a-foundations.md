# Noir Recursive Verifier — Phase 1A: Foundations

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** [`docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md`](../specs/2026-05-18-noir-recursive-verifier-design.md)

**Goal:** Land the foundational scaffolding for the Noir recursive verifier: a new `provekit-cli` subcommand stub, a compiling Noir crate skeleton, a Poseidon2 permutation wrapper, and a cross-implementation KAT proving the Noir stdlib permutation matches the Rust `poseidon2` crate bit-for-bit.

**Architecture:** Four atomic tasks. Each ends in a commit. Each produces working/testable software:
- Task 1 ends with a wired-up CLI subcommand that exits Ok.
- Task 2 ends with a Noir crate that passes `nargo check`.
- Task 3 ends with a Noir `#[test]` proving the stdlib permutation produces a frozen byte output.
- Task 4 ends with a Rust integration test cross-checking the same fixed input through both implementations.

**Tech Stack:** Rust (argh-based CLI, postcard, anyhow), Noir 1.0.0-beta.19 (stdlib `std::hash::poseidon2_permutation`), `poseidon2` workspace crate (BN254 Poseidon2 permutation).

---

## File map

```
NEW    tooling/cli/src/cmd/generate_noir_inputs.rs
MOD    tooling/cli/src/cmd/mod.rs
NEW    provekit/verifier-noir/Nargo.toml
NEW    provekit/verifier-noir/src/main.nr
NEW    provekit/verifier-noir/src/poseidon2.nr
NEW    provekit/verifier-noir/tests/cross_impl_kat.rs  (Rust test crate? — implemented as Cargo crate; details in Task 4)
NEW    provekit/verifier-noir-test/Cargo.toml         (Task 4 only; Cargo cannot live inside a Nargo crate without conflict)
NEW    provekit/verifier-noir-test/src/lib.rs
NEW    provekit/verifier-noir-test/tests/poseidon2_kat.rs
MOD    Cargo.toml (workspace `members =`)
```

Rationale: a Nargo package's root is `Nargo.toml`, not `Cargo.toml`. To run Cargo-driven integration tests that touch the Noir crate (shell out to `nargo test`), we add a *sibling* Cargo test crate `provekit/verifier-noir-test/`. This keeps Nargo and Cargo configs untangled.

---

## Task 1: Wire up `generate-noir-inputs` subcommand stub

**Files:**
- Create: `tooling/cli/src/cmd/generate_noir_inputs.rs`
- Modify: `tooling/cli/src/cmd/mod.rs`

**Outcome:** `provekit-cli generate-noir-inputs <pkv> <np>` parses args, prints a one-line "scaffold ready" message to stderr, and exits 0. No proof-parsing logic yet — that's Phase 2.

- [ ] **Step 1: Write the failing test.**

Append to `tooling/cli/src/cmd/generate_noir_inputs.rs` (file does not yet exist — this creates it):

```rust
use {
    super::Command,
    anyhow::Result,
    argh::FromArgs,
    std::path::PathBuf,
    tracing::instrument,
};

/// Emit Noir verifier inputs (types.nr / matrices.nr / Prover.toml) from a
/// `.pkv` (ProveKit Verifier) and a `.np` (Noir proof) file generated under
/// `HashConfig::Poseidon2`.
///
/// Phase 1A: argument-parsing scaffold only. Codegen logic lands in Phase 2.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "generate-noir-inputs")]
pub struct Args {
    /// path to the ProveKit Verifier (PKV) file
    #[argh(positional)]
    verifier_path: PathBuf,

    /// path to the Noir proof (.np) file
    #[argh(positional)]
    proof_path: PathBuf,

    /// output directory for the generated Noir crate inputs
    /// (default: `provekit/verifier-noir`)
    #[argh(option, default = "PathBuf::from(\"provekit/verifier-noir\")")]
    out_dir: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        eprintln!(
            "generate-noir-inputs: scaffold ready (codegen logic lands in Phase 2). \
             pkv={} np={} out_dir={}",
            self.verifier_path.display(),
            self.proof_path.display(),
            self.out_dir.display()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_run_returns_ok() {
        let args = Args {
            verifier_path: PathBuf::from("/tmp/does-not-exist.pkv"),
            proof_path: PathBuf::from("/tmp/does-not-exist.np"),
            out_dir: PathBuf::from("/tmp/out"),
        };
        // The scaffold does not touch the filesystem — it only echoes the args.
        assert!(args.run().is_ok());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails (module not yet wired).**

Run: `cargo test -p provekit-cli generate_noir_inputs::tests::scaffold_run_returns_ok 2>&1 | tail -20`
Expected: compile error — `unresolved import super::Command` because the new file is not yet declared as a module in `cmd/mod.rs`.

- [ ] **Step 3: Wire the new module into `cmd/mod.rs`.**

Modify `tooling/cli/src/cmd/mod.rs`. Find the `mod` declarations at the top:

```rust
mod analyze_pkp;
mod circuit_stats;
mod generate_gnark_inputs;
mod prepare;
mod prove;
mod show_inputs;
mod util;
mod verify;
```

Add `mod generate_noir_inputs;` in alphabetical position:

```rust
mod analyze_pkp;
mod circuit_stats;
mod generate_gnark_inputs;
mod generate_noir_inputs;
mod prepare;
mod prove;
mod show_inputs;
mod util;
mod verify;
```

Then find the `enum Commands` and add the new variant:

```rust
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum Commands {
    AnalyzePkp(analyze_pkp::Args),
    Prepare(prepare::Args),
    Prove(prove::Args),
    CircuitStats(circuit_stats::Args),
    Verify(verify::Args),
    GenerateGnarkInputs(generate_gnark_inputs::Args),
    GenerateNoirInputs(generate_noir_inputs::Args),
    ShowInputs(show_inputs::Args),
}
```

And the `Command for Commands` impl:

```rust
impl Command for Commands {
    fn run(&self) -> Result<()> {
        match self {
            Self::AnalyzePkp(args) => args.run(),
            Self::Prepare(args) => args.run(),
            Self::Prove(args) => args.run(),
            Self::CircuitStats(args) => args.run(),
            Self::Verify(args) => args.run(),
            Self::GenerateGnarkInputs(args) => args.run(),
            Self::GenerateNoirInputs(args) => args.run(),
            Self::ShowInputs(args) => args.run(),
        }
    }
}
```

- [ ] **Step 4: Re-run the test to verify it passes.**

Run: `cargo test -p provekit-cli generate_noir_inputs::tests::scaffold_run_returns_ok 2>&1 | tail -10`
Expected: `test result: ok. 1 passed`.

- [ ] **Step 5: Smoke-test the binary.**

Run: `cargo run -p provekit-cli --release --quiet -- generate-noir-inputs /tmp/x.pkv /tmp/y.np 2>&1 | tail -3`
Expected (on stderr): `generate-noir-inputs: scaffold ready (codegen logic lands in Phase 2). pkv=/tmp/x.pkv np=/tmp/y.np out_dir=provekit/verifier-noir`
Exit code: 0.

- [ ] **Step 6: Commit.**

```bash
git add tooling/cli/src/cmd/generate_noir_inputs.rs tooling/cli/src/cmd/mod.rs
git commit -m "feat(cli): scaffold generate-noir-inputs subcommand"
```

---

## Task 2: Noir crate skeleton (`provekit/verifier-noir`)

**Files:**
- Create: `provekit/verifier-noir/Nargo.toml`
- Create: `provekit/verifier-noir/src/main.nr`

**Outcome:** `nargo check` from `provekit/verifier-noir/` exits 0 against an empty `fn main() {}` circuit.

- [ ] **Step 1: Create the Nargo manifest.**

Create `provekit/verifier-noir/Nargo.toml` with:

```toml
[package]
name = "provekit-verifier"
type = "bin"
authors = [""]
compiler_version = ">=1.0.0"
description = "Noir recursive verifier for ProveKit WHIR+Spartan proofs (Poseidon2 flavor)"

[dependencies]
```

(No external Noir deps yet — `std::hash::poseidon2_permutation` is in the stdlib.)

- [ ] **Step 2: Create a minimal main.nr stub.**

Create `provekit/verifier-noir/src/main.nr`:

```noir
// ProveKit Noir Recursive Verifier
//
// Verifies a ProveKit WHIR+Spartan proof generated under HashConfig::Poseidon2.
// See docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md
//
// Phase 1A: crate skeleton only. Modules and verification logic land in later phases.

fn main() {}
```

- [ ] **Step 3: Run `nargo check` to verify the skeleton compiles.**

Run: `cd provekit/verifier-noir && nargo check 2>&1 | tail -5 && cd ../..`
Expected: no errors. Possibly "[provekit-verifier] Constraint system successfully compiled" or similar success line; exit 0.

- [ ] **Step 4: Run `nargo test` to verify the test runner accepts the crate.**

Run: `cd provekit/verifier-noir && nargo test 2>&1 | tail -5 && cd ../..`
Expected: `0 passed; 0 failed` (no tests yet) or equivalent; exit 0.

- [ ] **Step 5: Commit.**

```bash
git add provekit/verifier-noir/Nargo.toml provekit/verifier-noir/src/main.nr
git commit -m "feat(verifier-noir): add Noir crate skeleton"
```

---

## Task 3: `poseidon2.nr` — stdlib wrapper + in-circuit KAT

**Files:**
- Create: `provekit/verifier-noir/src/poseidon2.nr`
- Modify: `provekit/verifier-noir/src/main.nr`

**Outcome:** A `permute(state: [Field; 4]) -> [Field; 4]` helper backed by `std::hash::poseidon2_permutation`, and a Noir `#[test]` asserting the output for `[1, 2, 3, 4]` matches a frozen expected value.

The frozen expected value is **computed by Task 4**. For this task, we use a deliberately wrong placeholder (`[0; 4]`) so the test fails first, then update it after running through the Rust crate.

- [ ] **Step 1: Write the failing in-circuit test.**

Create `provekit/verifier-noir/src/poseidon2.nr`:

```noir
//! Thin wrapper over Noir's stdlib BN254 Poseidon2 permutation.
//!
//! The state shape and permutation parameters match the Rust `poseidon2`
//! workspace crate at the same input — see the cross-implementation KAT in
//! `provekit/verifier-noir-test/tests/poseidon2_kat.rs` for the bit-for-bit
//! guarantee.

use std::hash::poseidon2_permutation;

/// Apply one round of the BN254 Poseidon2 permutation to a 4-lane state.
pub fn permute(state: [Field; 4]) -> [Field; 4] {
    poseidon2_permutation(state, 4)
}

// --- in-circuit KAT ---
//
// EXPECTED_PERMUTE_1234 is the output of Poseidon2 on [1, 2, 3, 4]. It is
// computed once by the Rust `poseidon2` crate (see Task 4) and frozen here.
// If Noir's stdlib permutation ever drifts from the Rust crate, this test
// fails — and the cross-impl KAT in `verifier-noir-test` fails alongside it.
//
// PLACEHOLDER VALUE — overwritten in Task 4 step 3 after running the
// Rust-side computation. The test below is expected to FAIL until then.
global EXPECTED_PERMUTE_1234: [Field; 4] = [0, 0, 0, 0];

#[test]
fn permutation_1234_matches_frozen_kat() {
    let input: [Field; 4] = [1, 2, 3, 4];
    let output = permute(input);
    assert(output == EXPECTED_PERMUTE_1234);
}
```

- [ ] **Step 2: Declare the module in main.nr.**

Modify `provekit/verifier-noir/src/main.nr`:

```noir
// ProveKit Noir Recursive Verifier
//
// Verifies a ProveKit WHIR+Spartan proof generated under HashConfig::Poseidon2.
// See docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md
//
// Phase 1A: crate skeleton + Poseidon2 wrapper. Other modules land later.

mod poseidon2;

fn main() {}
```

- [ ] **Step 3: Run `nargo test` and verify the KAT FAILS (placeholder value).**

Run: `cd provekit/verifier-noir && nargo test poseidon2 2>&1 | tail -15 && cd ../..`
Expected: 1 failed test (`permutation_1234_matches_frozen_kat`) — the placeholder `[0; 4]` doesn't match the real permutation output. The failure proves the test is wired correctly and ready for Task 4 to fill in the correct value.

- [ ] **Step 4: Commit (with the failing KAT).**

```bash
git add provekit/verifier-noir/src/poseidon2.nr provekit/verifier-noir/src/main.nr
git commit -m "feat(verifier-noir): add poseidon2 wrapper with placeholder KAT"
```

The failing test is intentional — Task 4 generates the real expected value from the Rust crate and unfreezes the KAT.

---

## Task 4: Cross-impl KAT (Rust ↔ Noir bit-for-bit)

**Files:**
- Create: `provekit/verifier-noir-test/Cargo.toml`
- Create: `provekit/verifier-noir-test/src/lib.rs`
- Create: `provekit/verifier-noir-test/tests/poseidon2_kat.rs`
- Modify: `Cargo.toml` (workspace root) — add the new crate to `members`
- Modify: `provekit/verifier-noir/src/poseidon2.nr` — replace the placeholder `EXPECTED_PERMUTE_1234` with the real value computed by the Rust crate

**Outcome:** A Cargo integration test that (a) computes Poseidon2 on `[1, 2, 3, 4]` via the Rust `poseidon2` crate, (b) shells out to `nargo test` in the verifier-noir crate, (c) asserts both implementations agreed by virtue of `nargo test` exiting 0 with the Noir-side `EXPECTED_PERMUTE_1234` matching the Rust output.

- [ ] **Step 1: Create the sibling Cargo test crate manifest.**

Create `provekit/verifier-noir-test/Cargo.toml`:

```toml
[package]
name = "provekit-verifier-noir-test"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
authors.workspace = true
license.workspace = true
homepage.workspace = true
repository.workspace = true
publish = false

[dependencies]
poseidon2.workspace = true
ark-bn254.workspace = true
ark-ff.workspace = true

[dev-dependencies]
anyhow.workspace = true

[lints]
workspace = true
```

- [ ] **Step 2: Add the new crate to the workspace.**

Modify the workspace `Cargo.toml` at the repo root. Find the `[workspace] members = [...]` array and add `"provekit/verifier-noir-test"` in alphabetical order with the existing `provekit/*` entries.

Verify the addition is well-formed:

Run: `cargo metadata --format-version 1 --no-deps 2>&1 | head -5`
Expected: valid JSON (not an error). If it errors out, fix the Cargo.toml syntax before continuing.

- [ ] **Step 3: Generate the expected Poseidon2 output and unfreeze the Noir KAT.**

Create `provekit/verifier-noir-test/src/lib.rs`:

```rust
//! Test-only library exposing fixed Poseidon2 KAT inputs / outputs so the
//! Cargo and Nargo sides can reference the same constants.

use {ark_bn254::Fr, ark_ff::PrimeField};

/// KAT input for cross-implementation Poseidon2 permutation testing.
pub fn kat_input() -> [Fr; 4] {
    [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)]
}

/// Compute the expected output by running the Rust `poseidon2` crate.
pub fn kat_expected() -> [Fr; 4] {
    poseidon2::permutation::poseidon2_permutation(&kat_input())
}

/// Render a field element as a Noir-compatible decimal literal.
pub fn fr_to_noir_literal(fe: Fr) -> String {
    fe.into_bigint().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Print the four field elements that Noir's
    /// `EXPECTED_PERMUTE_1234` global should hold. Run with `--nocapture`
    /// to capture them; paste into `verifier-noir/src/poseidon2.nr` in
    /// step 4 below.
    #[test]
    fn print_kat_expected_for_noir() {
        let expected = kat_expected();
        for (i, fe) in expected.iter().enumerate() {
            println!("EXPECTED_PERMUTE_1234[{i}] = {}", fr_to_noir_literal(*fe));
        }
    }
}
```

Run: `cargo test -p provekit-verifier-noir-test print_kat_expected_for_noir -- --nocapture 2>&1 | grep EXPECTED`
Expected: four lines of the form `EXPECTED_PERMUTE_1234[i] = <decimal>`. Copy these four decimal values; step 4 pastes them into the Noir global.

- [ ] **Step 4: Patch `provekit/verifier-noir/src/poseidon2.nr` with the real values.**

Open `provekit/verifier-noir/src/poseidon2.nr` and replace the `global EXPECTED_PERMUTE_1234` line with the four decimal values from step 3. Example shape (the actual digits come from step 3 output):

```noir
global EXPECTED_PERMUTE_1234: [Field; 4] = [
    <decimal from step 3 line 0>,
    <decimal from step 3 line 1>,
    <decimal from step 3 line 2>,
    <decimal from step 3 line 3>,
];
```

- [ ] **Step 5: Re-run `nargo test` to verify the in-circuit KAT now PASSES.**

Run: `cd provekit/verifier-noir && nargo test poseidon2 2>&1 | tail -10 && cd ../..`
Expected: `1 passed; 0 failed`. The Noir stdlib permutation agrees with the Rust crate's permutation on this fixed input.

- [ ] **Step 6: Write the Cargo-side integration test that runs `nargo test`.**

Create `provekit/verifier-noir-test/tests/poseidon2_kat.rs`:

```rust
//! Cross-implementation Poseidon2 KAT.
//!
//! 1. Compute the Poseidon2 permutation output for a fixed `[Fr; 4]` input
//!    via the Rust `poseidon2` workspace crate.
//! 2. Shell out to `nargo test poseidon2` in the sibling Noir crate.
//!    That test asserts the stdlib permutation produces the same four
//!    field elements (frozen as Noir `global` constants in `poseidon2.nr`).
//! 3. Passing means both implementations agree on this KAT input.

use {
    provekit_verifier_noir_test::{kat_expected, kat_input},
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_kat_agrees() {
    // Sanity: Rust side computes a deterministic output.
    let a = kat_expected();
    let b = poseidon2::permutation::poseidon2_permutation(&kat_input());
    assert_eq!(a, b, "Rust poseidon2 crate is non-deterministic on the KAT input");

    // Locate the verifier-noir crate (two directories up from CARGO_MANIFEST_DIR).
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

    // Run `nargo test poseidon2` in that crate.
    let status = Command::new("nargo")
        .args(["test", "poseidon2"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo — is it on PATH?");

    assert!(
        status.success(),
        "nargo test poseidon2 failed (exit code {:?}). \
         The Noir stdlib permutation disagreed with the Rust poseidon2 crate's output \
         on input {:?}. Re-run step 3 in Phase 1A Task 4 to regenerate the expected values.",
        status.code(),
        kat_input(),
    );
}
```

- [ ] **Step 7: Run the Cargo-side cross-impl test and verify it passes.**

Run: `cargo test -p provekit-verifier-noir-test --test poseidon2_kat 2>&1 | tail -10`
Expected: `test result: ok. 1 passed`.

If it fails because nargo isn't on PATH in the test environment, the failure message says so explicitly — that's a CI environment issue, not a code issue.

- [ ] **Step 8: Commit.**

```bash
git add provekit/verifier-noir-test/ provekit/verifier-noir/src/poseidon2.nr Cargo.toml
git commit -m "test(verifier-noir): cross-impl Poseidon2 KAT (Rust crate ↔ Noir stdlib)"
```

---

## What Phase 1A leaves behind

- `provekit-cli generate-noir-inputs <pkv> <np>` accepts args and returns Ok. **No codegen logic yet.** Phase 2 fills this in.
- `provekit/verifier-noir/` compiles via `nargo check` and `nargo test`.
- `poseidon2.nr` exposes `permute([Field; 4]) -> [Field; 4]` and proves bit-for-bit agreement with the Rust `poseidon2` crate on a fixed input.
- `provekit/verifier-noir-test/` exists as the Cargo test home for things that need to invoke `nargo` from Rust.

## What Phase 1B will cover (next plan)

- `sponge.nr` — byte-oriented duplex sponge mirroring spongefish's `DuplexSponge<Poseidon2Wrapper, 128, 96>` (state 4 lanes, rate 3 lanes, capacity 1 lane).
- `transcript.nr` — high-level `absorb_field` / `squeeze_field` / `squeeze_challenge_bytes_n` / `init_from_pre_absorbed_state`.
- Cross-impl sponge KAT (same shape as Task 4 here) — replay an absorb/squeeze sequence through both implementations and assert byte-equal output.
- Cross-impl transcript test — init from a real prover-side post-domain-separator state, absorb/squeeze a synthetic sequence, assert agreement.

Phase 1B requires reading `spongefish/src/duplex_sponge.rs` carefully (exact byte-write semantics of `absorb` into the rate region, behavior at partial-block boundaries, `ratchet` semantics). That reading happens at Phase 1B implementation time, not now.

## What's deliberately out of scope for Phase 1

- `merkle.nr`, `sumcheck.nr`, `matrix_eval.nr`, `public_input.nr` (Phase 2)
- `whir.nr` (Phase 3)
- `types.nr` / `matrices.nr` codegen output (Phase 2)
- End-to-end `nargo execute` against a real proof (Phase 3)
- One-wrap recursion + <1 min stretch measurement (Phase 4)
