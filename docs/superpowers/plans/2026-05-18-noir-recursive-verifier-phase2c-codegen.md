# Noir Recursive Verifier — Phase 2C: Codegen Tool

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Spec:** [`docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md`](../specs/2026-05-18-noir-recursive-verifier-design.md)
**Predecessor:** [Phase 2B — Matrix + Public-Input](./2026-05-18-noir-recursive-verifier-phase2b-matrix-public-input.md)

**Goal:** Land the Rust-side codegen pipeline so the integrated Phase 3 verifier (`whir.nr` + `main.nr`) has the inputs it needs:

1. `provekit-cli generate-noir-inputs` deserializes `.pkv` + `.np` (postcard) and validates the contents.
2. Emits `provekit/verifier-noir/src/types.nr` — compile-time constants from the WHIR scheme.
3. Emits `provekit/verifier-noir/src/matrices.nr` — sparse A/B/C triples from the R1CS.
4. End-to-end smoke test: `prepare → prove → generate-noir-inputs → nargo check` passes on `noir-examples/poseidon2` with `--hash poseidon2`.

**Architecture:**
- Pure Rust work — no new Noir modules.
- Emitters are deterministic functions: `(Verifier, NoirProof) -> String`. The CLI subcommand wires them to filesystem I/O.
- Each emitted file goes through `nargo check` as the acceptance gate.
- `Prover.toml` emission is **deferred to Phase 3** (we don't know the integrated `main.nr` input signature yet; Phase 3 will define it).

**Tech Stack:** Rust workspace (postcard via `provekit_common::file::read`), `provekit-common` types (`Verifier`, `NoirProof`, `WhirR1CSScheme`, `R1CS`, `SparseMatrix`), Noir 1.0.0-beta.19.

---

## What's emitted vs deferred

**Emitted in Phase 2C:**
- `types.nr` with `global` declarations: `M`, `M_0`, `NUM_PUBLIC_INPUTS`, `NUM_CHALLENGES`, `NUM_CONSTRAINTS`, `NUM_WITNESSES`, `LOG_NUM_CONSTRAINTS`, `LOG_NUM_WITNESSES`.
- `matrices.nr` with `global A_TRIPLES`, `global B_TRIPLES`, `global C_TRIPLES` (each typed `[SparseTriple; N]`).

**Deferred to Phase 3:**
- `Prover.toml` (depends on `main.nr` input signature, which depends on `whir.nr`).
- WHIR-specific constants (round counts, OOD samples, query counts, folding factor) — those land in `types.nr` when Phase 3 wires up `whir.nr`.

---

## File map

```
MOD    tooling/cli/src/cmd/generate_noir_inputs.rs    (deserialize + emit logic)
MOD    tooling/cli/Cargo.toml                          (may need new dep on provekit-prover for proof loading)
NEW    provekit/verifier-noir/src/types.nr             (codegen OUTPUT — created via the tool, not hand-edited)
NEW    provekit/verifier-noir/src/matrices.nr          (codegen OUTPUT)
MOD    provekit/verifier-noir/src/main.nr              (declare mod types; mod matrices; — to make them compile-tested by nargo)
MOD    .gitignore                                       (ignore provekit/verifier-noir/Prover.toml since nargo auto-creates it)
```

---

## Task 1: Deserialize and dump scheme summary

**Files:**
- Modify: `tooling/cli/src/cmd/generate_noir_inputs.rs` — replace the scaffold's `eprintln!` with real deserialization

**Outcome:** `provekit-cli generate-noir-inputs <pkv> <np>` reads both files via `provekit_common::file::read`, prints a scheme summary (m, m_0, num_public_inputs, num_challenges, num_constraints, num_witnesses, num_nonzeros for A/B/C) to stdout, and exits 0. Invalid inputs cause `anyhow::Result` errors.

### Steps

- [ ] **Step 1: Generate a real .pkv + .np pair for testing.**

Run from `/Users/paradox/Desktop/projects/provekit`:

```bash
cd noir-examples/poseidon2 && nargo compile 2>&1 | tail -3 && cd ../..
mkdir -p /tmp/p2-codegen-test
./target/release/provekit-cli prepare noir-examples/poseidon2 \
    --hash poseidon2 \
    --pkp /tmp/p2-codegen-test/poseidon2.pkp \
    --pkv /tmp/p2-codegen-test/poseidon2.pkv 2>&1 | tail -10
```

Expected: `nargo compile` exits 0, `prepare` writes the two key files. If `prepare` fails citing "unknown hash" or similar, Poseidon2 isn't wired into the CLI's `--hash` flag yet — STOP and report.

Then produce a proof:

```bash
./target/release/provekit-cli prove \
    /tmp/p2-codegen-test/poseidon2.pkp \
    noir-examples/poseidon2/Prover.toml \
    --out /tmp/p2-codegen-test/poseidon2.np 2>&1 | tail -10
```

Expected: writes `.np`. Save these paths for testing.

If `provekit-cli` isn't built, run `cargo build -p provekit-cli --release` first.

- [ ] **Step 2: Replace the scaffold's `run()` body with real deserialization.**

Open `tooling/cli/src/cmd/generate_noir_inputs.rs`. Current `Command::run` body:

```rust
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
```

Replace with:

```rust
impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let verifier: Verifier = provekit_common::file::read(&self.verifier_path)
            .with_context(|| format!("reading PKV from {}", self.verifier_path.display()))?;
        let proof: NoirProof = provekit_common::file::read(&self.proof_path)
            .with_context(|| format!("reading NP from {}", self.proof_path.display()))?;

        let scheme = verifier
            .whir_for_witness
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("PKV has no WHIR scheme (Mavros only?)"))?;

        let nonzeros = nonzero_counts(&verifier.r1cs);

        println!("scheme summary:");
        println!("  hash_config       = {}", verifier.hash_config);
        println!("  m                 = {}", scheme.m);
        println!("  m_0               = {}", scheme.m_0);
        println!("  w1_size           = {}", scheme.w1_size);
        println!("  num_challenges    = {}", scheme.num_challenges);
        println!("  has_public_inputs = {}", scheme.has_public_inputs);
        println!("  num_constraints   = {}", verifier.r1cs.num_constraints());
        println!("  num_witnesses     = {}", verifier.r1cs.num_witnesses());
        println!("  num_public_inputs = {}", verifier.r1cs.num_public_inputs);
        println!("  nonzeros A/B/C    = {}/{}/{}", nonzeros.0, nonzeros.1, nonzeros.2);
        println!("  proof narg bytes  = {}", proof.whir_r1cs_proof.narg_string.len());
        println!("  proof hint bytes  = {}", proof.whir_r1cs_proof.hints.len());
        println!("  public inputs len = {}", proof.public_inputs.len());

        anyhow::ensure!(
            verifier.hash_config == provekit_common::HashConfig::Poseidon2,
            "PKV hash_config is {}, but generate-noir-inputs only supports Poseidon2 for v0",
            verifier.hash_config
        );

        Ok(())
    }
}

/// Count non-zero entries in each of the R1CS A, B, C matrices.
fn nonzero_counts(r1cs: &provekit_common::R1CS) -> (usize, usize, usize) {
    let a = matrix_nonzeros(&r1cs.a, r1cs);
    let b = matrix_nonzeros(&r1cs.b, r1cs);
    let c = matrix_nonzeros(&r1cs.c, r1cs);
    (a, b, c)
}

fn matrix_nonzeros(
    m: &provekit_common::SparseMatrix,
    r1cs: &provekit_common::R1CS,
) -> usize {
    (0..m.num_rows)
        .map(|row| m.hydrate(&r1cs.interner).iter_row(row).count())
        .sum()
}
```

Update the `use` block at the top:

```rust
use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{NoirProof, Verifier},
    std::path::PathBuf,
    tracing::instrument,
};
```

- [ ] **Step 3: Update the unit test to reflect the new behavior.**

Replace the existing `scaffold_run_returns_ok` test. The new behavior FAILS on a non-existent path, so the unit test needs adjustment. Replace the `#[cfg(test)] mod tests` block with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_fails_on_missing_files() {
        let args = Args {
            verifier_path: PathBuf::from("/tmp/does-not-exist.pkv"),
            proof_path: PathBuf::from("/tmp/does-not-exist.np"),
            out_dir: PathBuf::from("/tmp/out"),
        };
        assert!(args.run().is_err());
    }
}
```

- [ ] **Step 4: Build and run unit test.**

Run: `cargo build -p provekit-cli --release 2>&1 | tail -10`
Expected: clean build. If `Verifier` or `NoirProof` import fails, check the workspace `provekit-common` exports.

Run: `cargo test -p provekit-cli generate_noir_inputs 2>&1 | tail -10`
Expected: 1 passed.

- [ ] **Step 5: Smoke-test with the real .pkv / .np from Step 1.**

Run:

```bash
./target/release/provekit-cli generate-noir-inputs \
    /tmp/p2-codegen-test/poseidon2.pkv \
    /tmp/p2-codegen-test/poseidon2.np 2>&1
```

Expected: scheme summary printed to stdout with non-zero values for `m`, `m_0`, `num_witnesses`, `num_constraints`, `num_public_inputs` (≥ 8 for the poseidon2 example with 4-Field input + 4-Field output). Exit 0.

- [ ] **Step 6: Commit.**

```bash
cd /Users/paradox/Desktop/projects/provekit
git add tooling/cli/src/cmd/generate_noir_inputs.rs
git commit -m "feat(cli): generate-noir-inputs reads .pkv + .np, prints scheme summary"
```

Conventional Commits. NO `Co-Authored-By: Claude` trailer.

---

## Task 2: Emit `types.nr`

**Files:**
- Modify: `tooling/cli/src/cmd/generate_noir_inputs.rs` — add `emit_types_nr` function + write to `<out_dir>/src/types.nr`
- Modify: `provekit/verifier-noir/src/main.nr` — declare `mod types;` (so the new module is compile-tested)
- Create: `provekit/verifier-noir/src/types.nr` (via the tool)

**Outcome:** `provekit-cli generate-noir-inputs ...` produces a `provekit/verifier-noir/src/types.nr` file with `global` declarations for the scheme constants. The file is `nargo check`-clean. The CLI is idempotent: re-running produces an identical file.

### Steps

- [ ] **Step 1: Add `emit_types_nr` to `generate_noir_inputs.rs`.**

Below the `nonzero_counts` helpers, add:

```rust
fn emit_types_nr(verifier: &Verifier, scheme: &provekit_common::WhirR1CSScheme) -> String {
    let num_constraints = verifier.r1cs.num_constraints();
    let num_witnesses = verifier.r1cs.num_witnesses();
    let num_public_inputs = verifier.r1cs.num_public_inputs;
    let log_constraints = num_constraints.next_power_of_two().trailing_zeros();
    let log_witnesses = num_witnesses.next_power_of_two().trailing_zeros();

    format!(
        "// AUTO-GENERATED by `provekit-cli generate-noir-inputs`.
// DO NOT EDIT - re-run the codegen tool to regenerate.
//
// Compile-time constants for the v0 inner circuit. Tied to a specific
// `.pkv` (verifier key) shape; regenerate after any scheme change.

global M: u32 = {m};
global M_0: u32 = {m_0};
global W1_SIZE: u32 = {w1_size};
global NUM_CHALLENGES: u32 = {num_challenges};
global NUM_PUBLIC_INPUTS: u32 = {num_public_inputs};
global NUM_CONSTRAINTS: u32 = {num_constraints};
global NUM_WITNESSES: u32 = {num_witnesses};
global LOG_NUM_CONSTRAINTS: u32 = {log_constraints};
global LOG_NUM_WITNESSES: u32 = {log_witnesses};
",
        m = scheme.m,
        m_0 = scheme.m_0,
        w1_size = scheme.w1_size,
        num_challenges = scheme.num_challenges,
        num_public_inputs = num_public_inputs,
        num_constraints = num_constraints,
        num_witnesses = num_witnesses,
        log_constraints = log_constraints,
        log_witnesses = log_witnesses,
    )
}
```

- [ ] **Step 2: Wire `emit_types_nr` into `run()`.**

Add after the scheme summary `println!`s and the `ensure!`:

```rust
        // Emit types.nr
        let src_dir = self.out_dir.join("src");
        std::fs::create_dir_all(&src_dir)
            .with_context(|| format!("creating {}", src_dir.display()))?;
        let types_path = src_dir.join("types.nr");
        let types_src = emit_types_nr(&verifier, scheme);
        std::fs::write(&types_path, &types_src)
            .with_context(|| format!("writing {}", types_path.display()))?;
        eprintln!("wrote {}", types_path.display());

        Ok(())
```

Update the top-level `use` block to add `std::fs` use only if not already present (it's not, but `std::fs::` works without an explicit `use`).

- [ ] **Step 3: Pre-emit a placeholder `types.nr` and wire it into `main.nr`.**

Before running the tool, create a placeholder `provekit/verifier-noir/src/types.nr` with one global so `nargo check` doesn't error on the empty file when the new module is declared:

```noir
// Placeholder; overwritten by `provekit-cli generate-noir-inputs`.
global M: u32 = 0;
```

Modify `provekit/verifier-noir/src/main.nr`. Current head:

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

Replace with:

```noir
// ProveKit Noir Recursive Verifier
//
// Verifies a ProveKit WHIR+Spartan proof generated under HashConfig::Poseidon2.
// See docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md
//
// Phase 2C: + codegen-emitted `types` module. Full integration lands in Phase 3.

mod poseidon2;
mod sponge;
mod transcript;
mod merkle;
mod sumcheck;
mod matrix_eval;
mod public_input;

mod types;

fn main() {}
```

- [ ] **Step 4: Build + run end-to-end.**

```bash
cargo build -p provekit-cli --release 2>&1 | tail -5
./target/release/provekit-cli generate-noir-inputs \
    /tmp/p2-codegen-test/poseidon2.pkv \
    /tmp/p2-codegen-test/poseidon2.np 2>&1
```

Expected: scheme summary + `wrote provekit/verifier-noir/src/types.nr`. Inspect the file:

```bash
head -20 provekit/verifier-noir/src/types.nr
```

Expected: ASCII Noir source with non-zero globals.

- [ ] **Step 5: Confirm `nargo check` passes.**

```bash
cd provekit/verifier-noir && nargo check 2>&1 | tail -5 && cd ../..
```

Expected: clean check (the unused-global warnings for individual constants are fine — nothing references them yet).

- [ ] **Step 6: Re-run idempotency check.**

```bash
md5sum provekit/verifier-noir/src/types.nr
./target/release/provekit-cli generate-noir-inputs \
    /tmp/p2-codegen-test/poseidon2.pkv \
    /tmp/p2-codegen-test/poseidon2.np 2>&1 | tail -3
md5sum provekit/verifier-noir/src/types.nr
```

Expected: both md5sums equal.

- [ ] **Step 7: Commit.**

```bash
git add tooling/cli/src/cmd/generate_noir_inputs.rs \
        provekit/verifier-noir/src/main.nr \
        provekit/verifier-noir/src/types.nr
git commit -m "feat(cli): emit types.nr from .pkv via generate-noir-inputs"
```

Conventional Commits. NO Claude trailer.

---

## Task 3: Emit `matrices.nr`

**Files:**
- Modify: `tooling/cli/src/cmd/generate_noir_inputs.rs` — add `emit_matrices_nr` function
- Modify: `provekit/verifier-noir/src/main.nr` — declare `mod matrices;`
- Create: `provekit/verifier-noir/src/matrices.nr` (via the tool)

**Outcome:** The tool also writes `matrices.nr` with `A_TRIPLES`, `B_TRIPLES`, `C_TRIPLES` `global` arrays of `SparseTriple`s, sized to the actual nonzero count for the inner circuit. `nargo check` passes.

### Steps

- [ ] **Step 1: Add `emit_matrices_nr` to `generate_noir_inputs.rs`.**

```rust
fn emit_matrices_nr(verifier: &Verifier) -> String {
    let mut out = String::new();
    out.push_str(
        "// AUTO-GENERATED by `provekit-cli generate-noir-inputs`.
// DO NOT EDIT - re-run the codegen tool to regenerate.
//
// Sparse triples for the v0 inner circuit's R1CS A/B/C matrices.

use crate::matrix_eval::SparseTriple;

",
    );

    emit_matrix(&mut out, "A_TRIPLES", &verifier.r1cs.a, &verifier.r1cs);
    out.push('\n');
    emit_matrix(&mut out, "B_TRIPLES", &verifier.r1cs.b, &verifier.r1cs);
    out.push('\n');
    emit_matrix(&mut out, "C_TRIPLES", &verifier.r1cs.c, &verifier.r1cs);

    out
}

fn emit_matrix(
    out: &mut String,
    name: &str,
    matrix: &provekit_common::SparseMatrix,
    r1cs: &provekit_common::R1CS,
) {
    let hydrated = matrix.hydrate(&r1cs.interner);
    let mut triples: Vec<(usize, usize, provekit_common::FieldElement)> = Vec::new();
    for row in 0..matrix.num_rows {
        for (col, val) in hydrated.iter_row(row) {
            triples.push((row, col, val));
        }
    }

    out.push_str(&format!(
        "pub global {name}: [SparseTriple; {n}] = [\n",
        n = triples.len()
    ));
    for (row, col, val) in &triples {
        out.push_str(&format!(
            "    SparseTriple {{ row: {row}, col: {col}, val: {val_dec} }},\n",
            val_dec = field_to_decimal(*val)
        ));
    }
    out.push_str("];\n");
}

fn field_to_decimal(fe: provekit_common::FieldElement) -> String {
    use ark_ff::PrimeField;
    fe.into_bigint().to_string()
}
```

- [ ] **Step 2: Add `ark_ff` to `tooling/cli/Cargo.toml`** if not already a dependency:

```bash
grep ark-ff /Users/paradox/Desktop/projects/provekit/tooling/cli/Cargo.toml
```

If absent, add `ark-ff.workspace = true` to `[dependencies]`. (It's a workspace dep; already used by `provekit-common`.)

- [ ] **Step 3: Wire emission into `run()`.**

Add below the `types.nr` write:

```rust
        let matrices_path = src_dir.join("matrices.nr");
        let matrices_src = emit_matrices_nr(&verifier);
        std::fs::write(&matrices_path, &matrices_src)
            .with_context(|| format!("writing {}", matrices_path.display()))?;
        eprintln!("wrote {}", matrices_path.display());
```

- [ ] **Step 4: Pre-emit placeholder `matrices.nr` + declare in main.nr.**

Create `provekit/verifier-noir/src/matrices.nr` with:

```noir
// Placeholder; overwritten by `provekit-cli generate-noir-inputs`.
use crate::matrix_eval::SparseTriple;

pub global A_TRIPLES: [SparseTriple; 1] = [SparseTriple { row: 0, col: 0, val: 0 }];
pub global B_TRIPLES: [SparseTriple; 1] = [SparseTriple { row: 0, col: 0, val: 0 }];
pub global C_TRIPLES: [SparseTriple; 1] = [SparseTriple { row: 0, col: 0, val: 0 }];
```

Add `mod matrices;` to `main.nr` after `mod types;`.

- [ ] **Step 5: Build + run end-to-end.**

```bash
cargo build -p provekit-cli --release 2>&1 | tail -5
./target/release/provekit-cli generate-noir-inputs \
    /tmp/p2-codegen-test/poseidon2.pkv \
    /tmp/p2-codegen-test/poseidon2.np 2>&1
```

Expected: also writes `provekit/verifier-noir/src/matrices.nr`. Spot-check the head:

```bash
head -20 provekit/verifier-noir/src/matrices.nr
wc -l provekit/verifier-noir/src/matrices.nr
```

The line count depends on the inner circuit's R1CS size — for `noir-examples/poseidon2`, expect a few hundred to a few thousand lines.

- [ ] **Step 6: Confirm `nargo check` passes.**

```bash
cd provekit/verifier-noir && nargo check 2>&1 | tail -5 && cd ../..
```

Expected: clean check.

- [ ] **Step 7: Commit.**

```bash
git add tooling/cli/src/cmd/generate_noir_inputs.rs \
        tooling/cli/Cargo.toml \
        provekit/verifier-noir/src/main.nr \
        provekit/verifier-noir/src/matrices.nr
git commit -m "feat(cli): emit matrices.nr from .pkv via generate-noir-inputs"
```

Conventional Commits. NO Claude trailer.

---

## Task 4: End-to-end smoke test

**Files:**
- Create: `provekit/verifier-noir-test/tests/codegen_smoke.rs` — Cargo integration test that runs the full pipeline

**Outcome:** A Cargo test that:
1. Runs `provekit-cli prepare --hash poseidon2 noir-examples/poseidon2`.
2. Runs `provekit-cli prove`.
3. Runs `provekit-cli generate-noir-inputs`.
4. Runs `nargo check` on `provekit/verifier-noir/`.
5. Asserts all four exit 0.

This is the v0 regression gate for Phase 2C — any drift in scheme parsing, source emission, or Noir compilation surfaces here.

### Steps

- [ ] **Step 1: Create `provekit/verifier-noir-test/tests/codegen_smoke.rs`:**

```rust
//! End-to-end codegen smoke test.
//!
//! Pipeline:
//!   1. `provekit-cli prepare --hash poseidon2 noir-examples/poseidon2`
//!   2. `provekit-cli prove`
//!   3. `provekit-cli generate-noir-inputs`
//!   4. `nargo check` on provekit/verifier-noir
//!
//! Catches: postcard schema drift, Noir source emission bugs, type signature
//! breakage. Slow (~30s); run with `cargo test --test codegen_smoke -- --ignored`
//! if too slow for default CI.

use std::{
    env,
    path::PathBuf,
    process::Command,
};

/// Locate the project root (workspace root).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("CARGO_MANIFEST_DIR has two parents")
        .to_path_buf()
}

#[test]
fn codegen_pipeline_end_to_end() {
    let root = workspace_root();
    let cli = root.join("target/release/provekit-cli");
    if !cli.exists() {
        let status = Command::new("cargo")
            .args(["build", "-p", "provekit-cli", "--release"])
            .current_dir(&root)
            .status()
            .expect("cargo build failed to spawn");
        assert!(status.success(), "cargo build of provekit-cli failed");
    }

    let tmp = env::temp_dir().join("p2c-codegen-smoke");
    std::fs::create_dir_all(&tmp).expect("creating tmp dir");
    let pkp = tmp.join("poseidon2.pkp");
    let pkv = tmp.join("poseidon2.pkv");
    let np = tmp.join("poseidon2.np");

    // 1. prepare
    let status = Command::new(&cli)
        .args([
            "prepare",
            "noir-examples/poseidon2",
            "--hash",
            "poseidon2",
            "--pkp",
            pkp.to_str().unwrap(),
            "--pkv",
            pkv.to_str().unwrap(),
        ])
        .current_dir(&root)
        .status()
        .expect("prepare failed to spawn");
    assert!(status.success(), "prepare failed (exit {:?})", status.code());
    assert!(pkp.exists() && pkv.exists());

    // 2. prove
    let prover_toml = root.join("noir-examples/poseidon2/Prover.toml");
    let status = Command::new(&cli)
        .args([
            "prove",
            pkp.to_str().unwrap(),
            prover_toml.to_str().unwrap(),
            "--out",
            np.to_str().unwrap(),
        ])
        .current_dir(&root)
        .status()
        .expect("prove failed to spawn");
    assert!(status.success(), "prove failed (exit {:?})", status.code());
    assert!(np.exists());

    // 3. generate-noir-inputs
    let status = Command::new(&cli)
        .args([
            "generate-noir-inputs",
            pkv.to_str().unwrap(),
            np.to_str().unwrap(),
        ])
        .current_dir(&root)
        .status()
        .expect("generate-noir-inputs failed to spawn");
    assert!(
        status.success(),
        "generate-noir-inputs failed (exit {:?})",
        status.code()
    );

    // 4. nargo check
    let nargo_crate = root.join("provekit/verifier-noir");
    let status = Command::new("nargo")
        .args(["check"])
        .current_dir(&nargo_crate)
        .status()
        .expect("nargo check failed to spawn");
    assert!(
        status.success(),
        "nargo check failed (exit {:?}). \
         types.nr or matrices.nr emission produced invalid Noir source.",
        status.code()
    );
}
```

- [ ] **Step 2: Run the smoke test.**

Run: `cargo test -p provekit-verifier-noir-test --test codegen_smoke 2>&1 | tail -10`

Expected: 1 passed. (May take 30+ seconds for the first run including build, prepare, prove.)

- [ ] **Step 3: Full regression.**

Run: `cargo test -p provekit-verifier-noir-test 2>&1 | grep -E "^(test result|running)"`

Expected: 7 lib + 8 integration tests pass (the new codegen_smoke joins poseidon2/sponge/transcript/merkle/sumcheck/matrix_eval/public_input).

- [ ] **Step 4: Update `.gitignore`** (optional but recommended given Prover.toml will keep regenerating):

Add to root `.gitignore`:
```
/provekit/verifier-noir/Prover.toml
```

If a `.gitignore` already exists, just append; otherwise create one with that single line (and don't touch any other ignore patterns).

- [ ] **Step 5: Commit.**

```bash
git add provekit/verifier-noir-test/tests/codegen_smoke.rs .gitignore
git commit -m "test(verifier-noir): end-to-end codegen pipeline smoke test"
```

Conventional Commits. NO Claude trailer.

---

## What Phase 2C leaves behind

- `provekit-cli generate-noir-inputs` reads a real `.pkv` + `.np`, emits `types.nr` and `matrices.nr`, validates the Noir crate still compiles.
- End-to-end smoke test guards against drift.

## What Phase 3 will cover (next plan)

- `whir.nr` — the WHIR LDT verifier (the biggest remaining module).
- Integrated `main.nr` consuming all primitives + codegen-emitted `types.nr` + `matrices.nr`.
- Codegen extension for `Prover.toml` (now that `main.nr`'s input signature is known).
- End-to-end `nargo execute` on a real proof.

## Deliberately out of scope for Phase 2C

- `Prover.toml` emission — needs Phase 3's `main.nr` signature.
- WHIR-specific scheme constants (rounds, folding factor, query counts) — Phase 3 adds them to `types.nr`.
- Codegen optimization (matrix dedup, smaller emitted source) — premature.
