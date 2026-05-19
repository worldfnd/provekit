# ProveKit Noir Recursive Verifier — Design (Poseidon2, v0)

**Status:** approved (brainstorming).
**Next step:** writing-plans skill to produce the implementation plan.

## Goal

Build a Noir circuit that verifies a ProveKit WHIR+Spartan proof generated under `HashConfig::Poseidon2`, so a ProveKit proof can itself be recursively verified by another ProveKit proof.

**Two-stage delivery.** Inner circuit choice is driven by perf budget: a tiny inner for v0 to land correctness end-to-end fast, then `complete_age_check` for v1.

**v0 acceptance (inner: `noir-examples/basic-2`):**

1. `nargo execute --force` accepts a real Poseidon2-flavored proof of the `basic-2` example (`assert(a*b + c + d == 10)` — a single R1CS constraint, no public inputs).
2. The verifier circuit itself can be `prepare`d/`prove`d by `provekit-cli` and the resulting outer proof verified by the Rust verifier (one full wrap).
3. **Stretch perf target:** outer prove (recursive verification) completes in **under 1 minute on Darwin ARM64 (the dev system)**. Correctness wins over hitting this target — if we miss, we land correctness and open v0.1 for perf.

**v1 acceptance (inner: `complete_age_check`):**

1. Same as v0 but retargeted to `complete_age_check`. The existing `complete_age_check.np` / `.pkp` / `.pkv` at the repo root are Skyscraper-flavored; v1 must regenerate them under `--hash poseidon2` first.
2. Adds the multi-commitment / LogUp-challenge code path (Phase 1 second commitment, Phase 4 challenge binding), which `poseidon2` doesn't exercise.
3. Likely needs at least one round of verifier-circuit optimization to remain in human-tolerable prove time. <1 min is aspirational, not blocking.

### Why `basic-2` for v0 over `poseidon2`

**Updated 2026-05-19:** Original choice was `poseidon2` (4-field pub input + 4-field pub output) because it exercises the public-input binding path. Measurement showed `basic-2` is dramatically smaller (1 R1CS constraint vs 268, w1_size 5 vs 276), giving a much better shot at the <1 min stretch target. The trade-off: `basic-2` has `has_public_inputs = false`, so the integrated `main.nr` doesn't exercise `verify_public_input_hash` / `verify_public_eval`. Those modules are already individually verified via Phase 2B cross-impl KATs, so this isn't a soundness gap — just less end-to-end coverage. v1 (`complete_age_check`) re-exercises the public-input path.

## Non-goals (v0)

- Generic over inner-circuit shape. The verifier is fixed-shape per inner circuit; changing the inner circuit requires re-running codegen.
- Hash flavors other than Poseidon2. No runtime hash selection in Noir.
- Two or more nested levels of recursion. One wrap only.
- **Multi-commitment / LogUp branch.** Deferred to v1. The `poseidon2` example has no lookups, so `num_challenges == 0` and we land only the single-commitment Phase-1/4 paths. The branch is **stubbed** with `assert(NUM_CHALLENGES == 0)` in v0, not implemented.
- Production-grade circuit-size optimization beyond the obvious cheap wins. Correctness first, optimization later.

## Inputs to the design (from spec sources)

The Noir verifier mirrors the Rust verifier at `provekit/verifier/src/whir_r1cs.rs` and uses the Poseidon2 spec landed in PR #412:

- **Transcript sponge** (`provekit/common/src/poseidon2/sponge.rs`):
  BN254 Poseidon2 permutation over `[Fr; 4]`; byte-oriented `DuplexSponge<Poseidon2Wrapper, 128, 96>` — state 4 lanes × 32 bytes = 128 B, rate 3 lanes (96 B), capacity 1 lane (32 B). Each 32-byte chunk is decoded LE mod p before permutation and re-encoded LE after.
- **Merkle / one-shot hash** (`provekit/common/src/poseidon2/whir.rs` + `poseidon2::poseidon2_hash_bytes`):
  Same permutation, length-IV variant: capacity lane seeded with `IV = num_fes * 2^64`, output is `state[0]` after final permutation. Messages must be a positive multiple of 32 bytes; up to 3 elements absorbed per permutation.
- **Public-input instance hash** (`provekit/common/src/hash_config.rs::hash_poseidon2`):
  Domain-separation tag `PUBLIC_INPUTS_DST_FE = SHA256("PROVEKIT_PUBLIC_INPUTS_V1") mod p`, prepended to the public-input slice, then `poseidon2::poseidon2_hash` (same length-IV one-shot).

## Architecture

### Repository layout

```
provekit/verifier-noir/
  Nargo.toml
  Prover.toml                   ← codegen output (per proof)
  src/
    main.nr
    types.nr                    ← codegen output (per inner circuit)
    matrices.nr                 ← codegen output (per inner circuit)
    poseidon2.nr
    sponge.nr
    transcript.nr
    merkle.nr
    sumcheck.nr
    matrix_eval.nr
    public_input.nr
    whir.nr
  tests/                        ← in-circuit unit tests (KATs)

tooling/cli/src/cmd/generate_noir_inputs.rs   ← new subcommand
```

### Module responsibilities

| Module | Responsibility |
|---|---|
| `types.nr` | Compile-time `global` constants per inner circuit: `M`, `M_0`, `NUM_PUBLIC_INPUTS`, `NUM_WHIR_ROUNDS`, `FOLDING_FACTOR`, `OOD_SAMPLES`, query counts, Merkle tree heights, `NUM_CHALLENGES`, `W1_SIZE`, etc. Codegen output. |
| `matrices.nr` | Sparse A/B/C triples for this inner circuit. Codegen output. |
| `poseidon2.nr` | Thin wrapper over `std::hash::poseidon2_permutation`: `permute(state: [Field; 4]) -> [Field; 4]`. |
| `sponge.nr` | Byte-oriented duplex sponge mirroring `Poseidon2Sponge`: state `[Field; 4]`, rate 3 lanes, capacity 1 lane. `absorb_bytes`, `squeeze_bytes`, `ratchet`. Re-encodes bytes ↔ field per the Rust adapter (LE, mod p). |
| `transcript.nr` | Higher-level `absorb_field`, `squeeze_field`, `squeeze_challenge_bytes_n`; `init_from_pre_absorbed_state` that takes the codegen-supplied initial state. |
| `merkle.nr` | `poseidon2_length_iv_hash(elements: [Field; N]) -> Field` with `state[3] = N * 2^64`; `verify_path(leaf, siblings, index, root)`. |
| `sumcheck.nr` | Spartan sumcheck verifier: m_0 rounds of cubic poly h_i, assert `h_i(0) + h_i(1) == saved`, return `(r, alpha, blinding_eval, f_at_alpha)`. |
| `matrix_eval.nr` | Reads `matrices.nr` and computes `az_at_alpha`, `bz_at_alpha`, `cz_at_alpha` via transposed-matrix · `eq(alpha, ·)` evaluation. Prefix covector helpers for public/blinding/challenge weights. |
| `public_input.nr` | `verify_public_input_hash`: assert `prover_msg == poseidon2_length_iv_hash([DST_FE] ++ public_inputs)`. `verify_public_eval`: assert `public_eval == 1 + Σ x^i · pi_i`. |
| `whir.nr` | zkWHIR LDT verifier: STIR fold, OOD samples, query phase, Merkle openings. v0 handles commitment 1 only (single-commitment path); commitment 2 / LogUp paths land in v1. |
| `main.nr` | Orchestrates phases 0–7 below; holds the public-input boundary. |

### Approach choice (recorded)

- **Architecture:** per-phase module split (vs monolithic / trait-shaped).
- **Poseidon2 in-circuit impl:** stdlib `std::hash::poseidon2_permutation` + KAT test.
- **R1CS matrices:** baked as constants per inner circuit by codegen.
- **Outer public inputs:** inner public inputs verbatim.
- **Pre-absorbed sponge state:** computed by codegen tool in Rust and passed as private witness (avoids reimplementing postcard + SHA inside the circuit; soundness preserved by downstream instance-hash binding).

## Data flow

```
            ┌──────────────────────────────────────────────────────────┐
            │  provekit-cli generate-noir-inputs <pkv> <np>            │
            │                                                          │
            │   reads .pkv  → scheme constants (m, m_0, …)             │
            │   reads .np   → narg_string + hints                      │
            │   replays init absorb (protocol_id || instance)          │
            │                                                          │
            │   emits:                                                 │
            │     verifier-noir/src/types.nr                           │
            │     verifier-noir/src/matrices.nr                        │
            │     verifier-noir/Prover.toml                            │
            └──────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌───────────────────────────────────────────────────────────────────────┐
│ Noir circuit (verifier-noir/src/main.nr)                              │
│                                                                       │
│ Phase 0  init sponge from pre_absorbed_state              [priv]      │
│                                                                       │
│ Phase 1  absorb initial_root || initial_ood_answers                   │
│          if NUM_CHALLENGES > 0:                                       │
│              squeeze logup_challenges                                 │
│              absorb commitment_2_root || ood_answers_2                │
│                                                                       │
│ Phase 2  Spartan sumcheck (sumcheck.nr)                               │
│          squeeze r ∈ Field^{m_0}                                      │
│          absorb sum_g; squeeze rho                                    │
│          for i in 0..m_0:                                             │
│            absorb h_i ∈ Field^4                                       │
│            squeeze alpha_i                                            │
│            assert h_i(0) + h_i(1) == saved                            │
│          absorb blinding_eval                                         │
│          ⇒ (r, alpha, blinding_eval, f_at_alpha)                      │
│                                                                       │
│ Phase 3  public-input binding (public_input.nr)                       │
│          absorb public_inputs_hash                                    │
│          assert public_inputs_hash == poseidon2(DST_FE || publics)    │
│          squeeze x                                                    │
│                                                                       │
│ Phase 4  matrix evaluation (matrix_eval.nr)                           │
│          alphas = transposed_A/B/C · eq(alpha, ·)                     │
│          absorb evals_az, evals_bz, evals_cz                          │
│          if has_publics:    absorb public_eval; assert geometric eq   │
│          if multi-commit:   absorb challenge_eval; assert geometric eq│
│                                                                       │
│ Phase 5  zkWHIR LDT verify (whir.nr)                                  │
│          for c1 (with public/blinding/challenge weights as needed)    │
│          for c2 (if multi-commit, with c2 weights)                    │
│                                                                       │
│ Phase 6  assert f_at_alpha == (az·bz − cz) · EQ(r, alpha)             │
│                                                                       │
│ Phase 7  EOF: host-enforced via fixed-size inputs (no runtime check)  │
└───────────────────────────────────────────────────────────────────────┘
```

### Public-input boundary

```noir
fn main(
    // --- PUBLIC ---
    public_inputs: pub [Field; NUM_PUBLIC_INPUTS],

    // --- PRIVATE WITNESS (codegen-emitted) ---
    pre_absorbed_state: [Field; 4],
    initial_root: Field,
    initial_ood_answers: [Field; INITIAL_OOD_COUNT],
    // commitment 2 root + LogUp challenges (when NUM_CHALLENGES > 0)
    // sumcheck coefficients, blinding eval
    // public_inputs_hash, evals (az, bz, cz), public_eval, challenge_eval
    // WHIR per-round: roots, OOD answers, sumcheck coeffs, query leaves, sibling paths, indices
    // Final WHIR claim
    …
);
```

### Flow invariants

1. **Squeeze-before-read.** Every `squeeze_*` happens at exactly the byte offset the Rust verifier squeezes at, with the same prior absorbs. Any reordering is a transcript mismatch and rejects valid proofs.
2. **Compile-time sizes.** Every witness array is statically sized from `types.nr`. The codegen tool pads/sizes hints to match exactly.
3. **No host-side trust beyond the pre-absorbed state.** Every other input is constrained by the circuit; the pre-absorbed state is bound back to the public inputs through the Phase-3 instance hash.

## Codegen tool

`tooling/cli/src/cmd/generate_noir_inputs.rs` — new `provekit-cli generate-noir-inputs` subcommand.

**Signature:** `provekit-cli generate-noir-inputs <verifier.pkv> <proof.np> [--out-dir provekit/verifier-noir]`

**Steps:**

1. Deserialize `verifier.pkv` (postcard) → `WhirR1CSScheme` + R1CS.
2. Deserialize `proof.np` (postcard) → `WhirR1CSProof`.
3. Build the Rust transcript sponge as the prover does, absorb the protocol-id and instance bytes, capture the resulting state (4 field elements).
4. Replay the verifier locally to chunk `narg_string` + `hints` into the exact field-arrays the Noir circuit expects (per-phase, per-round, per-query).
5. Emit:
   - `src/types.nr` — `global` constants for sizes and parameters.
   - `src/matrices.nr` — A/B/C sparse triples.
   - `Prover.toml` — concrete values for every private witness and the public inputs.

**Determinism check:** the codegen tool runs the Rust verifier against the proof end-to-end before emitting anything. If the Rust verifier rejects, codegen aborts with a clear error.

## Error handling

Noir has one error mode: constraint failure. There is no `Result`. The Rust verifier's `ensure!`/`bail!`/`context!` all collapse to `assert(condition, "<phase>: <what>")` in Noir.

- No graceful errors.
- No dynamic length checks — sizes are compile-time globals.
- No "unused trailing bytes" check inside the circuit — the codegen tool sizes inputs exactly; the host (`nargo execute`) rejects size mismatches before constraints run.
- Assertion messages identify the phase and check; the integration test attributes failures from the location in the circuit.

## Testing

1. **Poseidon2 KAT.**
   - Rust unit test calls `poseidon2::poseidon2_permutation` on a fixed `[Fr; 4]` input; freezes the output bytes.
   - Noir `#[test]` in `poseidon2.nr` calls the stdlib `poseidon2_permutation` on the same input and asserts the same output. Glue: both tests reference the same KAT constants emitted as a small generated file.
   - A second KAT covers `poseidon2_hash_bytes` (length-IV one-shot).
2. **Per-module unit tests.** Noir `#[test]` per module where feasible: sponge absorb/squeeze roundtrip, sumcheck single-round acceptance, Merkle path verification on a hand-rolled tree.
3. **End-to-end integration test** (`provekit/verifier-noir/tests/end_to_end.rs` or in `tooling/cli`):
   - Run `provekit-cli prepare --hash poseidon2` on `noir-examples/basic-2` (v0 inner).
   - Run `prove` → `.np`.
   - Run `generate-noir-inputs` to emit `types.nr` / `matrices.nr` / `Prover.toml`.
   - Shell out to `nargo execute --force`. Assert exit 0.
   - Negative case: flip one byte of `initial_root`, assert `nargo execute` fails.
4. **One-wrap recursion.** v0 final acceptance:
   - `provekit-cli prepare` the verifier-noir crate itself with `--hash poseidon2`.
   - `prove` it.
   - Verify the outer proof with the Rust verifier. Assert success.
5. **Perf baseline** (added for the <1 min stretch target):
   - Before any optimization work, measure on this Mac:
     a. Inner prove time for `noir-examples/basic-2` under `--hash poseidon2`.
     b. Outer prove time once the wrap closes.
   - Record both in `docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md` after first successful wrap.
   - Drives v0.1 / v1 perf scoping; never gates v0 correctness.

## Scope decisions (recorded)

- **Multi-commitment path (`NUM_CHALLENGES > 0`) is v1, NOT v0.** The `poseidon2` example has no lookups, so v0 only implements the single-commitment Phase-1/4 paths. The multi-commit branch is `assert(NUM_CHALLENGES == 0)`-stubbed for v0; v1 lands the second commitment + LogUp challenge-binding code when retargeting to `complete_age_check`.
- **Blinding (zk) component is IN for v0.** Verifier consumes blinding-eval prover hint, blinding ood/queries, and the blinding covector. (If the <1 min target is missed, cutting blinding is the first optimization lever to evaluate for v0.1.)
- **Poseidon2-only.** No runtime hash selection.
- **Fixed folding factor + query counts** per inner circuit, baked via codegen.
- **Inner circuit: `noir-examples/basic-2` for v0, `complete_age_check` for v1.**

## Open risks

- **Circuit size vs <1 min target.** WHIR LDT inside an R1CS recursive proof is expensive. For v0's `poseidon2` inner the outer verifier should be small enough to land under 1 min on this Mac, but we have no measurement yet — risk is real. Mitigation: the stretch target does NOT gate v0 correctness; if missed, open v0.1 with optimization plan.
- **v1 perf at `complete_age_check` scale.** Even with v0 cleanly closed, retargeting to `complete_age_check` will likely overshoot 1 min substantially. v1 budget includes at least one round of optimization (share Merkle work across queries, drop blinding if soundness allows, lower WHIR query counts) — quantified once we have v0's numbers as a baseline.
- **Noir generics.** Noir's compile-time generics are limited compared to Rust. We lean on `global` constants in `types.nr` rather than function-level generics; some helpers may need explicit sizes baked in.
- **Stdlib Poseidon2 drift.** If Noir stdlib's permutation diverges from the `poseidon2` Rust crate, the KAT will catch it; remediation is documented (hand-rolled permutation as fallback) but expected not to fire.
- **Codegen surface.** The codegen tool reimplements proof parsing close to the Rust verifier. Risk of drift if the WHIR proof layout changes; mitigated by the in-tool determinism check (run the Rust verifier first).
- **Inner prove time on this Mac is unknown.** `complete_age_check` inner-prove time hasn't been measured locally; if it's already >30s, the v1 outer wrap can't possibly land under 1 min even with a free outer prover. Plan includes an early measurement step.

## Out of scope (deferred)

- Optimizations: in-circuit Poseidon2 absorption count, exploiting WHIR linear combinations to share Merkle opening work, sparse-matrix encoding tricks.
- Generic inner circuit support without regenerating the verifier.
- Other hash flavors (Skyscraper, SHA256, Keccak, Blake3) in Noir.
- Multi-level recursion (>1 wrap).
