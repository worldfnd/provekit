# mobench 0.1.30 Integration Plan (Noir Circuits)

Status: Draft plan
Owner: ProveKit maintainers
Scope start: passport end-to-end circuit

## 1. Objective

Add `mobench` `0.1.30` based mobile benchmarking so we can run selected Noir proving workloads on Android/iOS devices, starting with passport end-to-end proving.

## 2. Primary target for phase 1

Start with:
- `noir-examples/noir-passport-monolithic/complete_age_check`

Reason:
- Single-circuit end-to-end flow.
- Already used in CI/workflows (`circuit_keys.yml`) and compiler tests.
- Good baseline before fragmented passport chain and other examples.

## 3. Constraints discovered from mobench 0.1.30

From published crate APIs and README behavior:
- `mobench` build/run pipeline expects a benchmark crate that can be cross-compiled and exposed via UniFFI.
- Android/iOS templates call generated bindings expecting:
  - `BenchSpec`
  - `BenchReport`
  - `BenchException`
  - `runBenchmark(...)`
- Builders require UniFFI bindings generation (`uniffi-bindgen` binary in crate or globally installed tool).
- CLI build auto-detects benchmark crate name from `bench-mobile/Cargo.toml` (or config fallback).
- Run flow embeds `bench_spec.json` into mobile app assets/resources and passes function + iteration metadata.

## 4. Recommended integration architecture

Create a dedicated benchmark crate at repo root:
- Directory: `bench-mobile/`
- Package name: `bench-mobile`
- Add as workspace member.

Why this shape:
- Aligns with mobench CLI auto-detection paths.
- Minimizes extra configuration friction (`cargo mobench build/run` works with defaults).

### Crate responsibilities

`bench-mobile` should:
- Expose UniFFI-compatible `BenchSpec`, `BenchSample`, `BenchReport`, `BenchError`.
- Expose `run_benchmark(spec)` exported via UniFFI.
- Dispatch benchmark names to concrete proving workloads.
- Use `mobench_sdk::timing::run_closure*` so setup can be excluded from measured region.

## 5. Passport benchmark design (phase 1)

Initial benchmark functions in `bench-mobile/src/lib.rs`:

1. `passport_complete_age_check_prepare`
- Measures conversion/preparation from compiled Noir artifact to prover/verifier artifacts in-memory.

2. `passport_complete_age_check_prove`
- Measures proof generation only.
- Setup should prepare reusable prover/input state outside measured section.

3. `passport_complete_age_check_verify`
- Measures verifier time using a prepared proof.

4. `passport_complete_age_check_e2e`
- Measures prepare + prove + verify in one measured iteration (explicitly marked as e2e).

### Setup strategy

Use setup closures to separate concerns:
- Non-measured setup:
  - parse or load artifact/input fixtures
  - initialize prover/verifier objects
- Measured section:
  - exactly the operation under test (prepare OR prove OR verify OR e2e)

## 6. Fixture strategy

Avoid large mobile bundle blow-ups by phasing fixture complexity:

Phase 1A:
- Embed only essential source fixtures (`target/*.json` equivalent input and witness TOML data) and build scheme/prover in setup.

Phase 1B (if needed):
- Add optional precomputed PKP/PKV fixtures only after measuring artifact size and upload feasibility.

## 7. Implementation phases

## Phase 0: Preflight

- Add `bench-mobile` crate skeleton with UniFFI + mobench-sdk wiring.
- Add `src/bin/uniffi-bindgen.rs` and `build.rs` scaffolding generation.
- Confirm local command success:
  - `cargo mobench build --target android --release`

Exit criteria:
- Android build completes and generated app can call Rust FFI entrypoint.

## Phase 1: Passport monolithic baseline

- Implement benchmark dispatch for `complete_age_check` workflow.
- Add `prepare`, `prove`, `verify`, and `e2e` benchmarks.
- Validate benchmark function discovery/listing.

Exit criteria:
- `cargo mobench run --target android --function bench_mobile::passport_complete_age_check_prove --local-only`
  resolves benchmark function and generates summary artifacts.

## Phase 2: Fragmented passport chain

Add chain benchmarks for `noir-passport/merkle_age_check`:
- 4-circuit (`tbs_720`) sequence
- 5-circuit (`tbs_1300`) sequence

Suggested functions:
- `passport_merkle_720_chain_e2e`
- `passport_merkle_1300_chain_e2e`
- per-circuit prove benchmarks for hotspot identification.

## Phase 3: Additional Noir examples

Expand to representative workloads:
- `poseidon-rounds`
- `sha256` / `noir-native-sha256`
- `oprf` (if asset/setup cost acceptable)

## Phase 4: CI wiring

Add mobile-benchmark CI workflow with explicit contract outputs:
- `target/mobench/ci/summary.json`
- `target/mobench/ci/summary.md`
- `target/mobench/ci/results.csv`

Current PR workflow shape:
- `mobile-bench.yml` is dispatchable, BrowserStack-gated on secrets, and exposes `device_profile=smoke|triad|worst`.
- `mobile-bench-pr-command.yml` enables `/mobench` PR comments and dispatches `mobile-bench.yml` from the PR base ref.
- `mobile-bench-pr-command.yml` defaults PR-triggered runs to `device_profile=smoke` and allows `device_profile=triad|worst` for manual escalation.
- `mobile-bench-pr-auto.yml` auto-dispatches when a PR has the `bench` label and `Cargo Build & Test` has passed, using the PR base ref rather than the repository default branch and forcing the smoke profile.
- Sticky comment updates use the `<!-- mobench-summary -->` marker.

Current BrowserStack device profiles:
- Smoke:
  - Android: `Google Pixel 7-13.0`
  - iOS: `iPhone 16 Pro-18`
- Worst:
  - Android: `Motorola Moto G9 Play-10.0`
  - iOS: `iPhone 12-14`
- Triad:
  - Android: `Motorola Moto G9 Play-10.0`, `Google Pixel 7-13.0`, `Samsung Galaxy S24-14.0`
  - iOS: `iPhone 12-14`, `iPhone 15-17`, `iPhone 16 Pro-18`

Gate regressions using baseline comparison threshold.

## 8. Validation checklist

For each benchmark function:
- Name is stable and explicit.
- Uses `black_box` on computed outputs.
- Measured section excludes unrelated setup I/O.
- Iteration/warmup defaults documented.
- Output summary includes function, sample count, stats.

For integration quality:
- Android build and run command paths verified.
- iOS build path verified (packaging can be phase-gated if signing infra unavailable).
- No regressions to existing `provekit-cli` workflows.

## 9. Risks and mitigations

1. Artifact size too large for mobile packaging/upload
- Mitigation: start with in-setup construction and small fixture payloads.

2. Benchmark function naming mismatch between mobench config and registry
- Mitigation: use explicit fully-qualified names and add a list/discovery check in setup docs.

3. Host tooling friction (`cargo-ndk`, `uniffi-bindgen`, iOS packaging)
- Mitigation: phase Android first, codify prerequisites in docs and CI preflight.

4. Measuring setup instead of workload
- Mitigation: enforce setup-vs-measured separation with `run_closure_with_setup*`.

## 10. Proposed first execution commands

After phase-1 implementation:

```bash
# Build Android artifacts
cargo mobench build --target android --release

# Run baseline passport prove benchmark
cargo mobench run \
  --target android \
  --function bench_mobile::passport_complete_age_check_prove \
  --iterations 10 \
  --warmup 2 \
  --local-only \
  --release
```

## 11. Next planned code PR (phase 0+1)

- Add `bench-mobile` workspace crate.
- Implement UniFFI export surface + benchmark dispatch.
- Implement monolithic passport prepare/prove/verify/e2e benchmark functions.
- Add short usage doc for local Android/iOS run paths.
