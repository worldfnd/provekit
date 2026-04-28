# bench-mobile

`bench-mobile` is ProveKit's mobile benchmark crate. It packages selected
ProveKit proving workloads behind the interface expected by
[mobench](https://github.com/worldcoin/mobile-bench-rs) so the same Rust code
can be built into Android and iOS runners, executed on real devices, and
reported through the CI workflow.

The current scope covers three Noir examples:

- source circuits:
  `noir-examples/noir-passport-monolithic/complete_age_check`
  `noir-examples/oprf`
  `noir-examples/p256_bigcurve`
- embedded benchmark fixtures:
  `bench-mobile/fixtures/complete_age_check/`
  `bench-mobile/fixtures/oprf/`
  `bench-mobile/fixtures/p256_bigcurve/`

## What ProveKit uses mobench for

ProveKit uses `mobench` to answer one question: how expensive are our proving
steps on real mobile hardware?

This crate exposes prepare, prove, verify, and end-to-end benchmark functions
for each embedded fixture:

- `bench_mobile::bench_passport_complete_age_check_prepare`
- `bench_mobile::bench_passport_complete_age_check_prove`
- `bench_mobile::bench_passport_complete_age_check_verify`
- `bench_mobile::bench_passport_complete_age_check_e2e`
- `bench_mobile::bench_oprf_prepare`
- `bench_mobile::bench_oprf_prove`
- `bench_mobile::bench_oprf_verify`
- `bench_mobile::bench_oprf_e2e`
- `bench_mobile::bench_p256_bigcurve_prepare`
- `bench_mobile::bench_p256_bigcurve_prove`
- `bench_mobile::bench_p256_bigcurve_verify`
- `bench_mobile::bench_p256_bigcurve_e2e`

They let us measure different slices of the passport proving pipeline:

- `prepare`: deserialize the Noir artifact, build the proof scheme, and produce
  prover/verifier state
- `prove`: generate the proof from prepared prover state and parsed inputs
- `verify`: verify a prepared proof against a prepared verifier
- `e2e`: run prepare, prove, and verify in one measured benchmark

That split matters because proving is not the whole story. On mobile devices we
care about setup cost, proof cost, verifier cost, and the full end-to-end path.

## How mobench works with this crate

At a high level, the flow is:

1. `cargo-mobench build` cross-compiles this crate and generates a mobile test
   runner app
2. the generated Android/iOS app receives a benchmark spec containing:
   - function name
   - measured iteration count
   - warmup iteration count
3. the app calls the UniFFI-exported Rust entrypoint:
   `run_benchmark(spec)`
4. `run_benchmark` forwards to `mobench_sdk::run_benchmark(...)`
5. `mobench-sdk` discovers the selected `#[benchmark]` function, performs
   warmups, measures iterations, and returns a structured report
6. the mobile runner logs that report, and `mobench` turns the fetched device
   output into CI artifacts such as:
   - `summary.json`
   - `summary.md`
   - `results.csv`

Inside this crate:

- benchmark registration comes from `#[benchmark]`
- phase-level timing comes from `profile_phase(...)`
- the Rust/UniFFI boundary is expressed by custom record types such as
  `BenchSpec`, `BenchSample`, `SemanticPhase`, `HarnessTimelineSpan`, and
  `BenchReport`

The exported report preserves the fields the generated mobile runners care
about:

- wall-clock sample durations
- sample CPU time
- sample peak memory
- semantic phases
- harness timeline spans

## How the benchmark code is structured

```text
bench-mobile/
├── Cargo.toml
├── README.md
├── build.rs
├── fixtures/
│   ├── complete_age_check/
│   │   ├── complete_age_check.json
│   │   └── Prover.toml
│   ├── oprf/
│   │   ├── oprf.json
│   │   └── Prover.toml
│   └── p256_bigcurve/
│       ├── p256.json
│       └── Prover.toml
├── src/
│   ├── examples.rs
│   ├── lib.rs
│   ├── passport.rs
│   └── bin/
│       └── uniffi-bindgen.rs
└── tests/
    └── passport_smoke.rs
```

### `Cargo.toml`

Declares `bench-mobile` as a library crate that can be built as:

- `lib`
- `cdylib`
- `staticlib`

Those crate types are what `mobench` needs to package the Rust code into mobile
artifacts.

### `build.rs`

Currently empty on purpose. We use UniFFI proc-macro mode, so we do not need
build-time scaffolding generation here.

### `src/bin/uniffi-bindgen.rs`

Provides the `uniffi-bindgen` binary that `mobench` expects when generating the
mobile bridge code.

### `src/lib.rs`

This is the integration surface between ProveKit and `mobench`.

It does three jobs:

1. defines the UniFFI-visible request/response types
2. exports `run_benchmark(spec)`
3. registers the benchmark functions themselves

It also contains the benchmark-specific execution policy:

- `prepare` measures raw fixture preparation
- `prove` reuses a thread-local prepared fixture so the measured region is proof
  generation, not setup
- `verify` reuses a thread-local verified fixture so the measured region is
  verification, not proof generation
- `e2e` measures the full path in one run

### `src/examples.rs`

Contains shared fixture loading, proving, and verification code for the
embedded Noir examples used by mobile benchmarks.

### `src/passport.rs`

Contains the ProveKit-specific benchmark fixture logic:

- load the embedded Noir program artifact
- parse the embedded `Prover.toml`
- build `NoirProofScheme`, `Prover`, and `Verifier`
- prove and verify using the normal ProveKit crates

This file is where the mobile benchmark stays tied to real ProveKit proving
code instead of synthetic stand-ins.

### `fixtures/*/*.json`

Checked-in compiled Noir artifacts for the benchmarked circuits.

### `fixtures/*/Prover.toml`

Checked-in witness inputs for the same circuits.

Together, these fixtures make the benchmark reproducible without running `nargo`
on the device.

### `tests/passport_smoke.rs`

Host-side smoke tests for the embedded fixture:

- fixture preparation produces non-empty proving artifacts
- the embedded passport example can prove and verify successfully

These are not mobile performance tests. They are correctness checks that keep
the benchmark fixture from silently drifting out of shape.

### `tests/examples_smoke.rs`

Host-side smoke tests for the shared fixture loader and the OPRF/p256 fixtures.
They verify that the embedded examples prepare, prove, and verify successfully.

## Benchmark behavior and measurement boundaries

The crate tries to keep the measured region tight:

- benchmark setup and fixture parsing are excluded from `prove` and `verify`
  measurements via cached thread-local fixtures
- `prepare` exists separately so setup cost is still measured explicitly
- `e2e` is available when we do want the full pipeline cost
- `black_box(...)` is used so benchmark outputs are not optimized away

This matters because mobile benchmarking gets misleading very quickly if
artifact loading, serialization, and unrelated setup leak into every measured
iteration.

## Refreshing fixtures

Install the Noir toolchain expected by the repo:

```bash
noirup --version v1.0.0-beta.11
```

Refresh the checked-in Noir artifact fixture:

```bash
cd noir-examples/noir-passport-monolithic/complete_age_check
nargo compile --skip-brillig-constraints-check --force
cp target/complete_age_check.json ../../../bench-mobile/fixtures/complete_age_check/complete_age_check.json

cd ../../oprf
nargo compile --skip-brillig-constraints-check --force
cp target/oprf.json ../../bench-mobile/fixtures/oprf/oprf.json

cd ../p256_bigcurve
nargo compile --skip-brillig-constraints-check --force
cp target/p256.json ../../bench-mobile/fixtures/p256_bigcurve/p256.json
```

If the circuit or its ABI changes, refresh the fixture in the same change so
the benchmark stays representative.

## Local mobench usage

Build the mobile artifacts:

```bash
cargo-mobench build --target ios --release --crate-path bench-mobile
cargo-mobench build --target android --release --crate-path bench-mobile
```

Repo-level `mobench` defaults live in `mobench.toml` at the workspace root. In
this repository that file pins Android packaging to `arm64-v8a`, which matches
the real-device CI path and avoids unsupported `armeabi-v7a` builds in
`skyscraper/fp-rounding`.

Run a local or CI-managed benchmark by selecting one of the exported benchmark
function names. The important knobs are:

- `--function`: which benchmark to run
- `--iterations`: measured iterations
- `--warmup`: warmup iterations
- `--target`: `android` or `ios`

For CI and BrowserStack runs, the repo workflows wrap these commands and fetch
the resulting reports back into `target/mobench/ci/...`.

## BrowserStack device profiles used in this repo

PR benchmarks run the smoke profile by default:

- Android: `Google Pixel 7-13.0`
- iOS: `iPhone 16 Pro-18`

Manual workflow dispatches can still select the triad profile:

- Android:
  - `Motorola Moto G9 Play-10.0`
  - `Google Pixel 7-13.0`
  - `Samsung Galaxy S24-14.0`
- iOS:
  - `iPhone SE 2020-16`
  - `iPhone 15-17`
  - `iPhone 16 Pro-18`

The low-spec pair used for worst-case checks is:

- Android: `Motorola Moto G9 Play-10.0`
- iOS: `iPhone SE 2020-16`

The sticky PR comment is updated in place using the `<!-- mobench-summary -->`
marker so each rerun replaces the previous report.
