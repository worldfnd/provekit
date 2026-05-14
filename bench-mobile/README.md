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
- benchmark inputs from the source examples:
  `noir-examples/noir-passport-monolithic/complete_age_check/Prover.toml`
  `noir-examples/oprf/Prover.toml`
  `noir-examples/p256_bigcurve/Prover.toml`

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
3. the app calls the native JSON C ABI exported by `mobench-sdk`
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
- the mobile boundary is the `mobench_run_benchmark_json` C symbol exported by
  `mobench_sdk::export_native_c_abi!()`

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
├── src/
│   ├── examples.rs
│   ├── lib.rs
│   └── passport.rs
├── scripts/
│   └── generate-fixtures.sh
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

Copies Noir artifacts generated under the source examples' `target/`
directories into Cargo's `OUT_DIR` so the mobile runner can embed them without
checking compiled JSON into git.

### `src/lib.rs`

This is the integration surface between ProveKit and `mobench`.

It does three jobs:

1. exports the native mobench JSON C ABI
2. keeps a host-side `run_benchmark(spec)` wrapper for tests and diagnostics
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
- parse the source example `Prover.toml`
- prepare, prove, and verify through `provekit-ffi`'s in-process helper API

This file is where the mobile benchmark stays tied to real ProveKit proving
code through `provekit-ffi` instead of synthetic stand-ins.

### Generated Noir artifacts

Compiled Noir JSON artifacts are generated by
`bench-mobile/scripts/generate-fixtures.sh` before CI or BrowserStack builds.
The generated files stay under each source example's ignored `target/`
directory and are copied into the mobile crate at build time.

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
noirup --version v1.0.0-beta.19
```

Generate the Noir artifacts consumed by the benchmark build:

```bash
bench-mobile/scripts/generate-fixtures.sh
```

If a circuit or ABI changes, regenerate the artifacts before running
`bench-mobile` tests or mobile packaging. The generated JSON remains ignored.

## Local mobench usage

Build the mobile artifacts:

```bash
cargo-mobench build --target ios --release --crate-path bench-mobile
cargo-mobench build --target android --release --crate-path bench-mobile
```

Repo-level `mobench` defaults live in `mobench.toml` at the workspace root. In
this repository that file pins Android packaging to `arm64-v8a`, which matches
the real-device CI path and avoids unsupported `armeabi-v7a` builds in
`skyscraper/fp-rounding`. It also sets `ffi_backend = "native-c-abi"`, so the
generated Android and iOS runners call the C ABI directly and skip UniFFI
binding generation.

Run a local or CI-managed benchmark by selecting one of the exported benchmark
function names. The important knobs are:

- `--function`: which benchmark to run
- `--iterations`: measured iterations
- `--warmup`: warmup iterations
- `--target`: `android` or `ios`

For CI and BrowserStack runs, the repo workflows wrap these commands and fetch
the resulting reports back into `target/mobench/ci/...`.

## BrowserStack device profiles used in this repo

PR benchmarks run the triad profile by default:

- Android:
  - `Vivo Y21-11.0`
  - `Google Pixel 7-13.0`
  - `Samsung Galaxy S24-14.0`
- iOS:
  - `iPhone 11-13`
  - `iPhone 15-17`
  - `iPhone 16 Pro-18`

The iOS triad also carries a backup triad for BrowserStack scheduling or
catalog changes:

- `iPhone SE 2022-15`
- `iPhone 14-16`
- `iPhone 16 Pro Max-18`

Manual workflow dispatches and `/mobench` comments can select `smoke`,
`worst`, or `triad`; when omitted, PR commands also default to `triad`.

The low-spec pair used for worst-case checks is:

- Android: `Vivo Y21-11.0`
- iOS: `iPhone 11-13`

The sticky PR comment is updated in place using the `<!-- mobench-summary -->`
marker so each rerun replaces the previous report.
