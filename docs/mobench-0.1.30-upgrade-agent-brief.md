# Agent Brief: Ship `mobile-bench-rs` `0.1.30` Upstream

## Use This Prompt

> Work in the upstream `worldcoin/mobile-bench-rs` repository, not in
> ProveKit. Implement the upstream changes required for a real `0.1.30`
> release, add or update tests in `mobile-bench-rs`, bump the crate versions to
> `0.1.30`, and prepare the release so downstream consumers like ProveKit can
> drop their local patch. Use ProveKit only as an external integration harness
> to prove the release works. Do not write a ProveKit upgrade plan. Do not
> encode ProveKit-only workflow policy into `mobile-bench-rs`.

## What Was Wrong With The Previous Brief

The old instructions were aimed at upgrading ProveKit to a hypothetical
upstream `0.1.30`. That is the wrong scope.

The correct scope is:

- primary repo: `worldcoin/mobile-bench-rs`
- objective: implement and release upstream `0.1.30`
- downstream repo: ProveKit is only the acceptance harness

## Objective

Produce an upstream `mobile-bench-rs` `0.1.30` release that contains the
behaviors ProveKit currently patches locally:

- iOS benchmark completion timeout is configurable
- iOS packaged apps keep the requested benchmark spec across regeneration
- iOS emits raw CPU and peak-memory metrics directly in the benchmark payload
- summary extraction preserves those iOS metrics even when BrowserStack
  profiling is empty
- fetch/result handling fails hard when no benchmark payloads are recovered
- CI output validation and diagnostics are first-class upstream features
- BrowserStack/provider failure modes are surfaced clearly and preserve
  diagnostic artifacts
- renderer output does not show misleading hard-coded units in headers

At the end, downstreams should be able to consume `0.1.30` without carrying the
current ProveKit patch for these behaviors.

## Primary Repositories

### Upstream implementation repo

- `https://github.com/worldcoin/mobile-bench-rs`

### Downstream validation harness

- `https://github.com/dcbuild3r/provekit`
- reference branch used to prove the current behavior:
  `codex/mobench-v1-browserstack`

## Non-Goals

Do not do these in upstream:

- do not add ProveKit-specific device profile names like `smoke`, `triad`, or
  `worst`
- do not add PR comment behavior or other repo-local CI policy
- do not hardcode ProveKit benchmark function names
- do not ship a ProveKit patch file as the solution

## Source Material To Read First

Read these before touching upstream code:

1. ProveKit’s current local patch:
   [mobile-bench-rs-browserstack-devices.patch](/Users/dcbuilder/Code/world/ProveKit/.github/patches/mobile-bench-rs-browserstack-devices.patch)
2. ProveKit’s upstream notes:
   [mobench-0.1.30-upstream-notes.md](/Users/dcbuilder/Code/world/ProveKit/docs/mobench-0.1.30-upstream-notes.md)
3. The current, strict downstream validator:
   [validate_mobile_bench_outputs.sh](/Users/dcbuilder/Code/world/ProveKit/.github/scripts/validate_mobile_bench_outputs.sh)
4. The downstream workflow wiring:
   [mobile-bench-reusable.yml](/Users/dcbuilder/Code/world/ProveKit/.github/workflows/mobile-bench-reusable.yml)

## Proven Downstream Evidence

These observed runs are the acceptance evidence the upstream release must
satisfy.

### Known good smoke runs

- [24247366652](https://github.com/dcbuild3r/provekit/actions/runs/24247366652)
  `platform=both`
  - iOS passed
  - Android passed
  - requested spec matched actual spec on both platforms
- [24271400191](https://github.com/dcbuild3r/provekit/actions/runs/24271400191)
  `platform=ios device_profile=worst`
  - passed on `iPhone 14-16.3`
  - requested spec matched actual spec
  - summary resource usage:
    - `cpu_total_ms = 83280`
    - `peak_memory_kb = 1272004`
  - raw iOS resources:
    - `elapsed_cpu_ms = 83280`
    - `peak_memory_kb = 1272004`
  - `performance_metrics` was still `{}`, so the summary must preserve raw iOS
    metrics without relying on BrowserStack profiling

### Known failure evidence

- [24269734185](https://github.com/dcbuild3r/provekit/actions/runs/24269734185)
  `platform=both device_profile=worst`
  - iOS `iPhone 7-10` failed immediately with BrowserStack `422`:
    the device OS is below the minimum accepted for the app/test bundle
  - Android `Vivo Y21-11.0` scheduled successfully but timed out after the full
    fetch window
  - BrowserStack marked the Android build and session `timedout`
  - the fetched instrumentation log ends with BrowserStack’s bundled `adb`
    wrapper being killed
- [24270709415](https://github.com/dcbuild3r/provekit/actions/runs/24270709415)
  `platform=ios device_profile=worst`
  - `iPhone 11-13` also failed with the same BrowserStack `422`

These runs establish two important facts:

1. the oldest viable iOS target for this app bundle is not simply “the oldest
   iPhone BrowserStack lists”
2. low-end Android devices can stay alive long enough to require strong timeout
   handling and diagnostics even when no benchmark payload is recovered

## Required Upstream Work

### 1. Bump the upstream crate versions to `0.1.30`

In `worldcoin/mobile-bench-rs`:

- bump `mobench`
- bump `mobench-sdk`
- bump `mobench-macros`
- update any workspace lockfiles
- update release notes / changelog / release prep docs

This version bump is the last step, not the first step. Do it only after the
feature work and tests are in place.

### 2. Add first-class iOS completion timeout support

Implement upstream support for choosing the iOS benchmark completion timeout.

Required behavior:

- no hard-coded `300.0` timeout in the generated XCUITest harness
- timeout should flow from config or CLI into generated iOS test code
- selected timeout must be visible in `cargo mobench` logs

Acceptable public surface:

- a config key such as `browserstack.ios_completion_timeout_secs`
- or a CLI flag such as `--benchmark-timeout-secs`

The important part is that the generated harness uses it and the user can
control it.

### 3. Preserve iOS resources across project regeneration

Fix the regeneration flow so iOS packaging keeps:

- `bench_spec.json`
- `bench_meta.json`
- any other required files under `BenchRunner/Resources`

This must survive repeated calls that currently recreate the generated iOS
scaffold.

Required tests:

- unit or integration test proving `generate_ios_project(...)` preserves
  existing `Resources`
- packaging-level test proving the final IPA/test bundle contains the requested
  bench spec, not the template default

### 4. Fail if fetched results do not match the requested benchmark spec

Upstream must not treat “some benchmark ran” as success.

Required behavior:

- after fetch/result processing, compare requested spec vs actual reported spec
- fail if function / iterations / warmup do not match

This is specifically to prevent the old iOS failure mode where the app silently
ran `prepare` with `20/3` instead of the requested benchmark.

### 5. Emit raw iOS CPU and peak-memory metrics directly from the runner

The generated iOS runner must write raw metrics into the benchmark payload:

- `resources.elapsed_cpu_ms`
- `resources.peak_memory_kb`

Requirements:

- measure process CPU locally in the runner process
- measure peak memory locally in the runner process
- do not depend only on BrowserStack post-processing for these numbers

Required tests:

- a generated-template regression test proving the fields are present in
  `BenchRunnerFFI.swift`
- at least one test that validates the emitted JSON shape

### 6. Preserve raw iOS peak memory in summary extraction

Upstream summary generation must use raw iOS payload metrics when provider-side
profiling is missing.

Required behavior:

- if raw `resources.peak_memory_kb` is present, preserve it into
  `summary.device_summaries[].benchmarks[].resource_usage.peak_memory_kb`
- if raw `resources.elapsed_cpu_ms` is present, preserve it into
  `resource_usage.cpu_total_ms`
- do not drop those fields just because `performance_metrics == {}`

Required tests:

- resource extraction test proving explicit raw `peak_memory_kb` wins when
  BrowserStack profiling is absent
- summary-generation test proving the final summary retains both
  `cpu_total_ms` and `peak_memory_kb`

### 7. Treat unrecovered fetch failures as hard failures

Current downstream expectation:

- fetch can fail only if no real benchmark payloads were recovered
- empty payload collections count as “no payloads”

Upstream must implement this directly.

Required behavior:

- `cargo mobench run --fetch`
- `cargo mobench ci run --fetch`
- if fetch fails and recovered payloads are missing or structurally empty, exit
  non-zero
- if fetch fails but at least one valid payload was recovered, continue with a
  warning and preserve diagnostics

### 8. Add first-class CI validation

Downstreams should not have to write their own shell validator for basic CI
correctness.

Upstream should either:

- validate automatically inside `ci run`, or
- expose an explicit validation command such as
  `cargo mobench ci validate --results-dir ... --fetch-output-dir ...`

Minimum validation scope:

- `summary.json` exists
- `device_summaries` is non-empty
- `results.csv` contains data rows
- requested spec equals actual spec
- benchmark rows have required resource usage when the target supports it
- fetched BrowserStack state is terminal and successful

### 9. Emit machine-readable diagnostics for BrowserStack runs

Upstream should write a diagnostics artifact such as:

- `browserstack-diagnostics.json`

Recommended content:

- build id
- build status
- sessions
- per-session status
- testcase status counts
- whether a payload was recovered

This should make downstream `jq` scraping unnecessary.

### 10. Preserve fetch artifacts on failure

When fetch/result handling fails, upstream must still preserve the partial
BrowserStack output it managed to retrieve.

That includes:

- `build.json`
- `session.json`
- fetched logs
- any recovered partial payloads

This is required for debugging timeouts and provider-side failures.

### 11. Improve device compatibility failure handling

This requirement comes directly from the worst-device experiments.

Observed failures:

- `iPhone 7-10` rejected by BrowserStack `422`
- `iPhone 11-13` rejected by BrowserStack `422`

Required upstream improvement:

- detect or surface device/app minimum-OS incompatibility as a first-class
  compatibility error
- do not leave the user with only a generic schedule failure message

Best case:

- preflight-check requested iOS devices against the app/test bundle minimum OS
  before attempting to schedule the BrowserStack run

Acceptable fallback:

- keep the schedule attempt, but parse BrowserStack `422` compatibility failures
  into a structured, user-facing error that includes:
  - device
  - requested OS
  - minimum accepted OS or minimum bundle requirement, when available

### 12. Fix renderer unit/header mismatch

The current renderer can produce a column header like `Mean (ms)` while
rendering values like `3.192s`.

That is misleading.

Upstream should fix this in one of two ways:

- remove hard-coded units from the header, or
- force the column values to stay in the same unit as the header

The goal is consistency between header and rendered cell values.

## Upstream Files Likely To Change

In `worldcoin/mobile-bench-rs`, expect to touch files like:

- `crates/mobench-sdk/src/codegen.rs`
- `crates/mobench-sdk/templates/ios/BenchRunner/BenchRunnerFFI.swift.template`
- `crates/mobench-sdk/templates/ios/BenchRunner/BenchRunnerUITests/BenchRunnerUITests.swift.template`
- `crates/mobench/src/lib.rs`
- CLI/config parsing code for `mobench`
- summary rendering code for markdown/plots/tables
- version metadata across the workspace
- changelog / release notes / publishing docs

## Required Upstream Tests

Add or update tests in `worldcoin/mobile-bench-rs` for:

1. iOS resource preservation across regeneration
2. iOS packaged bundles keeping the requested spec
3. generated iOS runner emitting `elapsed_cpu_ms` and `peak_memory_kb`
4. summary extraction preserving raw iOS `peak_memory_kb`
5. fetch failures with no payloads exiting non-zero
6. validation failing on empty or mismatched outputs
7. structured BrowserStack diagnostics generation
8. renderer header/unit consistency
9. device compatibility failures being surfaced clearly

## External Acceptance Validation Using ProveKit

After the upstream implementation is ready, validate it with ProveKit as an
external consumer.

### How to use ProveKit for validation

Use the ProveKit branch:

- `dcbuild3r/provekit`
- branch: `codex/mobench-v1-browserstack`

Point ProveKit temporarily at your upstream `mobile-bench-rs` branch or tag.
Do not validate only with upstream unit tests.

### Required downstream checks

1. iOS smoke run succeeds
2. Android smoke run succeeds
3. combined `platform=both` smoke run succeeds
4. requested benchmark spec matches actual spec
5. iOS summaries still include:
   - `cpu_total_ms`
   - `peak_memory_kb`
6. iOS raw payload still includes:
   - `elapsed_cpu_ms`
   - `peak_memory_kb`
7. Android summaries still include:
   - `cpu_total_ms`
   - `peak_memory_kb`

### Worst-device acceptance checks

Use the ProveKit worst-device experiments as a downstream proof point:

- `Vivo Y21-11.0` must preserve strong timeout diagnostics and fetched artifacts
- iOS compatibility failures must be surfaced clearly for too-old devices
- the oldest viable iOS device found so far is `iPhone 14-16`

Upstream does not need to encode these exact profile names, but it does need to
support the behaviors required to debug and handle them correctly.

## Deliverables

The agent working upstream should deliver:

- code changes in `worldcoin/mobile-bench-rs`
- updated upstream tests
- crate version bumps to `0.1.30`
- release notes or changelog entry for `0.1.30`
- a concise list of what changed and why
- downstream validation evidence from ProveKit smoke runs

## Definition Of Done

This work is done only when:

1. the upstream repo contains the required feature changes
2. upstream tests cover those changes
3. `mobench`, `mobench-sdk`, and `mobench-macros` are bumped to `0.1.30`
4. downstream ProveKit smoke validation passes against the upstream build
5. renderer unit output is no longer misleading
6. provider compatibility and timeout failures are diagnosable without custom
   downstream scraping
