# mobench 0.1.30 Upstream Notes

This repo now depends on `mobench` `0.1.29`, but still carries a local patch in
`.github/patches/mobile-bench-rs-browserstack-devices.patch` plus
workflow-side validation glue. The items below should be upstreamed in
`mobench 0.1.30` so the repo can drop that patch and simplify the CI workflow.

## Already upstream in 0.1.29

Do not re-implement these:

- Android default ABI narrowing to `arm64-v8a`
- Android generated-project asset preservation
- BrowserStack artifact result recovery via `recover_benchmark_results_from_fetched_artifacts`

## Upstream in 0.1.30

### 1. Profile-aware iOS benchmark completion timeout

Current local patch:
- threads `MOBENCH_IOS_BENCHMARK_TIMEOUT_SECS` into `generate_ios_project(...)`
- renders `{{BENCHMARK_TIMEOUT_SECS}}` into `BenchRunnerUITests.swift.template`
- lets the caller choose shorter smoke and longer triad waits

What should be upstreamed:
- first-class `mobench` config/CLI support for iOS benchmark completion timeout
- generated XCUITest harness should use that configured timeout instead of hard-coded `300.0`
- the configured timeout should be visible in `cargo mobench build` / `cargo mobench ci run` logs

Why:
- BrowserStack device performance varies significantly by device/profile
- a fixed 300-second wait is too rigid for long proving runs

Recommended upstream surface:
- either a `browserstack.ios_completion_timeout_secs` config key
- or a generic `--benchmark-timeout-secs` / `--completion-timeout-secs` flag that feeds generated harnesses

### 2. Ensure generated iOS BrowserStack artifacts actually embed `bench_spec.json`

Observed in ProveKit smoke rerun:
- request asked for `bench_mobile::bench_passport_complete_age_check_prove`
- fetched iOS summary instead contained `bench_mobile::bench_passport_complete_age_check_prepare`
- fetched iOS samples used default profile settings (`20` iterations, `3` warmup)

Likely cause:
- generated iOS `project.yml` points at `../../target/mobile-spec/ios`
- from `target/mobench/ios/BenchRunner`, that resolves to `target/mobench/target/mobile-spec/ios`
- the packaged app therefore misses `bench_spec.json`, so the app falls back to `DEFAULT_FUNCTION`, `20`, and `3`

What should be upstreamed:
- fix the generated iOS resource path so `bench_spec.json` is bundled into the app
- add an integration test that packages the iOS BrowserStack artifacts and verifies the embedded spec matches the requested function/iterations/warmup
- fail `ci run --target ios` if fetched results do not match the requested benchmark spec

Why:
- otherwise iOS can report apparently successful samples for the wrong benchmark
- this is more dangerous than an empty run because it looks valid at first glance

### 3. Treat failed/timed-out fetches as hard failures when no payloads are recovered

Current local patch:
- preserves the existing artifact recovery attempt
- if BrowserStack fetch errors and no benchmark payloads were recovered from fetched artifacts, `mobench` now returns an error

What should be upstreamed:
- `cargo mobench run --fetch`
- `cargo mobench ci run --fetch`
- payload presence checks must treat both `None` and structurally empty payloads
  (`Some({})`, `Some({"device": []})`, etc.) as "no benchmark payloads"

Desired behavior:
- if live fetch succeeds, continue normally
- if live fetch fails but fetched artifacts recover at least one valid benchmark payload, continue with a warning
- if live fetch fails and no valid payloads can be recovered, fail the command

Why:
- otherwise CI can produce empty summaries and still look successful

### 4. First-class validation of non-empty benchmark outputs

Current local implementation lives in:
- `.github/scripts/validate_mobile_bench_outputs.sh`

What it currently validates:
- `summary.json` exists
- `summary.device_summaries` is non-empty
- `results.csv` exists
- `results.csv` contains at least one data row
- recovered benchmark payload collections are not merely present, but non-empty
- BrowserStack `build.json` artifacts were fetched
- no fetched BrowserStack build/session/testcase state is still `running`, `failed`, `error`, `timedout`, or `timeout`

What should be upstreamed:
- a built-in `mobench` validation mode for CI outputs, either:
  - implicit inside `ci run`, or
  - explicit as `cargo mobench ci validate --results-dir ... --fetch-output-dir ...`

Why:
- output-presence checks are not enough
- every repo will otherwise reinvent this same shell validation

### 5. Machine-readable BrowserStack diagnostics

Current workflow prints diagnostics by parsing fetched artifacts itself:
- build id
- per-device session state
- testcase status counters
- whether any `bench-report.json` payload was recovered

What should be upstreamed:
- `mobench` should emit a compact machine-readable diagnostics artifact alongside fetch output
- suggested file: `browserstack-diagnostics.json`

Suggested schema:
- `build_id`
- `build_status`
- `sessions[]`
- per session:
  - `device`
  - `session_id`
  - `session_status`
  - `testcase_status`
  - `payload_recovered`

Why:
- repo workflows should not need bespoke `jq` parsing for common BrowserStack failure triage

### 6. Make incomplete BrowserStack terminal states explicit in `mobench` exit behavior

Current repo workflow still checks this outside `mobench`:
- fetched build status still `running`
- fetched session status still `running`
- testcase status contains `running`, `failed`, `error`, or `timedout`

What should be upstreamed:
- `mobench` should distinguish:
  - successful completed run with payloads
  - completed run with provider-side failures
  - timed-out / still-running provider state

Why:
- CI should not need to infer terminal state correctness from raw BrowserStack JSON

### 7. Preserve artifact fetch outputs for failure cases as a documented contract

Current repo behavior:
- upload raw BrowserStack artifacts on both success and failure
- validate against those raw artifacts after `ci run`

What should be upstreamed:
- document that `--fetch-output-dir` is populated even when fetch/result handling fails partway through
- avoid cleanup paths that discard partially fetched diagnostic artifacts

Why:
- partial artifact preservation is necessary for debugging long-running remote failures

## Not upstream targets

These are repo policy, not `mobench` features:

- `smoke` vs `triad` profile names and exact device lists
- ProveKit’s PR comment policy
- ProveKit-specific benchmark function selection
- ProveKit-specific failure threshold for empty summaries

## Exit criterion for dropping the local patch

We can remove the local patch when upstream `mobench` exposes:

1. configurable iOS completion timeout
2. guaranteed iOS bundling of the requested bench spec
3. hard failure on unrecovered fetch errors
4. built-in CI validation and diagnostics good enough to replace the local shell script
