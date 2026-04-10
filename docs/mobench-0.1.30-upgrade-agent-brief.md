# Agent Brief: Upgrade ProveKit to `mobile-bench-rs` `0.1.30`

## Use This As The Delegation Prompt

> Upgrade ProveKit from the locally patched `mobile-bench-rs` `0.1.29`
> integration to upstream `0.1.30`. Start by proving which repo-local fixes are
> actually upstream in `0.1.30`, minimize the remaining local patch instead of
> assuming it can be dropped, keep the current `smoke`/`triad` workflow
> contract, and do not weaken validation. Acceptance requires successful manual
> BrowserStack smoke runs for `platform=ios`, `platform=android`, and
> `platform=both`, with fetched artifacts that match the requested benchmark
> spec and with summary rows that include both `cpu_total_ms` and
> `peak_memory_kb`.

## Objective

Upgrade ProveKit’s mobile benchmark integration to upstream
`mobile-bench-rs` `0.1.30`, then remove or shrink the local patch in
[mobile-bench-rs-browserstack-devices.patch](/Users/dcbuilder/Code/world/ProveKit/.github/patches/mobile-bench-rs-browserstack-devices.patch)
only where upstream behavior is proven equivalent.

This is not just a dependency bump. It is an upstream-audit, integration, and
remote-verification task.

## Required Outcome

At the end of the work:

- the workspace resolves `mobench-sdk` / `mobench-macros` to `0.1.30`
- `cargo mobench` installation in CI is pinned to `0.1.30`
- any remaining local patch surface is intentional, minimal, and documented
- iOS and Android BrowserStack smoke runs produce non-empty results
- fetched results match the requested benchmark spec exactly
- every reported benchmark row includes:
  - `resource_usage.cpu_total_ms`
  - `resource_usage.peak_memory_kb`
- empty, mismatched, failed, timed-out, or incomplete remote runs fail red

## Read First

Before changing anything, read:

1. [README.md](/Users/dcbuilder/Code/world/ProveKit/README.md)
2. [overview.md](/Users/dcbuilder/Code/world/ProveKit/overview.md)
3. [Cargo.toml](/Users/dcbuilder/Code/world/ProveKit/Cargo.toml)
4. [docs/mobench-integration-plan.md](/Users/dcbuilder/Code/world/ProveKit/docs/mobench-integration-plan.md)
5. [docs/mobench-0.1.30-upstream-notes.md](/Users/dcbuilder/Code/world/ProveKit/docs/mobench-0.1.30-upstream-notes.md)
6. [mobile-bench-reusable.yml](/Users/dcbuilder/Code/world/ProveKit/.github/workflows/mobile-bench-reusable.yml)
7. [validate_mobile_bench_outputs.sh](/Users/dcbuilder/Code/world/ProveKit/.github/scripts/validate_mobile_bench_outputs.sh)
8. [mobile-bench-rs-browserstack-devices.patch](/Users/dcbuilder/Code/world/ProveKit/.github/patches/mobile-bench-rs-browserstack-devices.patch)

## Constraints

- Do not widen benchmark scope beyond
  `bench_mobile::bench_passport_complete_age_check_prove`
- Keep PR-triggered runs on the `smoke` profile unless explicitly instructed
  otherwise
- Preserve the current repo contract:
  - only `smoke` and `triad` device profiles exist
  - PR auto runs default to `smoke`
  - PR comment command defaults to `smoke`
- Do not remove repo-side validation until upstream `0.1.30` behavior is
  proven equivalent
- Do not touch unrelated local files or revert unrelated worktree dirt

## Proven Current Baseline

These facts have already been established in ProveKit’s current patched
`0.1.29` integration:

- iOS smoke run
  [24210777930](https://github.com/dcbuild3r/provekit/actions/runs/24210777930)
  succeeded with:
  - requested spec = actual spec
  - `performance_metrics == {}`
  - summary `resource_usage.cpu_total_ms` present
  - summary `resource_usage.peak_memory_kb` present
- combined smoke run
  [24247366652](https://github.com/dcbuild3r/provekit/actions/runs/24247366652)
  succeeded end to end for `platform=both` with:
  - iOS requested spec = actual spec
  - Android requested spec = actual spec
  - iOS summary resource usage:
    - `cpu_total_ms = 59097`
    - `peak_memory_kb = 1661025`
  - iOS raw resources:
    - `elapsed_cpu_ms = 59097`
    - `peak_memory_kb = 1661025`
  - Android summary resource usage:
    - `cpu_total_ms = 167780`
    - `peak_memory_kb = 1402112`
- Android smoke runs already succeed with both metrics present
- the current validator intentionally fails if:
  - `summary.device_summaries` is empty
  - `results.csv` has no data rows
  - actual benchmark spec differs from requested spec
  - any benchmark row is missing `cpu_total_ms` or `peak_memory_kb`
  - BrowserStack state is incomplete, failed, or timed out

The upgrade must preserve that bar.

## Upstream Requirements To Verify In `0.1.30`

Do not remove local behavior until each requirement is checked against the
actual upstream `0.1.30` source.

1. Configurable iOS completion timeout
2. iOS `bench_spec.json` survives regeneration and is bundled into the app
3. generated iOS runner emits raw benchmark resource fields:
   - `resources.elapsed_cpu_ms`
   - `resources.peak_memory_kb`
4. summary/resource extraction honors raw `resources.peak_memory_kb` when
   BrowserStack profiling is absent
5. failed or timed-out fetches become hard failures when no benchmark payloads
   are recovered
6. upstream validation is good enough to replace or simplify repo validation,
   without weakening behavior
7. BrowserStack diagnostics are good enough for CI triage
8. partial fetch artifacts are preserved on failure

## Execution Instructions

### Phase 1: Audit Upstream `0.1.30`

1. Clone `mobile-bench-rs` upstream and check out the exact `0.1.30` tag.
2. Diff upstream `0.1.30` against the repo-local patch contract described in
   [mobench-0.1.30-upstream-notes.md](/Users/dcbuilder/Code/world/ProveKit/docs/mobench-0.1.30-upstream-notes.md).
3. Produce a concrete gap list with three buckets:
   - upstream complete
   - upstream partial
   - still repo-local
4. If a critical requirement is still missing, keep the minimum local patch for
   it. Do not block the whole upgrade if the gap is small and well-bounded.

### Phase 2: Upgrade ProveKit

1. Bump the workspace dependency version in
   [Cargo.toml](/Users/dcbuilder/Code/world/ProveKit/Cargo.toml).
2. Regenerate [Cargo.lock](/Users/dcbuilder/Code/world/ProveKit/Cargo.lock).
3. Update the workflow install pin in
   [mobile-bench-reusable.yml](/Users/dcbuilder/Code/world/ProveKit/.github/workflows/mobile-bench-reusable.yml)
   to `0.1.30`.
4. Update docs that still mention `0.1.29`.

### Phase 3: Rebuild The Local Patch

1. Rebase or regenerate
   [mobile-bench-rs-browserstack-devices.patch](/Users/dcbuilder/Code/world/ProveKit/.github/patches/mobile-bench-rs-browserstack-devices.patch)
   against upstream `0.1.30`.
2. Delete hunks for behavior that is now genuinely upstream.
3. Keep only the smallest repo-local delta that is still required.
4. Update workflow grep assertions so they prove the remaining patch contract,
   not the old `0.1.29` patch content.

### Phase 4: Reconcile Validation

1. Re-read
   [validate_mobile_bench_outputs.sh](/Users/dcbuilder/Code/world/ProveKit/.github/scripts/validate_mobile_bench_outputs.sh)
   against the actual `0.1.30` output shape.
2. Keep repo-side checks for all behaviors that upstream still does not enforce.
3. At minimum, preserve these checks unless upstream demonstrably enforces them:
   - non-empty `summary.device_summaries`
   - non-empty `results.csv`
   - requested spec equals actual spec
   - every benchmark row reports `cpu_total_ms` and `peak_memory_kb`
   - BrowserStack build/session/testcase states are complete and successful

## Exact Verification Commands

Use these as the baseline verification flow. Adjust only if the workflow
interface changes during the upgrade.

### Local Verification

Run:

```bash
cargo test -p bench-mobile embedded_passport_fixture_proves_and_verifies -- --nocapture
```

Verify the workspace resolves `mobench-sdk` to `0.1.30`:

```bash
cargo metadata --format-version 1 --locked \
  | jq -r '.packages[] | select(.name=="mobench-sdk") | .version'
```

If a patch still exists, verify it applies to a clean upstream `0.1.30`
checkout:

```bash
git -C /tmp/mobench-0.1.30-check apply --check \
  /Users/dcbuilder/Code/world/ProveKit/.github/patches/mobile-bench-rs-browserstack-devices.patch
```

### Manual GitHub Actions Runs

Dispatch the workflow from the current branch HEAD:

```bash
HEAD_SHA="$(git rev-parse HEAD)"
gh workflow run .github/workflows/mobile-bench.yml \
  -R dcbuild3r/provekit \
  -f platform=ios \
  -f device_profile=smoke \
  -f iterations=2 \
  -f warmup=1 \
  -f head_sha="$HEAD_SHA"

gh workflow run .github/workflows/mobile-bench.yml \
  -R dcbuild3r/provekit \
  -f platform=android \
  -f device_profile=smoke \
  -f iterations=2 \
  -f warmup=1 \
  -f head_sha="$HEAD_SHA"

gh workflow run .github/workflows/mobile-bench.yml \
  -R dcbuild3r/provekit \
  -f platform=both \
  -f device_profile=smoke \
  -f iterations=2 \
  -f warmup=1 \
  -f head_sha="$HEAD_SHA"
```

After smoke is stable, run one `triad` verification:

```bash
gh workflow run .github/workflows/mobile-bench.yml \
  -R dcbuild3r/provekit \
  -f platform=both \
  -f device_profile=triad \
  -f iterations=2 \
  -f warmup=1 \
  -f head_sha="$HEAD_SHA"
```

### Artifact Inspection

For each completed run, download the platform artifact and inspect the summary:

```bash
RUN_ID="REPLACE_ME"
PLATFORM="ios" # or android
DEST="/tmp/mobench-results-${PLATFORM}-${RUN_ID}"

rm -rf "$DEST" && mkdir -p "$DEST"
gh run download "$RUN_ID" -R dcbuild3r/provekit -n "mobench-results-${PLATFORM}" -D "$DEST"
```

Check requested spec, actual spec, and summary resource usage:

```bash
jq '
  {
    requested_spec: {
      function: .spec.function,
      iterations: .spec.iterations,
      warmup: .spec.warmup
    },
    actual_specs: [
      (.benchmark_results // {})
      | to_entries[]?
      | .value[]?
      | {
          function: (.function // .spec.name),
          iterations: (.spec.iterations // .iterations),
          warmup: (.spec.warmup // .warmup)
        }
    ] | unique,
    benchmark_resource_usage: (
      (.summary.device_summaries[0].benchmarks[0].resource_usage // {})
    )
  }
' "$DEST"/mobench/ci/"$PLATFORM"/summary.json
```

For iOS, explicitly verify that raw payload metrics exist even when provider
profiling is absent:

```bash
jq '
  {
    performance_metrics: .performance_metrics,
    raw_resources: .benchmark_results["iPhone 16 Pro"][0].resources,
    summary_resource_usage: .summary.device_summaries[0].benchmarks[0].resource_usage
  }
' "$DEST"/mobench/ci/ios/summary.json
```

Acceptance for iOS is:

- `performance_metrics` may be `{}` and that is acceptable
- raw resources must include:
  - `elapsed_cpu_ms`
  - `peak_memory_kb`
- summary resource usage must still include:
  - `cpu_total_ms`
  - `peak_memory_kb`

Acceptance for Android is:

- summary resource usage still includes:
  - `cpu_total_ms`
  - `peak_memory_kb`
- Android heap-derived fields must not regress unexpectedly

## Mandatory Acceptance Checks

Every successful remote platform run must satisfy all of the following:

1. requested benchmark spec equals actual reported spec
2. `summary.device_summaries` is non-empty
3. `results.csv` contains at least one benchmark row
4. every benchmark row reports:
   - `resource_usage.cpu_total_ms`
   - `resource_usage.peak_memory_kb`
5. fetched BrowserStack state is terminal and successful

The upgrade is not accepted if a run merely turns green while emitting empty or
mismatched samples.

## Failure Handling

If upstream `0.1.30` still misses any required behavior:

1. keep the minimal local patch for that gap
2. document the remaining gap in
   [mobench-0.1.30-upstream-notes.md](/Users/dcbuilder/Code/world/ProveKit/docs/mobench-0.1.30-upstream-notes.md)
3. update workflow grep assertions to match the remaining patch contract
4. do not describe the repo as fully unpatched

If smoke passes but `triad` fails:

1. keep `smoke` as the default PR profile
2. preserve all triad diagnostics and fetched artifacts
3. report triad as a separate follow-up gap instead of weakening smoke

## Deliverables

The final change set should include:

- the `0.1.30` dependency upgrade
- updated workflow install pinning
- refreshed docs
- a minimized local patch, or no patch if all requirements are upstream
- exact verification commands and run links
- a short summary of what remains repo-local, if anything

## Definition Of Done

This upgrade is done only when:

- ProveKit resolves and installs `mobile-bench-rs` `0.1.30`
- iOS smoke succeeds
- Android smoke succeeds
- combined `platform=both` smoke succeeds
- all required metrics appear in fetched summaries
- triad is either verified or its remaining gap is isolated and documented
- the remaining patch surface, if any, is intentional and explained
