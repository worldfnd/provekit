# Adding browser/WASM execution to mobile-bench-rs

## Assessment

This is a medium-sized addition, not a new `mobench-sdk` timing backend.
`mobile-bench-rs` currently builds native Android/iOS applications, uploads
them to BrowserStack App Automate, and retrieves native-runner results. Mobile
Safari and Chrome instead require BrowserStack Automate/WebDriver, a static web
bundle, and either BrowserStack Local or an immutable HTTPS deployment.

The existing project can still provide the trusted-CI and reporting layers:

- immutable prebuilt manifest verification;
- function/device shard accounting;
- `summary.json`, `summary.md`, and `results.csv`;
- split-run merge and PR reporting; and
- credential isolation between untrusted preparation and trusted execution.

The native process-memory and profiling code cannot be reused for browsers.
Browser results must label JavaScript heap, WASM linear memory, provider
telemetry, and unavailable values separately.

## Recommended implementation

1. Add a `web-prebuilt` artifact kind containing an entry page, static manifest,
   benchmark ABI/schema version, and supported execution modes.
2. Add an Automate/WebDriver provider beside the existing App Automate client,
   not inside the native Android/iOS runners.
3. Treat `ios-safari`, `android-chrome`, and `macos-browser` as browser
   environments, while preserving the physical device/OS resolved by
   BrowserStack.
4. Poll the page's stable result protocol and normalize its samples into the
   existing report layer.
5. Require COOP/COEP headers for threaded builds and maintain a single-thread
   build for Safari and other environments without shared-memory support.
6. Keep BrowserStack Local lifecycle and immutable HTTPS hosting as explicit,
   interchangeable transports.

The runner in `benchmarks/v1/wasm/` is a working spike for steps 1-4: it uses a
Worker, exposes `window.__MOBENCH_STATE__`, verifies the static manifest before
opening WebDriver, and emits a schema-versioned result.

## Effort and risk

- ProveKit-only working lane: roughly 2-4 engineering days after credentials
  and a supported device/OS pair are available.
- Generalized, reviewed `mobile-bench-rs` feature: roughly 1-2 weeks, including
  provider abstractions, trusted prebuilt schema changes, tests, docs, and one
  Android plus one iOS service-gated run.
- Main risks: Safari memory termination without an exact peak-memory API,
  BrowserStack device catalog drift, Local tunnel reliability, large bundle
  transfer time, threaded-WASM header requirements, and accidentally merging
  native and browser results into one comparison row.

The smallest safe upstream change is therefore to reuse Mobench's immutable
prebuilt/reporting contract while keeping browser execution as a separate
provider and platform family.
