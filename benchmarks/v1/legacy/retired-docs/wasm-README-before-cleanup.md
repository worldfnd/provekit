# Browser/WASM benchmark lane

Browser proving is an execution backend, not a mobile target. Native device
runs continue to use BrowserStack App Automate; real browser runs require
BrowserStack Automate/WebDriver and a static HTTPS site or BrowserStack Local.

The V1 WASM crate exposes the threaded runtime needed for the Mac campaign:

- `parallel` plus `wasm-bindgen-rayon`: the shared-memory worker build;
- the historical runner policy, which never calls `initThreadPool`, is the
  single-thread baseline. The generated V1 package is kept pinned to the same
  V1 commit for both policies.

Select the policy with `MOBENCH_WASM_THREADS=single` (default), `auto`, or an
explicit count from 2 through 32. `auto` records a single-thread fallback with
the reason when the page is not cross-origin isolated; an explicit count fails
instead of silently producing a scalar measurement. The generated package
manifest records the build variant and requested policy, while each result
records the actual pool mode and count.

`bun run build` keeps the threaded generated package in
`v1-wasm-pkg-threaded/` (and mirrors it into the ignored Vite import alias for
that build). Direct invocations of `build-provekit-v1-wasm.sh` can select an
explicit output with `PROVEKIT_V1_WASM_PACKAGE_DIR`.

The first gate is a local macOS browser smoke. The multithread campaign must
report `crossOriginIsolated`, `SharedArrayBuffer`, and an initialized Rayon
pool before its timings are accepted. Only after that passes should the same immutable static bundle run through
BrowserStack Local on mobile Safari and Chrome.

The publication workflow also uses Mobench 0.1.48's `build --target web` and
`run-web` path. Its repository-owned adapter is
`bench-mobile/src/lib_web.rs`; `bench-mobile/scripts/prepare-web-benchmarks.sh`
generates the seven complete/fragmented/WebAuthn/OPRF witnesses outside
measurement and selects the portable browser dependency graph. The workflow
builds one bundle per workload and runs all four primary proof functions
against four BrowserStack Automate environments.

Build and run that gate with:

```bash
cd benchmarks/v1/wasm
bun install --frozen-lockfile
MOBENCH_WASM_THREADS=auto bun run build
MOBENCH_WASM_THREADS=auto bun run smoke
```

Omit `MOBENCH_WASM_THREADS=auto` for the historical single-thread build and
smoke.

The build uses a separate Cargo target directory and overrides the repository's
threaded WASM linker flags. The pinned V1 `provekit-wasm` crate always exports
the Rayon hooks, so the historical single-thread lane is defined by not
initializing the pool rather than by replacing the V1 proving artifact.

The browser runner must report:

- initialization, witness, prove, and verify time;
- proof and bundle bytes;
- circuit constraint/witness counts;
- browser/device/runtime metadata;
- success, verification failure, timeout, crash, or likely OOM; and
- memory metrics with their exact scope.

Portable browser process RSS is unavailable. Chromium heap APIs and WASM
linear-memory size are best-effort metrics; Safari peak memory must not be
presented as exact.

The initial runner reports Chromium's used JavaScript heap only when available,
and labels it as neither WASM high-water memory nor process RSS.

## BrowserStack real-device command

First resolve an available iPhone SE 2022 and iOS pairing in BrowserStack's
current device catalog. The matrix deliberately does not hard-code iOS 15:
availability and the browser/WASM runtime must be checked immediately before a
publication run. Freeze the selected version in the command environment and in
the saved result.

Start a BrowserStack Local tunnel with a unique local identifier, then run:

```bash
export BROWSERSTACK_USERNAME='...'
export BROWSERSTACK_ACCESS_KEY='...'
export BROWSERSTACK_LOCAL_IDENTIFIER='provekit-v1-unique-id'
export BROWSERSTACK_OS_VERSION='resolved-version'
bun run browserstack -- ios_safari_single
```

The command serves the already-built `dist/` bundle, verifies every file
against `dist/manifest.json` before opening a paid session, and emits one JSON
record conforming to `browserstack-run.schema.json`. It never writes or prints
the BrowserStack credentials. Use `MOBENCH_WARMUP` and `MOBENCH_ITERATIONS` to
override the publication defaults of one and five.

Bundle verification can be run without credentials or a paid session:

```bash
bun run browserstack -- --verify-bundle
```

Do not put BrowserStack secrets in feature-branch jobs. A trusted runner must
verify a static asset manifest (path, size, SHA-256, MIME type, no symlinks)
before serving it and opening the credentialed WebDriver session.
