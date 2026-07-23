# Browser/WASM benchmark lane

Browser proving is an execution backend, not a mobile target. Native device
runs continue to use BrowserStack App Automate; real browser runs require
BrowserStack Automate/WebDriver and a static HTTPS site or BrowserStack Local.

The V1 WASM crate now exposes separate build modes:

- default/`parallel`: the existing shared-memory worker build;
- `--no-default-features`: the single-thread module required by iOS Safari.

The first gate is a local macOS browser smoke using the single-thread module.
Only after that passes should the same immutable static bundle run through
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
bun run build
bun run smoke
```

The build uses a separate Cargo target directory and overrides the repository's
threaded WASM linker flags. Merely disabling the `parallel` feature does not
remove the shared-memory flags in the repository-wide `.cargo/config.toml`.

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
