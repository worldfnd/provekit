# @worldcoin/provekit

First-party browser API for loading ProveKit artifacts, executing Noir inputs
locally, and proving and verifying with ProveKit WebAssembly.

```ts
import { initProveKit } from "@worldcoin/provekit";

const runtime = await initProveKit({ threads: "auto" });
const prover = await runtime.loadProver(pkpBytes);
const verifier = await runtime.loadVerifier(pkvBytes);

const proof = await prover.prove({ secret: "1" });
const valid = await verifier.verify(proof);

prover.dispose();
verifier.dispose();
```

Threaded mode requires `SharedArrayBuffer` and a cross-origin-isolated page:

```text
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

`threads: "auto"` selects the bundled threaded build when supported and falls
back to the separate scalar, non-shared-memory build. The fallback deliberately
does not require SIMD or relaxed SIMD, so it can initialize on Safari/WebKit.
An explicit positive thread count fails with `THREADS_UNAVAILABLE` if the
requested pool cannot be created. iOS and iPadOS use the single-threaded build
in auto mode.

The package accepts current binary ProveKit artifacts only: PKP 2.0+ and PKV
2.1+ with the same major version. Legacy PKP 1.1 / PKV 1.2 artifacts must be
regenerated with the repository's current Noir 1.0.0-beta.20 toolchain.

The browser defaults accept at most 64 MiB for each compressed prover/verifier
artifact and 16 MiB for a proof. The low-level Rust decoder independently caps
compressed input at 64 MiB and expanded postcard data at 256 MiB. Applications
should configure smaller limits when their known artifacts permit it.

## Building

`npm run build:wasm` builds a threaded SIMD artifact and a scalar Safari-safe
fallback with the repository-pinned toolchain, derives the exact
`wasm-bindgen-cli` version from `Cargo.lock`, and optimizes each with its
matching WebAssembly feature set. `npm run build` then bundles TypeScript and
copies the generated glue, `.wasm`, declarations, and rayon snippets into
`dist/wasm`.

Consumers may override the bundled glue with `wasmModule` and the binary input
with `wasmUrl`, which is useful for CSP-controlled hosting or tests.
