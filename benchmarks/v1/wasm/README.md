# ProveKit V1 browser/WASM lane

The canonical Mac browser measurements build ProveKit V1 from the immutable
core commit in `../sources.lock.json` and run Chrome with exactly 16 WASM
workers. The threaded package is kept in `v1-wasm-pkg-threaded/` and the build
manifest records the request and effective worker count.

Build and smoke the fixed-16 package:

```bash
cd benchmarks/v1/wasm
bun install --frozen-lockfile
MOBENCH_WASM_THREADS=16 INPUT_TO_PROOF_EXECUTION_POLICY=multithread bun run build
MOBENCH_WASM_THREADS=16 MOBENCH_SNARKJS_THREADS=16 bun run smoke
```

The smoke gate requires `crossOriginIsolated`, `SharedArrayBuffer`, an
initialized Rayon pool, valid-proof acceptance, and tampered-proof rejection.
The browser runner records process RSS, proof bytes, payload bytes, runtime
identity, and worker counts. Mac-native runs are diagnostic and are not merged
into the browser target.

`MOBENCH_WASM_THREADS=single` is available only for historical diagnostics;
the canonical entrypoint defaults to the fixed-16 threaded build. Superseded
single/automatic-thread exports are under [`../legacy/`](../legacy/README.md).
