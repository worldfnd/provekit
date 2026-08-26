# ProveKit JS SDK

Browser-first TypeScript SDK for ProveKit WASM proving and verification.

The package wraps the generated `provekit-wasm` bindings and exposes a small client-facing API: load ProveKit artifacts once, then call `prove()` and `verify()`.

## Install

The SDK is currently consumed from source via the `provekit-js` package. Once published it can be installed with:

```sh
npm install provekit-sdk
```

## Quick start (Mavros prover)

A Mavros prover ships with an extra `program.wasm` artifact and does not need a host-side witness generator.

```ts
import initWasm, * as provekitWasm from "./pkg/provekit_wasm.js";
import { createProveKit } from "provekit-sdk";

const provekit = await createProveKit({
  bindings: provekitWasm,
  init: initWasm,
  wasmModule: new URL("./pkg/provekit_wasm_bg.wasm", import.meta.url),
  threads: navigator.hardwareConcurrency,
});

// Loads prover.pkp, verifier.pkv, and program.wasm from /artifacts/.
const scheme = await provekit.loadArtifacts("/artifacts/");

const proof = await scheme.prove({ input: "42" });
await scheme.verify(proof);  // throws on rejection
scheme.dispose();
```

## Quick start (Noir prover)

A Noir prover needs a `witnessProvider` that runs the Noir circuit to produce the witness map. The SDK does not bundle Noir frontend packages — supply them yourself:

```ts
import { decompressWitnessStack } from "@noir-lang/acvm_js";
import { Noir } from "@noir-lang/noir_js";
import { createProveKit, type WitnessProvider } from "provekit-sdk";

const witnessProvider: WitnessProvider = {
  async generateWitness(inputs, circuit) {
    const noir = new Noir(circuit as never);
    const { witness } = await noir.execute(inputs as never);
    const stack = decompressWitnessStack(witness);
    return stack[0]!.witness;
  },
};

const scheme = await provekit.loadArtifacts({
  baseUrl: "/artifacts/",
  witnessProvider,
});

const proof = await scheme.prove({ x: "42" });
await scheme.verify(proof);
scheme.dispose();
```

## Artifact naming

`loadArtifacts(baseUrl)` resolves these standard files under the URL:

| File           | Required           | Purpose                           |
| -------------- | ------------------ | --------------------------------- |
| `prover.pkp`   | always             | serialized prover key             |
| `verifier.pkv` | unless `skipVerifier: true` | serialized verifier key  |
| `program.wasm` | Mavros provers     | witness generation and derivatives module |

Pass `BytesInput` (URL, fetch input, or raw bytes) to override any of them:

```ts
await provekit.loadArtifacts({
  prover: myProverBytes,
  verifier: myVerifierBytes,
  provingModules: { program: programBytes },
});
```

Legacy split `witgen.wasm` and `ad.wasm` modules remain supported.

## API surface

- `createProveKit(options)` — initializes the WASM module, optional panic hook, and thread pool. Returns a `ProveKit`.
- `provekit.loadArtifacts(input)` — loads a prover (and optional verifier + Mavros modules). Returns a `ProveKitScheme`.
- `scheme.prove(inputs)` — produces a `Proof`. **Consumes the prover** — call `loadArtifacts` again to prove another input set.
- `scheme.verify(proof)` — throws on rejection or setup errors.
- `scheme.tryVerify(proof)` — returns a boolean (`true` on success, `false` on rejection); still throws if no verifier was loaded.
- `scheme.dispose()` — frees WASM handles. Safe to call multiple times and after `prove()`.

## Notes

- Some proving modes execute supplied WASM modules in the page. Only load artifacts from trusted origins.
- Threaded WASM requires cross-origin isolation headers:
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cross-Origin-Embedder-Policy: require-corp`
