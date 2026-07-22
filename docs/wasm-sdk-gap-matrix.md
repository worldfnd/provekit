# First-party WASM SDK gap matrix

This document records the design boundary for a production-shaped ProveKit browser SDK. It compares fresh ProveKit `main` at `4b61b5d68e633a044eb41de4a6934d52ffdcbedc` with the Verity reference implementation inspected at `3f6b8ad6e7c994a740a204fbf35c0a3f3001e4d3`. It is a migration and acceptance record, not a performance report.

## Decision summary

- Keep ProveKit's Rust/WASM proof engine and add the smallest first-party TypeScript layer above it. Do not import Verity's generic multi-backend factory.
- Current artifacts are PKP 2.0 and PKV 2.1, generated with ProveKit's Noir 1.0.0-beta.20 frontend. The first-party SDK must reject incompatible major versions before decompression/deserialization.
- The World ID passkey fixture is legacy PKP 1.1/PKV 1.2, generated with Noir 1.0.0-beta.11 and ProveKit 0.1.4. It is not safe to load on current `main` and must be regenerated after a reviewed source/dependency migration.
- Verity remains a useful behavior and packaging reference. It is not a runtime dependency of the first-party SDK.

## Gap matrix

| Capability | Fresh ProveKit `main` | Verity reference | First-party decision / acceptance gate |
| :--- | :--- | :--- | :--- |
| Low-level proof engine | `provekit-wasm` loads binary PKP/PKV, exposes `getCircuit()`, consumes a WASM prover for one proof, and reuses a verifier. | Calls the same native ProveKit binding. | Retain the Rust engine. Reconstruct the low-level prover behind a reusable logical TypeScript handle. |
| Artifact validation | Checks magic, format identifier, major/minor version, compression, and postcard payload. | Maps loader failures into SDK errors. | Reject before deserialization with observed and expected versions. Never accept v1 by rewriting headers. Add input and decompression bounds. |
| High-level inputs | Low-level binding accepts a witness map. | Executes embedded circuit ABI with Noir/ACVM from object or JSON input. | First-party `prover.prove(inputs)` owns this bridge and pins compatible Noir packages. Guard witness-key conversion rather than depending silently on undocumented `.inner` fields. |
| Runtime API | Direct generated WASM exports. | Higher-level backend/factory API. | Export `initProveKit()`, `loadProver()`, `loadVerifier()`, `prove()`, `verify()`, and idempotent `dispose()` without a multi-backend abstraction. |
| Initialization | Panic hook and Rayon thread-pool export exist. | Coordinates WASM setup and threads. | Race-safe singleton; concurrent callers share success, failed initialization remains retryable, and callers may override the WASM module/URL. |
| Threading | Rayon requires worker assets, `SharedArrayBuffer`, and cross-origin isolation. | Has browser/device fallback logic. | Support `false`, explicit count, and `"auto"`. Auto falls back to one thread. Require COOP/COEP for threaded mode and test deployed worker asset resolution. |
| iOS/WebKit | No production policy in the low-level binding. | Defaults/falls back conservatively. | Treat iOS/iPadOS as single-threaded until the exact deployment passes E2E; do not infer success from initialization alone. |
| Lifecycle | Generated WASM handles expose `.free()`; the low-level prover is consumed. | Wraps handles, but reference cleanup is not the acceptance standard. | Free native handles, make disposal idempotent, reject use after disposal, and release retained byte/input references when practical. Document JavaScript zeroization limits. |
| Errors | Mostly JavaScript errors with string messages. | Adds SDK error mapping. | Stable typed categories for initialization, artifact/version, input/witness, proving, malformed proof, invalid proof, OOM, threads, and disposed state. Mathematical invalidity returns `false`; malformed bytes throw. |
| Sensitive data | Engine need not make network requests. | Local witness generation. | No default logging of inputs, witnesses, assertions, or full proofs. Browser test must prove no witness-bearing request occurs. Do not silently fall back to remote proving. |
| Package contents | Build comments describe manual `cargo build`, `wasm-bindgen`, and `wasm-opt`. | Copies glue, WASM, workers, snippets, and types into a package. | Packed artifact must contain all runtime assets and work from a consumer project with Vite-safe resolution. Pin `wasm-bindgen`; preserve SIMD/thread/bulk-memory flags. |
| Testing | Rust header, decompression, and witness-map tests exist. | JS unit and browser examples exist. | Add Rust and TypeScript negative tests, packed-package smoke, single/threaded browser E2E, tamper rejection, repeated calls, and network inspection. |
| Production fixture | Toy/examples exist; no current passkey-sized acceptance result. | Reference flows are not proof of this package's production circuit behavior. | Use the passkey circuit externally only after compatibility and licensing review. Measure memory/timing in a real browser; do not estimate or claim success. |
| Release | No first-party npm publication is implied by the low-level crate. | Has package/release conventions. | Package/version docs and CI evidence are required, but publishing is a separately authorized operation. Never publish from a development task. |

## Legacy passkey artifact evidence

The external World ID fixture at commit `85aeeef539961cae5a63de794997b507a5975717` contains:

| File | On-disk size | Decompressed payload | Format | SHA-256 |
| :--- | ---: | ---: | :--- | :--- |
| `passkey_ownership_proof.pkp` | 2,663,088 bytes | 50,264,351 bytes | PKP 1.1, 20-byte header, XZ | `007b1a21d668ce3d3753fadb376fe85d25e8b921c5a070f1b4d35669bd506558` |
| `passkey_ownership_proof.pkv` | 4,711,891 bytes | 10,592,553 bytes | PKV 1.2, 20-byte header, Zstd | `faf20fc90f82054fa4134745edac01bfb08fca73c7953ae3c1df45043d7d3906` |

Current `main` uses a 21-byte header with hash configuration and expects PKP 2.0/PKV 2.1. Even if the major-version check were bypassed, the reader would consume the legacy compression byte as hash configuration and then attempt to deserialize incompatible data. Keeping the hard rejection is a correctness requirement.

## Deterministic regeneration path

After the circuit compiles unchanged in meaning with the pinned beta.20 frontend:

```sh
cargo run --release --bin provekit-cli -- prepare \
  /absolute/path/to/passkey-ownership-proof \
  --force \
  --pkp /absolute/path/to/artifacts/passkey_ownership_proof.pkp \
  --pkv /absolute/path/to/artifacts/passkey_ownership_proof.pkv
```

The regeneration record must include:

1. ProveKit commit, `Cargo.lock`, `rust-toolchain.toml`, and exact command.
2. Noir revision `v1.0.0-beta.20` / `b4236c1957d0c26cb65d82adc9e5447b6ff1d629`.
3. Content-addressed or audited vendored provenance for every Noir dependency; tag-only references are insufficient for a long-lived reproducibility claim.
4. Hash configuration, artifact header versions, byte lengths, and SHA-256 checksums.
5. ABI/public-input comparison, constraint statistics, and positive/negative vectors covering challenge, RP ID, signature, passkey slot, and Merkle path binding.
6. Native prove/verify followed by packed-SDK single-threaded browser prove/verify before downstream replacement.

### Current beta.20 blockers

An isolated beta.20 compile stops before artifact generation with nine errors:

- `TaceoLabs/noir-poseidon` `v0.5.0-beta.0` imports the removed `std::collections::vec::Vec` path and contains a bool/Field comparison that no longer type-checks.
- `noir-lang/poseidon` `v0.2.6` calls the old two-argument `poseidon2_permutation` API.
- vendored `noir_bigcurve-mavros` uses removed `u1`; beta.20 requires `bool`.

Resolving these may be source-compatible maintenance, but it is not yet proven semantics-preserving. Stop and obtain cryptographic review if the fix changes constraints, ABI, commitment ordering, public inputs, or signature/Merkle checks.

## External fixture licensing and measurement gaps

The fixture is about 8.28 MB tracked: about 7.37 MB of PKP/PKV files, 0.90 MB of vendored source, and 6.7 KB of top-level circuit source. Before copying any part into ProveKit:

- retain the World ID circuit/repository MIT notice;
- retain Apache-2.0 notices shipped with vendored WebAuthn and `noir-bignum-mavros`;
- resolve the missing copied license/provenance for `noir_bigcurve-mavros` and the locally added `nodash` shim;
- resolve licenses and exact commits for remote Poseidon, Base64, and SHA packages;
- prefer an external acceptance fixture until repository-size and notice policy are approved.

No passkey-sized browser measurement is recorded. Required evidence includes browser/OS/version, SDK and artifact versions, thread mode/count, initialization time, witness time, proof time, verification time, proof bytes, peak memory measurement method/result, repeated-run behavior, and network capture showing no witness upload.

## Packed-package browser acceptance

On 2026-07-22, the packed `@worldcoin/provekit` package passed its current-format SHA-256 example in headless Chromium 149.0.7827.55 on macOS 26.5.1 arm64. Each run loaded PKP 2.0/PKV 2.1, proved twice with one logical prover, reused one verifier, and rejected a public-input-tampered proof. After entering the sensitive witness/proving phase, the test observed exactly the two expected same-origin lazy Noir/ACVM WASM fetches, with no query strings, request bodies, custom headers, unexpected paths, or WebSockets.

| Requested mode | Actual mode | Initialization | First proof | Second proof | Two verifications | Proof size |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| `false` | single, 1 thread | 12.65 ms | 2,513.31 ms | 2,410.56 ms | 470.02 ms | 512,251 bytes |
| `"auto"` | threaded, 8 threads | 48.96 ms | 854.70 ms | 761.79 ms | 125.58 ms | 509,819 bytes |

These are local acceptance measurements, not benchmarks. Playwright did not expose a reliable peak process-memory measurement in this run, and the blocked legacy passkey fixture was not executed. Passkey-sized peak memory, witness time, and proof time remain explicitly unmeasured until the beta.20 circuit migration and licensing gates above are resolved.

## Release boundary

“Production-shaped” means the API, package, errors, lifecycle, and tests support a production review. It does not authorize npm publication, claim an audited circuit, or prove production browser performance. Publication, downstream artifact replacement, and a production-readiness claim each require separate evidence and approval.
