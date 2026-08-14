# Reproducing the V1 input-to-proof campaign

This is the canonical reproduction contract for
[`input-to-proof-data/input-to-proof-samples.csv`](input-to-proof-data/input-to-proof-samples.csv).
Do not use the files under `legacy/` as inputs to this campaign.

## Frozen result

The matrix is 4 profiles × 3 stacks × 3 targets × 2 modes = 72 logical
series. The committed CSV has 417 rows: 345 measured, 69 warmup, and three
structured gaps. A complete series is exactly one warmup followed by five
sequential measured samples. A gap is exactly one row with blank timing,
proof-size, payload-size, and memory metrics.

The three gaps are evidence, not estimates:

| Series | Status | Evidence |
| --- | --- | --- |
| Mac Chrome · Circom WebAuthn · cold | `runtime_failed` | 16-worker renderer exhausted memory while mapping the pinned zkey/WTNS |
| Mac Chrome · Circom WebAuthn · warm | `not_run` | blocked by the cold failure; no earlier four-worker timing substituted |
| Motorola E15 · Circom WebAuthn · cold | `runtime_failed` | 32-bit userspace could not map the pinned 1.73 GB zkey plus WTNS |

## Immutable identities

The lock files are part of the campaign identity:

- [`benchmark-contract.json`](benchmark-contract.json) defines the matrix,
  measurement boundary, correctness gates, and gap semantics.
- [`sources.lock.json`](sources.lock.json) pins ProveKit V1, Self, World ID
  Protocol, TACEO OPRF, `privacy-ethereum/webauth-circom`, Circom, Mopro,
  witness generators, and Rapidsnark by immutable revision.
- [`toolchains.lock.json`](toolchains.lock.json) pins Nargo/Noir, Barretenberg,
  SnarkJS, wasm-bindgen, Mobench, Android, SRS, and artifact hashes.

Important pins:

| Component | Identity |
| --- | --- |
| ProveKit V1 | core commit `9b2a6f37c67691eab4b0cec6c35e35c520e93285` |
| ProveKit browser package | `tooling/provekit-wasm`, Noir beta.11 inputs |
| ProveKit/SnarkJS browser workers | exactly 16 requested/effective workers |
| Noir native | Nargo `1.0.0-beta.19` |
| Barretenberg native/browser | `barretenberg-rs`/`bb.js` `4.2.0-aztecnr-rc.2` |
| Mopro | `0.3.7`, commit `10871f02e365c478cb4b61016e4034f7e74f076b` |
| Circom | `2.2.2` |
| SnarkJS | `0.7.6` |
| Native Rapidsnark | `rust-rapidsnark` `0.1.4` |
| Native witness adapter | `witnesscalc-adapter` `0.1.7` where qualified |
| Compatibility fallback | `iden3/circom-witnesscalc` `0.3.0`, not default |
| iPhone OPRF witness | `wasmi` `0.46.0` interpreting the exact Circom witness Wasm |
| E15 ABI bridge | Mobench `0.1.48` plus commit `e992596a786cc18047102a318d40131c953e57b8` |

The reference npm package `@worldcoin/provekit@0.1.0` is not the measured V1
runtime. It is retained only as a compatibility record.

## Circuits and semantic boundary

The CSV names four profiles separately. They are closest counterparts, not
apples-to-apples proof statements:

- Passport historical: Noir `complete_age_check`; Circom Self registration
  plus `vc_and_disclose`.
- Passport P1: the matching monolithic RSA-4096 sources under
  `noir/passport_p1/` and `circom/passport_p1/`.
- OPRF O2: the World-ID-aligned Noir nullifier statement and World ID Protocol
  Circom nullifier circuit. TACEO's core OPRF example is historical only.
- WebAuthn: Noir's ES256 assertion with challenge/type/origin/RP-ID/UP/UV/key
  bindings and the pinned Circom closest analogue with documented omissions.

Every row carries the circuit variant, source commit, backend, witness backend,
artifact hashes, and a non-equivalence note. No staged Passport result is
silently treated as a monolithic proof.

## Targets and prerequisites

Required tools are Git, `jq`, Bun, Rust/Cargo, Xcode, Android SDK/NDK/JDK,
ADB, and Google Chrome. The locked Android environment is Temurin 21,
platform `android-34`, NDK `26.1.10909125`.

Capture target identity before preparation:

```bash
# Mac publication surface
sw_vers
uname -m
system_profiler SPHardwareDataType
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --version

# Physical Motorola E15
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.product.cpu.abilist
adb shell getconf LONG_BIT
```

The iPhone lane is BrowserStack iPhone SE 2022 on iOS 15 and requires external
credentials plus explicit paid-session confirmation. The E15 lane records its
ABI, zygote, and userspace bitness in the raw evidence. Browser and native
rows are never merged into one runtime category.

## Entrypoint

Always inspect the dry plan first; it starts no devices and no paid session:

```bash
bash benchmarks/v1/scripts/run-reproducibility.sh \
  --stage all --campaign provekit-v1-cross-device --dry-run
```

Supported stages are `bootstrap`, `prepare`, `smoke`, `measure`, `export`, and
`all`:

```bash
bash benchmarks/v1/scripts/run-reproducibility.sh \
  --stage all --campaign provekit-v1-cross-device \
  --confirm-paid-browserstack
```

BrowserStack username/key are read from the caller's environment only. They
are never written to command logs, raw exports, or the committed CSV.

### Bootstrap

Bootstrap verifies the JSON locks and Circom artifact hashes, then installs
only the locked compiler, SDK, adapter, and package versions. It preserves Bun
and Cargo lockfiles and rejects toolchain drift.

### Prepare

Preparation compiles/fixes the four workload profiles, freezes circuit and
proving bundles, builds the native Mobench adapters, and builds the browser
fixtures. Prepared artifacts are content-hashed under `target/v1-benchmarks/`.
The committed CSV is a frozen publication artifact; a clean rerun must retain
its raw reports and write a new campaign manifest rather than overwrite it.

### Fixed-16 Mac WASM policy

The canonical runner always invokes the Mac browser lane with:

```text
INPUT_TO_PROOF_EXECUTION_POLICY=multithread
MOBENCH_WASM_THREADS=16
MOBENCH_SNARKJS_THREADS=16
```

The ProveKit report must show 16 WASM workers. The Circom report must show 16
requested and effective SnarkJS workers. Barretenberg requests 32 and records
its 16-worker effective limit. The fixed worker values are in the raw report,
the package manifest, and the CSV `package_versions`/`non_equivalence_note`
fields; no host `hardwareConcurrency` default is accepted for the canonical
Mac rows.

### Smoke and measurement gates

Before timing, every runnable lane must accept a valid proof and reject a
tampered proof. The headline boundary is:

```text
raw structured input → witness generation → proof generation → serialized proof bytes
```

For ProveKit, witness construction and proving are one integrated operation;
`witness_time_ms` remains blank rather than being inferred. Noir/Barretenberg
and Circom report their observed witness and proving phases separately, while
`input_to_proof_time_ms` is the outer end-to-end duration.

Cold mode starts a fresh process/runtime for every attempt with locked assets
already local. Warm mode reuses the initialized runtime but regenerates the
witness and proof for every attempt. The runner performs one warmup and five
sequential measured samples and refuses to export incomplete successful
series.

## Export and validation

Raw evidence is exported only after schema, duplicate, unit, coverage, proof,
tamper, and gap checks pass:

```bash
bun benchmarks/v1/input-to-proof-data/export.ts
bun test benchmarks/v1/input-to-proof-data/export.test.ts
git diff --check
```

The canonical CSV retains stable columns for target identity, circuit/backend
identity, timing phases, serialized proof bytes, deduplicated proving payload,
peak process RSS, constraints, source/package versions, artifact hashes,
session provenance, status, and structured failure details. Missing metrics are
blank. APK/IPA upload size is transport evidence and is never counted as
proving payload.

The Marimo notebook at
[`analysis/input_to_proof_analysis.py`](analysis/input_to_proof_analysis.py)
reads only the canonical CSV. It validates 72-series coverage, derives medians
and dispersion from the five measured samples, and renders missing cells
visibly instead of interpreting them as zero.

Historical proof-only, semantic-parity, TACEO, automatic-thread, and diagnostic
material is documented under [`legacy/`](legacy/README.md) and is deliberately
excluded from the publication path.
