# Reproducing the V1 input-to-proof campaign

This is the canonical runbook for
[`input-to-proof-data/input-to-proof-samples.csv`](input-to-proof-data/input-to-proof-samples.csv).
It defines the source identities, toolchains, devices, execution boundaries,
sampling rules, correctness gates, artifact-size definitions, and failure
semantics for the published numbers.

Do not use files under [`legacy/`](legacy/) as inputs to this campaign. They are
retained for historical comparison and audit only.

## 1. Frozen publication result

The publication matrix is:

```text
4 profiles × 3 stacks × 3 targets × 2 timing modes = 72 logical series
```

The committed CSV contains 417 rows:

| Row type | Count |
| --- | ---: |
| Measured samples | 345 |
| Warmup samples | 69 |
| Explicit gap rows | 3 |

Successful series contain exactly one warmup followed by five sequential
measured samples. A gap is one row with blank timing, proof-size, proving
payload, and memory metrics plus an explicit status and failure explanation.

### Current gaps

These are evidence-backed gaps, not estimates or substituted timings:

| Series | Status | Evidence |
| --- | --- | --- |
| Mac Chrome · Circom WebAuthn · cold | `runtime_failed` | The fixed-16 renderer exhausted memory while mapping the pinned zkey/WTNS |
| Mac Chrome · Circom WebAuthn · warm | `not_run` | Blocked by the cold failure; no earlier four-worker timing was substituted |
| Motorola E15 · Circom WebAuthn · cold | `runtime_failed` | The 32-bit userspace could not map the pinned 1.73 GB zkey plus WTNS |

## 2. Campaign identity

The following files define the immutable publication contract:

| File | Role |
| --- | --- |
| [`benchmark-contract.json`](benchmark-contract.json) | Matrix, measurement boundary, correctness gates, required fields, and gap semantics |
| [`sources.lock.json`](sources.lock.json) | Immutable source revisions for ProveKit, circuits, Mopro, witness generators, and Rapidsnark |
| [`toolchains.lock.json`](toolchains.lock.json) | Locked compiler, SDK, browser, mobile, SRS, and artifact identities |
| [`input-to-proof-data/manifest.json`](input-to-proof-data/manifest.json) | Canonical CSV provenance and artifact manifest |

The branch's publication surface is Chrome/WASM on the M4 Max MacBook. Native
Mac runs are diagnostic. Browser and native results must never be merged into a
single runtime category.

## 3. Workloads and semantic boundary

The stacks use the closest available counterparts; they do not prove identical
statements. Keep the circuit identity and the row's `non_equivalence_note`
attached to every comparison.

| Profile | Noir circuit | Circom counterpart | Important difference |
| --- | --- | --- | --- |
| Passport historical | `complete_age_check` | Self registration plus `vc_and_disclose` | Circom is a staged product flow, while Noir is monolithic |
| Passport P1 | Matched monolithic RSA-4096 circuit | `circom/passport_p1/passport_p1.circom` | Closest matched integrity, registry, DG1, and age assertion |
| OPRF O2 | World-ID-aligned Noir nullifier statement | World ID Protocol nullifier circuit | Same named profile/public nullifier, different implementation details |
| WebAuthn | ES256 assertion binding challenge, type, origin, RP-ID, flags, and key | Pinned `privacy-ethereum/webauth-circom` analogue | Circom omits several Noir bindings |

TACEO's primitive OPRF example and other production-backend experiments are
retained under `legacy/`; they are not silently merged into the publication
matrix.

## 4. Targets and prerequisites

| Target | Surface | Required identity |
| --- | --- | --- |
| iPhone SE 2022 | Native BrowserStack | iOS 15, arm64, paid-session confirmation |
| Motorola E15 | Native physical device | ADB-captured OS, ABI, zygote, and userspace bitness |
| M4 Max MacBook | Chrome/WASM publication surface | macOS/arm64 and Chrome version captured at run time |

Required local tools are Git, `jq`, Bun, Rust/Cargo, Xcode, Android
SDK/NDK/JDK, ADB, and Google Chrome. The locked Android environment is
Temurin 21, platform `android-34`, NDK `26.1.10909125`.

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
adb shell getprop ro.zygote
```

The runner records these values in raw evidence. BrowserStack device/session
provenance is retained with every successful iPhone lane.

## 5. Locked toolchains and backends

| Component | Pinned identity |
| --- | --- |
| ProveKit V1 core | `9b2a6f37c67691eab4b0cec6c35e35c520e93285` |
| ProveKit browser inputs | `tooling/provekit-wasm`, Noir beta.11 inputs |
| Noir native | Nargo `1.0.0-beta.19` |
| Barretenberg native/browser | `barretenberg-rs` / `bb.js` `4.2.0-aztecnr-rc.2` |
| Browser Noir adapter | `noir_js` beta.11 for ProveKit and beta.19 for Barretenberg |
| Mopro | `0.3.7`, commit `10871f02e365c478cb4b61016e4034f7e74f076b` |
| Circom | `2.2.2` |
| SnarkJS | `0.7.6` |
| Native Rapidsnark | `rust-rapidsnark` `0.1.4` |
| Native witness adapter | `witnesscalc-adapter` `0.1.7` where qualified |
| Native Rust witness | `rust-witness` `0.1.6` where the target-specific fallback is required |
| Compatibility fallback | `iden3/circom-witnesscalc` `0.3.0`, fallback only |
| iPhone OPRF witness | `wasmi` `0.46.0` interpreting the exact Circom witness Wasm |
| Mobench / E15 ABI bridge | `0.1.48`, commit `e992596a786cc18047102a318d40131c953e57b8` |

The reference npm package `@worldcoin/provekit@0.1.0` is retained as a
compatibility record only. It is not the measured V1 browser runtime.

For native Circom, arm64 pilots prefer `witnesscalc-adapter@0.1.7` with
`rust-rapidsnark@0.1.4`. The iPhone lane uses Rapidsnark only after the exact
circuit passes build, proof-verification, tamper-rejection, warmup, and sample
gates. The E15 lane first records its ABI and userspace bitness; if Rapidsnark
is unsupported there, the row uses the Mopro Arkworks plus Rust-witness
fallback and keeps that backend difference explicit.

## 6. Entrypoint and stages

Always inspect the non-secret dry plan first. It starts no devices and no paid
session:

```bash
bash benchmarks/v1/scripts/run-reproducibility.sh \
  --stage all \
  --campaign provekit-v1-cross-device \
  --dry-run
```

The supported stages are:

| Stage | Purpose |
| --- | --- |
| `bootstrap` | Verify locks and install only pinned compilers, SDKs, adapters, and packages |
| `prepare` | Build/fix circuits, freeze proving bundles, and build native/browser fixtures |
| `smoke` | Run valid-proof and tamper-rejection canaries |
| `measure` | Run one warmup and five sequential measured samples per successful series |
| `export` | Validate raw reports and write the canonical CSV |
| `all` | Run the stages in order |

Run the full campaign only with explicit paid-session confirmation:

```bash
bash benchmarks/v1/scripts/run-reproducibility.sh \
  --stage all \
  --campaign provekit-v1-cross-device \
  --confirm-paid-browserstack
```

Preparation writes content-hashed artifacts and raw reports under the local
`target/v1-benchmarks/` tree. A clean rerun must preserve its raw reports and
write a new campaign manifest rather than overwrite the committed publication
artifact.

## 7. Fixed-16 browser policy

The canonical Mac browser lane uses these values:

```text
INPUT_TO_PROOF_EXECUTION_POLICY=multithread
MOBENCH_WASM_THREADS=16
MOBENCH_SNARKJS_THREADS=16
```

The ProveKit report must show 16 WASM workers. The Circom report must show 16
requested and effective SnarkJS workers. Barretenberg requests 32 workers and
records its 16-worker effective limit. These values are retained in raw
reports, package manifests, and CSV provenance; host `hardwareConcurrency`
defaults are not accepted for canonical Mac rows.

## 8. Timing and correctness contract

The headline measurement is:

```text
raw structured input → witness generation → proof generation → serialized proof bytes
```

- ProveKit integrates witness construction with proving, so
  `witness_time_ms` remains blank rather than being inferred.
- Noir/Barretenberg and Circom report observed witness and proving phases when
  available; `input_to_proof_time_ms` is the outer end-to-end duration.
- Cold mode starts a fresh process/runtime per attempt with locked assets local.
- Warm mode reuses initialized runtime state but regenerates witness and proof.
- Every timed lane must accept a valid proof and reject a tampered proof before
  its samples are exported.

### Size and memory definitions

- `proof_size_bytes` is the exact serialized proof length.
- `circuit_size_bytes` is the deduplicated proving payload required to create a
  proof: proving key/PKP plus the frozen proving input, such as a WTNS or ACIR
  witness. Verifier-only material is excluded.
- `artifact_size_bytes` and `bundle_size_bytes` retain the backend's artifact
  and transport accounting separately.
- `peak_memory_mib` is peak process RSS when measurable.
- APK/IPA/XCUITest upload size is transport evidence, never proving payload.

Missing measurements remain blank and are accompanied by an explicit status,
failure code, and failure detail. They are never encoded as zero.

## 9. Export and validation

The canonical data directory contains the publication exporter and schema at
its root. Native E15 normalizers and gap helpers live under
[`input-to-proof-data/native/`](input-to-proof-data/native/) with their own
normalization schema; this is intentionally distinct from the publication
schema.

```bash
bun benchmarks/v1/input-to-proof-data/export.ts
bun test benchmarks/v1/input-to-proof-data/export.test.ts
bun test benchmarks/v1/input-to-proof-data/native/*.test.ts
bash benchmarks/v1/scripts/run-reproducibility.test.sh
git diff --check
```

Export must pass schema, duplicate, unit, coverage, proof, tamper, and gap
checks. The canonical CSV has stable columns for target identity,
circuit/backend identity, timing phases, proof/payload/artifact sizes, peak
RSS, constraints, source/package versions, hashes, session provenance, status,
and structured failure details.

## 10. Credentials, evidence, and legacy boundaries

- BrowserStack username and key are read from the caller's environment only.
- Paid BrowserStack sessions require the explicit confirmation flag.
- Secrets never enter command logs, raw exports, or the committed CSV.
- Raw device, browser, build, and session evidence stays under local `target/`.
- [`legacy/`](legacy/) contains superseded proof-only, semantic-parity, TACEO,
  automatic-thread, diagnostic, and historical notebook material. It is useful
  for audit, but is not an input to this campaign.
- The `analysis/` directory is intentionally empty in this freeze. The future
  publication notebook must read only the canonical CSV and render missing
  series as gaps rather than zeros.
