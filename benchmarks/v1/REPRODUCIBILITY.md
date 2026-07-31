# Reproducing the ProveKit V1 cross-device campaign

This is the canonical guide for the 27-cell ProveKit V1 campaign. It covers
three workloads (Passport, WebAuthn, OPRF), three stacks (ProveKit V1,
Noir/Barretenberg, Circom/Groth16), and three targets (BrowserStack iPhone SE
2022 native, physical Motorola E15 native, and Chrome/WASM on an M4 Max
MacBook).

This campaign does **not** drop Mopro or Arkworks. Mopro is the native
integration layer. Rapidsnark is preferred on supported arm64 targets;
Arkworks plus `rust-witness` is the explicit target-specific fallback when the
E15 userspace cannot support Rapidsnark.

## 1. Immutable inputs

The following files are part of the campaign identity:

- `benchmark-contract.json`: workloads, targets, gates, fields, and failure
  semantics.
- `sources.lock.json`: immutable upstream Git revisions for Self, World ID
  Protocol, TACEO OPRF, `privacy-ethereum/webauth-circom`, Mopro, and native
  adapters.
- `toolchains.lock.json`: exact compiler, SDK, crate, npm, and WASM adapter
  versions.
- the repository commit recorded in the frozen campaign manifest;
- Bun/Cargo lockfiles and hashes of every prepared circuit/proving bundle.

Locked highlights:

| Component | Fixed identity |
| --- | --- |
| Mopro | `0.3.7`, commit `10871f02e365c478cb4b61016e4034f7e74f076b` |
| Mobench SDK in frozen device artifacts | `0.1.48` plus PR #45 commit `e992596a786cc18047102a318d40131c953e57b8` |
| Mobench orchestration CLI | `0.1.48` plus PR #45 commit `e992596a786cc18047102a318d40131c953e57b8` |
| Android JDK | Temurin `21.0.11+10.0.LTS` via Mise |
| Android SDK/NDK | platform `android-34`; NDK `26.1.10909125` |
| Native Noir | `nargo 1.0.0-beta.19` |
| Native Barretenberg | `barretenberg-rs 4.2.0-aztecnr-rc.2` |
| Browser ProveKit | pinned V1 `tooling/provekit-wasm` at `9b2a6f37`, single-thread WASM |
| Browser Circom | `snarkjs@0.7.6` |
| Rapidsnark witness adapter | `witnesscalc-adapter@0.1.7` |
| Rapidsnark prover | `rust-rapidsnark@0.1.4` |
| Witness compatibility fallback | `iden3/circom-witnesscalc@0.3.0` |

Mobench is pinned to the immutable commit behind
`codex/android-32bit-native-abi`, not to the published `0.1.48` crate alone.
That patch maps Rust `usize` values to JNA's native `size_t` width and prevents
the generated runner from corrupting the C ABI on the E15's 32-bit userspace.

The browser Noir candidate is `@noir-lang/noir_js@1.0.0-beta.19` with
`@aztec/bb.js@4.2.0-aztecnr-rc.2`, matching Mopro's native Barretenberg line.
It is not measurement-ready merely because it installs:
all three browser circuits must first pass proof verification and tamper
rejection. If a different `bb.js` is required, update its exact version and
integrity in `toolchains.lock.json`, regenerate the Bun lockfile, and create a
new campaign manifest before collecting samples.

`@worldcoin/provekit@0.1.0` is retained as a compatibility/reference package,
but it is not used for the V1 publication measurements. The measured browser
lane builds `tooling/provekit-wasm` from the immutable V1 core commit with
single-thread WASM and the frozen beta.11 inputs. This distinction prevents a
current npm SDK artifact from being reported as a V1-branch result.

## 2. Circuit identity and non-equivalence

These workloads are the closest counterparts available. They are neither
one-to-one nor apples-to-apples.

### Passport

- Noir: `complete_age_check`, a monolithic passport age-check proof.
- Circom: Self signature-specific registration followed by
  `vc_and_disclose`, a two-proof product flow.

Report registration and disclosure identities and phase timings. Never add
the two Circom proofs and label the total an equivalent circuit.

### WebAuthn

- Noir: an ES256 assertion which binds signature/public key, challenge,
  `clientDataJSON.type`, expected origin, RP-ID hash, required UP/UV flags, and
  the configured assertion inputs.
- Circom: pinned `privacy-ethereum/webauth-circom`, the closest practical
  ES256 counterpart. It does not bind the complete same statement.

The older “no Circom WebAuthn circuit” claim is stale. The correct posture is
to run the pinned counterpart, inventory its public/private signals in the
frozen manifest, and label the semantic omissions. Do not claim equivalence.

### OPRF

- Noir: TACEO `oprf-nr` core example.
- Circom: World ID Protocol query and nullifier application circuits.

Query and nullifier remain distinct circuit names and result rows. They are
not collapsed into a synthetic circuit or represented as identical to TACEO's
example.

## 3. Target identity

Capture identity before preparation or measurement:

```bash
# Mac
sw_vers
uname -m
system_profiler SPHardwareDataType
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --version

# Physical Motorola E15
adb shell getprop ro.product.manufacturer
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.cpu.abilist
adb shell getconf LONG_BIT
```

Prepare and run the ProveKit diagnostic lane with the locked 32-bit Mobench
bridge:

```bash
benchmarks/v1/scripts/build-e15-provekit-diagnostic.sh
benchmarks/v1/scripts/run-e15-provekit.ts \
  --campaign provekit-v1-cross-device \
  --output target/v1-benchmarks/reproduction/provekit-v1-cross-device/e15 \
  --warmup 1 --samples 5 --sequential
```

The runner requires exactly one authorized ADB device, installs the signed APK,
runs Passport, WebAuthn, and OPRF sequentially, retains per-workload logcat,
and reconstructs Mobench's chunked JSON. The normalizer emits one blank-timing
attested warmup plus five measured rows for each success, or one structured gap
row carrying the actual native panic or timeout.

For BrowserStack, resolve the current `iPhone SE 2022` catalog entry before
dispatch and retain the resolved OS/device identifier, session ID, build ID,
app URL/ID, and result URL. Credentials, authorization headers, and signed URLs
must not enter logs or exports.

The three runtime categories are:

- `native-ios`;
- `native-android`;
- `browser-wasm-chrome`.

Mac-native output is smoke/diagnostic evidence and is not a fourth publication
target. Browser results cannot be inserted into native rows.

## 4. Bootstrap

Requirements are Git, `jq`, Bun, Rust/Cargo, Xcode, the Android SDK/NDK/JDK,
ADB, Google Chrome, and enough disk space for Groth16 keys and frozen bundles.

Android builds source `scripts/android-env.sh`. OpenJDK 26 is rejected because
the campaign's Kotlin/Android Gradle toolchain cannot parse that version and
release lint fails. `bootstrap-android-java.sh` installs the locked Temurin 21
runtime through Mise; SDK platform 34 and NDK 26.1.10909125 are verified before
an Android build starts.

Inspect the complete non-secret command plan first:

```bash
benchmarks/v1/scripts/run-reproducibility.sh --stage all \
  --campaign provekit-v1-cross-device --dry-run
```

Then bootstrap:

```bash
benchmarks/v1/scripts/run-reproducibility.sh --stage bootstrap \
  --campaign provekit-v1-cross-device
```

Bootstrap must:

1. parse all JSON locks;
2. reject a source checkout whose `HEAD` differs from `sources.lock.json`;
3. install exact versions only and verify package/archive integrity;
4. preserve Bun and Cargo lockfiles;
5. record tool version output in the campaign log.

Sources and tools belong under `target/v1-benchmarks/`. A second bootstrap is
idempotent and must reject drift rather than reset a user's checkout.

## 5. Prepare and freeze bundles

```bash
benchmarks/v1/scripts/run-reproducibility.sh --stage prepare \
  --campaign provekit-v1-cross-device
```

Preparation compiles every selected circuit, creates its witness/proving
artifacts, and writes a frozen manifest containing:

- repository and circuit source commits;
- tool/package versions and lockfile hashes;
- circuit, bytecode/R1CS, witness generator, proving key, verification key,
  runtime, and bundle SHA-256 values;
- circuit size and constraint count;
- workload/circuit semantic identity and public-output schema;
- target/backend compatibility decisions.

ProveKit preparation may be nondeterministic. Prepare one PKP/PKV pair per
workload, hash it, freeze it in the campaign manifest, and reuse that exact
pair on all three targets. Independently prepared pairs define different
campaigns even when both verify.

For Groth16, the final `.zkey` and verification key are campaign artifacts.
The PTAU is preparation-only and is not shipped or counted in the runtime
bundle. A reference WTNS used by a proof-only harness is also not circuit
download size.

Run preparation twice as a determinism audit. Deterministic artifacts must
match. An intentionally nondeterministic ProveKit pair is accepted only by
reusing the first frozen manifest; the second pair is diagnostic and must not
replace or mix with it.

## 6. Backend gates

### ProveKit V1

Native iOS and Android use the ProveKit C ABI through Mobench. Chrome uses the
pinned single-thread V1 `tooling/provekit-wasm` build. ProveKit must deliver all nine
workload/target cells; an incomplete ProveKit matrix is not publication-ready.

The publication iPhone ProveKit prebuilt contains one isolated proof-only
function per workload. Each setup performs the valid-proof/tamper gate outside
timing, and each proof records an internal prover duration plus exact serialized
`.np` bytes. The Mobench wrapper duration is retained separately and must never
be substituted for the internal prover duration.

ProveKit beta.11 circuit artifacts and their matching inputs are frozen as one
unit under `target/v1-benchmarks/provekit-beta11-artifacts`. In particular,
`complete_age_check.json` must be paired with
`complete_age_check.Prover.toml` from the same detached beta.11 source
revision. The six-overflow-bit beta.19 Passport input is incompatible with
that beta.11 artifact and must never overwrite or feed the ProveKit lane.

### Noir + Barretenberg

Native uses Mopro 0.3.7, Noir beta.19, and
`barretenberg-rs 4.2.0-aztecnr-rc.2`. Port existing circuits to beta.19 only
when changes are mechanical and public/semantic outputs remain identical.

The native WebAuthn and TACEO OPRF adapters consume frozen beta.19
`WitnessStack` files produced by pinned Nargo. They pass the solved witness
directly to Barretenberg; witness generation is outside the timed boundary and
`witness_time_ms` therefore remains blank. Their combined benchmark is named
`proof_verify`, not `e2e`. Both host canaries verify a valid proof and reject a
one-bit mutation before measurement.

The shared local CRS is the first 134,217,792 bytes (2,097,153 points) of
`https://crs.aztec.network/g1.dat`, SHA-256
`ea6069e3563ad79f186d1c0088499309cbdaeb54254346760ffec7fe15ae49cd`.
`prepare-noir-beta19-srs.sh` refuses an existing file with a different size or
hash. The publication arm64 iOS prebuilt records one one-warmup/five-sample
proof-only function per workload; correctness and tamper rejection run in its
setup.

The publication Passport fixture uses Barrett parameters generated for the
pinned beta.19 `noir-bignum` revision. Earlier four-overflow-bit inputs are
kept only as beta.11 ProveKit recovery evidence; they must never be reused for
the beta.19 Barretenberg lane.

Chrome and the E15 use the frozen version pair after proof-and-tamper smoke
validation. The campaign includes an armv7 Barretenberg build and records the
exact backend/ABI in every E15 row; Mac or browser results are never substituted
for Android measurements.

The default ProveKit Passport lane may exceed the E15's usable memory and be
killed by Android's low-memory killer. After retaining that failed attempt,
the runner may use
`bench_passport_complete_age_check_e2e_single_thread` as a constrained native
fallback. Its Rayon pool is created during warmup and reused for the five
measured samples. Export it under the distinct
`passport_complete_age_check_single_thread` variant with
`rayon_threads: 1`; never present it as the same execution policy as the
unconstrained iPhone or browser lane.

The committed E15 V1 evidence records the actual `armeabi-v7a`/`zygote32`
identity and uses the constrained single-thread Passport fallback where
required. It completed the valid-proof/tamper gates and one warmup plus five
sequential samples for all three workloads. The resulting medians are
71,595.260 ms (Passport), 27,839.158 ms (WebAuthn), and 12,564.926 ms (OPRF);
the sample-level payload, proof, and RSS values are in the canonical CSV.
Earlier low-memory kills and Android quarantine attempts remain recovery
evidence, not measurements.

### Circom + Groth16

Chrome uses `snarkjs@0.7.6`, including its WASM witness calculation/proving
path.

For native arm64, pilot `witnesscalc-adapter@0.1.7` and
`rust-rapidsnark@0.1.4`. Use Rapidsnark on iPhone only after Passport,
WebAuthn, and both named World ID OPRF circuits pass:

1. build and package;
2. valid proof verification;
3. tampered proof rejection;
4. one warmup;
5. five sequential measured samples.

The native Rapidsnark lane uses frozen SnarkJS-validated WTNS files. Their
SHA-256 values are locked in `toolchains.lock.json`; preparation regenerates a
Groth16 proof and verifies it before packaging:

- World ID OPRF query:
  `89844b3d8e0b0a9a58075659b694f2e0f5582a198430da6d8101a48707f7446f`
- World ID OPRF nullifier:
  `b5c2bf1c167f8fe77cf13bf96db143c21aa19f27f6b7cc9317b255c43d32f568`
- Self `vc_and_disclose`:
  `53a4ce55036d040275e3cb5548ad771f67789e018098eab92656beb0e218807f`
- Self RSA-4096 registration:
  `9a785c0e2a974ca751777bb6824ebd8e6d4be1b43224cc1a0cbe6cc02d663c6a`
- WebAuthn:
  `294c8091d87c2dbec8bc8997d0e892b65e81d5f95a14320081dcaefea1a5e0d8`

Each native app runs a process-local correctness gate before timing: a valid
proof must verify and a mutated proof must be rejected. The two OPRF variants
are separate apps and separate circuit variants. `proof_verify` means proof
generation plus verification with a frozen witness; it is not full
witness-to-proof end-to-end time.

`prepare-rapidsnark-oprf-ios-prebuilt.sh` creates two isolated proof entries.
`prepare-rapidsnark-passport-webauthn-ios-prebuilt.sh` creates three more.
Both use a device-only arm64 XCFramework path; simulator builds are opt-in via
`V1_RAPIDSNARK_BUILD_IOS_SIMULATOR=1`.

The iOS Rapidsnark build applies the tracked
`rapidsnark-ios-single-thread.patch` and
`rapidsnark-ios-low-memory.patch`. The first fixes the ffiasm default worker
pool to one thread only for iPhone device builds. The second mmaps the WTNS,
runs QAP/FFT before the point MSMs, releases the FFT roots before the MSM
passes, and page-aligns and unmaps each read-only zkey section after its last
use. Mac and simulator behavior is not changed unless the iOS-equivalent
calibration macros are explicitly enabled. Both patches are included in the
frozen bundle's content identity, and the resulting backend configuration
must remain visible in the row package versions.

The WebAuthn zkey is 1.73 GB, so embedding it makes an IPA that BrowserStack
rejects before a device session. Set `MOBENCH_WEBAUTHN_ZKEY_URL` to a
campaign-controlled HTTPS URL while preparing the Passport/WebAuthn bundle.
The resulting WebAuthn IPA contains only the expected byte length and SHA-256;
the iOS runner downloads to its cache, verifies both values, and only then
sets the native fixture path. The exact downloaded zkey remains part of
`proving_payload_size_bytes`; the smaller IPA is transport only and is never
reported as the proving payload. Retain the URL service and tunnel logs with
the session evidence, and rebuild the immutable prebuilt if the URL changes.

The remote downloader streams to a file. Its SHA-256 pass additionally uses
Darwin `F_NOCACHE` and drains an autorelease pool around every 8 MiB read.
Without those two controls, integrity verification left the 1.73 GB file hot
or retained immediately before the mmap prover and iOS killed the process at
its 2,098 MB `ActiveHard` limit.

The final 2026-07-30 iPhone SE 2022 attempt passed in BrowserStack build
`9fe5b442db9319cae7010b9e89c95610685e4a6e`, session
`5e8373982ce020b462092542ecce8e5a49caf4aa`. The device downloaded and
hash-verified exactly 1,733,145,772 zkey bytes, accepted a valid proof,
rejected the tampered canary, completed one warmup and five measured proofs,
and emitted the structured report. The measured prover median is
38,679.039 ms; the exact proving payload is 1,842,364,184 bytes; proof sizes
range from 1,000 to 1,006 bytes; and per-sample process peaks range from
844.406 to 848.219 MiB. The retained passing session, device,
instrumentation, report, and App Profiling evidence are the publication
source. Earlier HTTP and jetsam attempts remain retained as recovery evidence,
not measurements.

IPA executables may receive nondeterministic Xcode build UUIDs when rebuilt.
Each preparation script therefore freezes its first validated bundle behind a
content manifest. A second invocation hashes every relevant adapter, packaging
script, zkey, WTNS, and verification key; when those inputs are unchanged it
revalidates and reuses the byte-identical prebuilt manifest. Any content drift
forces a fresh bundle instead of silently mixing artifacts.

The final iPhone bundle can be assembled without changing its source
artifacts:

```bash
benchmarks/v1/scripts/merge-ios-prebuilt-manifests.sh \
  target/v1-benchmarks/full-campaign-ios-prebuilt \
  target/v1-benchmarks/provekit-ios-prebuilt/manifest.json \
  target/v1-benchmarks/mopro-noir-ios-prebuilt/manifest.json \
  target/v1-benchmarks/rapidsnark-core-ios-prebuilt/manifest.json \
  target/v1-benchmarks/rapidsnark-oprf-ios-prebuilt/manifest.json
```

The merged manifest uses a deterministic 40-hex content identity and writes
the contributing manifest hashes to the adjacent `.provenance.json` file.
The proof-metrics bundle contains 11 named proof functions: three ProveKit,
three Noir/Barretenberg, and five Circom/Groth16 variants. Mobench dry-run
validation must pass before paid execution.

On the E15, make the decision from captured ABI/userspace evidence. Try
Rapidsnark only if that target is supported. Otherwise use Mopro Arkworks plus
`rust-witness`. The CSV fields `prover_backend` and `witness_backend` preserve
that difference; results are not normalized into a generic “Circom” backend.

The completed E15 campaign records `armeabi-v7a`/`zygote32` identity and the
qualified native backend for every row. Circom OPRF combines the two World ID
variants; Passport combines disclosure and RSA-4096 registration. Each
component independently passed the proof/tamper and 1+5 gates before it entered
the CSV. `iden3/circom-witnesscalc@0.3.0` remains a compatibility fallback, not
a publication backend.

### Analysis environment

The Marimo notebook reads only `semantic-parity-data/semantic-parity-samples.csv`.
Its Python 3.12
environment is locked by `analysis/pyproject.toml` and `analysis/uv.lock`:
Marimo 0.23.15, Pandas 2.3.3, Matplotlib 3.10.8, and Seaborn 0.13.2.

```bash
cd benchmarks/v1/analysis
uv sync --frozen
uv run marimo check benchmark_analysis.py
uv run marimo export html benchmark_analysis.py \
  --no-include-code --force \
  -o ../../../target/v1-benchmarks/analysis/benchmark-analysis.html
```

## 7. Smoke before timing

```bash
benchmarks/v1/scripts/run-reproducibility.sh --stage smoke \
  --campaign provekit-v1-cross-device
```

Every measured lane must first:

1. build/load the exact frozen artifacts;
2. generate or load the expected witness;
3. prove and accept a valid proof;
4. mutate proof bytes or a public input and reject it;
5. retain public outputs, circuit identity, adapter/backend identity, and the
   smoke evidence path.

A proof that cannot be verified, or a verifier that accepts the tampered
case, is never timed.

## 8. Measure

Run physical/local measurement:

```bash
benchmarks/v1/scripts/run-reproducibility.sh --stage measure \
  --campaign provekit-v1-cross-device
```

BrowserStack is paid and must additionally require credentials from the
environment and the runner's explicit paid-confirmation flag. Never put the
credential values on a command line or in a retained command log.

For each expected cell, execute exactly one warmup then five sequential
measured samples. Write one row per attempt, including the warmup. Record:

- campaign, target, device, OS, ABI, runtime, and browser;
- stack, frontend, prover backend, witness backend, circuit, and circuit
  commit;
- sample index, warmup flag, status, failure class, and failure message;
- initialization, witness, prove, verify, and end-to-end nanoseconds;
- exact serialized proof bytes, primary circuit bytes, and deduplicated proving
  payload bytes;
- peak process memory and constraint count;
- source commit, package versions, artifact hashes, and session/result
  provenance.

Successful measured rows require positive durations. Missing metrics remain
blank. Failed or unsupported cells use one of `unsupported`, `build_failed`,
`crashed`, `timed_out`, or `zero_samples`; zero is never a sentinel for
missing data.

Mobench executes native warmups but deliberately excludes them from
`BenchReport.samples`. The iOS normalizer therefore emits an attested
`status=ok`, `sample_kind=warmup`, `sample_index=0` row with blank timing
fields, followed by the five retained measured samples. It never copies a
measured duration into the warmup row or invents a warmup time.

For every published cell, `peak_memory_mib` is mandatory. Native rows use the
benchmark worker/application process peak. Mac browser rows poll the unique
Chrome renderer PID at 100 ms and report renderer RSS; JavaScript heap is not a
substitute.

`artifact_size_bytes` and `bundle_size_bytes` both carry the deduplicated
per-cell proving payload for schema compatibility: PKP plus input for ProveKit,
ACIR/circuit plus frozen witness plus SRS for browser Barretenberg, and WASM
plus zkey plus input for browser Circom. Native adapters report their exact
equivalent inputs. IPA, APK, XCUITest, verifier-only assets, and duplicate
uploads are never counted. `artifact_hashes` contains hashes of those proving
inputs, not hashes of transport containers.

## 9. Export and validate

```bash
benchmarks/v1/scripts/run-reproducibility.sh --stage export \
  --campaign provekit-v1-cross-device
```

Export regenerates the canonical sample-level CSV from the committed,
hash-locked V1 evidence and retains secret-free provenance. It must fail on:

- a missing required column;
- a duplicate campaign/target/stack/workload/circuit/sample key;
- an unknown status;
- a missing value encoded as zero;
- a successful sample without correctness evidence;
- a runtime/surface mismatch;
- a ProveKit cell without one warmup and five measured samples;
- an expected Noir/Circom cell which has neither samples nor an explicit
  failure row.

The publication export path is
`semantic-parity-data/export-v1.ts`. It verifies every committed V1 evidence
hash, replaces the nine stale ProveKit rows, and runs the full 27-cell legacy
CSV validator. Raw `measure` outputs remain in the campaign directory and are
never substituted into the publication file without an explicit evidence and
manifest update.

When BrowserStack rejects an immutable iOS artifact before a session can
start, set `V1_IOS_GAPS_JSON` to an array of structured, evidence-backed gap
records. The normalizer accepts a gap only for a lane whose required result or
manifest entry is absent; it still rejects unexplained missing lanes. The final
freeze has no gap rows. Its only non-telemetry values are the five clearly
labelled iPhone Circom proving-payload estimates described below.

The Marimo notebook reads only this master CSV. It independently validates
coverage and units, derives median and dispersion from measured (non-warmup)
rows, and renders missing cells distinctly. Titles, captions, and legends must
state that circuit counterparts are non-equivalent.

At the final V1 evidence freeze, all **27 logical cells** have the four
requested publication fields: prove-only time, deduplicated proving payload
size, serialized proof size, and peak process memory. The canonical file has
**162 records**: **135 measured rows** and **27 attested warmups**. The
historical WebAuthn iPhone Circom closest-analogue row retains its explicit
asset-size estimate note (hash-pinned zkey plus frozen WTNS); it excludes IPA,
XCUITest, and upload transport sizes. Every ProveKit V1 payload and every
matched P1/O2 native payload is exact committed evidence, not an estimate.

## 10. Evidence and publication rules

Raw command streams, device logs, proof/tamper evidence, and immutable bundle
manifests stay beneath the campaign result directory. The exported evidence
contains no secrets.

Historical benchmark data may guide debugging, but may enter the master CSV
only if all of the following match this campaign:

- repository and circuit source commits;
- compiler/package/adapter versions;
- circuit semantics and public-output schema;
- exact bundle hashes;
- target, OS, ABI, runtime, and browser;
- one-warmup/five-sample protocol;
- valid-proof acceptance and tampered-proof rejection.

Unsupported and failed cells are findings, not values. Never estimate a timing,
copy another target's value, or silently omit a failure. The only estimates in
the older compound-variant export are the five iPhone Circom payloads called
out in that file's estimate notes; the semantic-parity publication has only
the historical WebAuthn estimate described above.
