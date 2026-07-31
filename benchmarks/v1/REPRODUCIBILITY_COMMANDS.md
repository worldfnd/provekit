# Historical engineering command transcript

This file retains the exploratory commands used while developing the campaign.
It is **not** the publication procedure and some commands describe superseded
adapters or supporting evidence. For a blog-linked reproduction path, use
[`REPRODUCIBILITY.md`](REPRODUCIBILITY.md) and
[`scripts/run-reproducibility.sh`](scripts/run-reproducibility.sh). The
authoritative results are [`data/benchmark-samples.csv`](data/benchmark-samples.csv).

The orchestration script records the actual expanded commands in
`target/v1-benchmarks/reproduction/<campaign>/commands.log`.

## 0. Identify the campaign

```bash
git status --short --branch
git rev-parse HEAD
export V1_CAMPAIGN=announcement-v1
```

Use an isolated campaign worktree. The release worktree is
`codex/provekit-v1-cross-device-campaign`; do not use the dirty primary
checkout.

## 1. Preview the complete run

```bash
benchmarks/v1/scripts/run-reproducibility.sh \
  --stage all \
  --campaign "$V1_CAMPAIGN" \
  --dry-run
```

## 2. Bootstrap and prepare

```bash
benchmarks/v1/scripts/run-reproducibility.sh \
  --stage bootstrap \
  --campaign "$V1_CAMPAIGN"

benchmarks/v1/scripts/run-reproducibility.sh \
  --stage prepare \
  --campaign "$V1_CAMPAIGN"

benchmarks/v1/scripts/run-reproducibility.sh \
  --stage smoke \
  --campaign "$V1_CAMPAIGN"
```

## 3. Prepare ProveKit native packages

```bash
FUNCTIONS='["bench_mobile::bench_passport_complete_age_check_prepare","bench_mobile::bench_passport_complete_age_check_prove","bench_mobile::bench_passport_complete_age_check_verify","bench_mobile::bench_passport_complete_age_check_e2e","bench_mobile::bench_passport_fragmented_age_check_prepare","bench_mobile::bench_passport_fragmented_age_check_prove","bench_mobile::bench_webauthn_assertion_prepare","bench_mobile::bench_webauthn_assertion_prove","bench_mobile::bench_webauthn_assertion_verify","bench_mobile::bench_webauthn_assertion_e2e","bench_mobile::bench_oprf_prepare","bench_mobile::bench_oprf_prove","bench_mobile::bench_oprf_verify","bench_mobile::bench_oprf_e2e"]'
SOURCE_SHA="$(git rev-parse HEAD)"

MOBENCH_CI_PREPARE=1 ./bench-mobile/scripts/generate-fixtures.sh

cargo-mobench ci prepare \
  --target ios \
  --crate-path bench-mobile \
  --ffi-backend native-c-abi \
  --functions "$FUNCTIONS" \
  --iterations 5 \
  --warmup 1 \
  --release \
  --source-sha "$SOURCE_SHA" \
  --output-dir target/mobench/prebuilt/ios \
  --manifest target/mobench/prebuilt/ios/manifest.json

cargo-mobench ci prepare \
  --target android \
  --crate-path bench-mobile \
  --ffi-backend native-c-abi \
  --functions "$FUNCTIONS" \
  --iterations 5 \
  --warmup 1 \
  --release \
  --source-sha "$SOURCE_SHA" \
  --output-dir target/mobench/prebuilt/android \
  --manifest target/mobench/prebuilt/android/manifest.json
```

## 3a. Run the full local Mac matrix

Run this with no other prover benchmark active:

To refresh the checked Mac evidence:

```bash
bun run benchmarks/v1/scripts/run-mac-native-benchmarks.ts
bun run benchmarks/v1/scripts/run-mac-wasm-benchmarks.ts
```

The first command runs ProveKit and native Barretenberg for passport,
WebAuthn, and Taceo OPRF; Arkworks for World ID OPRF query/nullifier; and
Rapidsnark for Self passport registration/disclosure. The second command runs
ProveKit and Barretenberg for all three Noir workloads in local Chrome only.
Both commands are sequential and use one warmup plus five measured samples.

## 4. Prepare Mopro native Circom/Arkworks and Noir/Barretenberg adapters

These are preparation/development commands. They do not replace the frozen
publication bundles or their retained measurements:

```bash
benchmarks/v1/scripts/prepare-webauthn-circom.sh --witness
benchmarks/v1/scripts/prepare-mopro-native-adapters.sh --build-ios
# Requires Zig on PATH for Mopro's Barretenberg Android linker:
benchmarks/v1/scripts/prepare-mopro-native-adapters.sh --build-android

# Optional benchmark-only setup; this circuit needs at least the 4.83 GB
# power-22 PTAU. Reuse its verified cache. The script gives SnarkJS a 32 GB
# heap by default, writes setup output through a partial file, and verifies the
# resulting 1.73 GB zkey before it can become the cache entry.
V1_WEBAUTHN_PTAU=/absolute/path/to/powersOfTau28_hez_final_22.ptau \
  benchmarks/v1/scripts/prepare-webauthn-circom.sh --setup

# Build the four-function Mobench adapter and install the hash-checked zkey as
# an application resource. These commands do not start BrowserStack sessions.
benchmarks/v1/scripts/build-mopro-webauthn-mobile.sh ios
benchmarks/v1/scripts/build-mopro-webauthn-mobile.sh android
benchmarks/v1/scripts/build-rapidsnark-webauthn-mobile.sh ios
benchmarks/v1/scripts/build-rapidsnark-webauthn-mobile.sh android

# Freeze and verify all five native Circom witnesses, then build arm64-only
# iPhone packages. These commands do not start BrowserStack sessions.
benchmarks/v1/scripts/prepare-provekit-ios-prebuilt.sh
benchmarks/v1/scripts/prepare-mopro-noir-ios-prebuilt.sh
benchmarks/v1/scripts/prepare-circom-native-witnesses.sh
benchmarks/v1/scripts/prepare-rapidsnark-oprf-ios-prebuilt.sh
benchmarks/v1/scripts/prepare-rapidsnark-passport-webauthn-ios-prebuilt.sh

benchmarks/v1/scripts/merge-ios-prebuilt-manifests.sh \
  target/v1-benchmarks/full-campaign-ios-prebuilt \
  target/v1-benchmarks/provekit-ios-prebuilt/manifest.json \
  target/v1-benchmarks/mopro-noir-ios-prebuilt/manifest.json \
  target/v1-benchmarks/rapidsnark-core-ios-prebuilt/manifest.json \
  target/v1-benchmarks/rapidsnark-oprf-ios-prebuilt/manifest.json

# Mac native: repeat for all four Arkworks functions and all three Rapidsnark
# functions listed below, preserving one warmup and five measured samples.
MOBENCH_WEBAUTHN_ZKEY="$PWD/target/v1-benchmarks/groth16/webauthn/webauthn_default_benchmark.zkey" \
  cargo run --release \
  --manifest-path target/v1-benchmarks/mopro/provekit-v1-mobile-adapters/Cargo.toml \
  --bin mobench-host -- \
  provekit_v1_mobile_adapters::bench_webauthn_arkworks_prove 1 5 \
  "$PWD/target/v1-benchmarks/arkworks-webauthn-prove.json"

MOBENCH_GROTH16_FIXTURE_ROOT="$PWD/target/v1-benchmarks/mobile-fixtures/groth16/webauthn" \
  cargo run --release \
  --manifest-path benchmarks/v1/rapidsnark-mobile-webauthn/Cargo.toml \
  --bin mobench-host -- \
  provekit_v1_rapidsnark_mobile_webauthn::bench_webauthn_rapidsnark_prove \
  1 5 "$PWD/target/v1-benchmarks/rapidsnark-webauthn-prove.json"

# Expanded manual scaffold commands:
MOPRO="$(benchmarks/v1/scripts/bootstrap-mopro.sh)"
mkdir -p target/v1-benchmarks/mopro
cd target/v1-benchmarks/mopro
"$MOPRO" init --adapter circom,noir --project-name provekit-v1-mobile-adapters
cd provekit-v1-mobile-adapters
printf '\n[workspace]\n' >> Cargo.toml
perl -pi -e 's/circom-prover = "0\\.1"/circom-prover = "=0.1.4"/' Cargo.toml
cargo generate-lockfile
cargo check --release

"$MOPRO" build \
  --mode release \
  --platforms android \
  --architectures aarch64-linux-android \
  --no-auto-update

"$MOPRO" build \
  --mode release \
  --platforms ios \
  --architectures aarch64-apple-ios \
  --no-auto-update
```

Before building, replace sample circuits with the frozen campaign artifacts.
For Circom WebAuthn, the validated path transpiles the compiled witness WASM
through Mopro `rust-witness`; `bootstrap-w2c2.sh` puts a pinned macOS host tool
on `PATH` so iOS cross-compilation does not incorrectly build the tool for the
phone. Provide the standard SnarkJS zkey by verified cache path. The retained
adapter recursively flattens scalar and nested-array JSON signals because
Mopro's generic helper otherwise drops them. Require field-for-field equality
with the validated WTNS plus a valid proof/verification gate before packaging.
The four registered functions are `bench_webauthn_arkworks_witness`,
`bench_webauthn_arkworks_prove`, `bench_webauthn_arkworks_verify`, and
`bench_webauthn_arkworks_e2e`. Rapidsnark uses the same validated WTNS and
registers prove, verify, and end-to-end; witness generation remains the shared
Circom phase. The retained
`.dat` remains a `witnesscalc_adapter` fallback, though its release C++
optimization exceeded the 30-minute local diagnostic cap. The published
proof-only path uses `rust-rapidsnark` with frozen WTNS plus the matching
SnarkJS zkey. Do not call Mopro's forked Arkworks lane `circom-compat`.

Mopro's Noir adapter is a real native Barretenberg path for Swift/iOS and
Kotlin/Android. Mopro 0.3.7 currently pins Noir beta.19; the existing campaign
fixtures are beta.11 with Barretenberg 0.87. Publish native results only after
the exact bytecode/proof compatibility gate passes, or label a recompiled
beta.19 run as a separate backend version.

The historical hosted Rapidsnark binary lookup is not part of the release path.
The campaign vendors/builds the pinned native libraries and records their exact
identity in the prepared bundle.

The campaign's resource-aware fallback builds the pinned iden3 native
libraries instead of using that unavailable binary host:

```bash
benchmarks/v1/scripts/build-rapidsnark-mobile-ios.sh passport-disclose
benchmarks/v1/scripts/build-rapidsnark-mobile-ios.sh passport-register
benchmarks/v1/scripts/prepare-rapidsnark-ios-prebuilt.sh

find target/v1-benchmarks/rapidsnark-ios-prebuilt \
  -name manifest.json \
  -type f \
  -print \
  -sort

benchmarks/v1/scripts/build-rapidsnark-mobile-android.sh passport-disclose
benchmarks/v1/scripts/build-rapidsnark-mobile-android.sh passport-register
benchmarks/v1/scripts/prepare-rapidsnark-android-prebuilt.sh

find target/v1-benchmarks/rapidsnark-android-prebuilt \
  -name manifest.json \
  -type f \
  -print \
  -sort
```

Run each manifest independently on `iPhone SE 2022-15`. Read the expected
source/function/iteration/warmup values from the manifest and retain its
Mobench summary, BrowserStack build ID, and session artifacts.
Run the Android manifests independently per device as well, beginning with
`passport-disclose-prove` on `Samsung Galaxy S24-14.0`.

## 5. Load credentials and verify both BrowserStack products

On the campaign workstation, load the credentials from the external Mobench
environment file. It is outside the ProveKit repository and must never be
copied into a result archive or printed:

```bash
set -a
source "$HOME/Code/world/mobile-bench-rs/.env"
set +a
```

Load the `BrowserStack` item from the personal `my.1password.com` account and
`Agents` vault into these two environment variables without printing them:

```bash
test -n "$BROWSERSTACK_USERNAME"
test -n "$BROWSERSTACK_ACCESS_KEY"
benchmarks/v1/scripts/preflight-browserstack-products.sh
```

Both `BrowserStack Automate` and `BrowserStack App Automate` subscriptions are
required, and both checks must pass.

Before any large Android App Automate upload, run the bounded ingestion
control:

```bash
V1_BROWSERSTACK_PROBE_TIMEOUT_MS=60000 \
  bun benchmarks/v1/scripts/probe-browserstack-espresso-ingestion.ts
```

Do not proceed unless its retained summary contains
`"diagnosis": "healthy"`, `"ingestion_recovered": true`, and a non-null
`bs://` handle. The default URL control avoids a redundant 20.37 MB transfer
from the Mac. To isolate multipart transport explicitly, set
`V1_BROWSERSTACK_PROBE_TRANSPORT=file`.

## 6. Run native App Automate packages

```bash
export V1_IOS_PREBUILT_MANIFEST="$PWD/target/mobench/prebuilt/ios/manifest.json"
export V1_ANDROID_PREBUILT_MANIFEST="$PWD/target/mobench/prebuilt/android/manifest.json"

benchmarks/v1/scripts/patch-xcuitest-testing-interop.sh \
  "$(dirname "$V1_IOS_PREBUILT_MANIFEST")"

benchmarks/v1/scripts/run-reproducibility.sh \
  --stage native \
  --campaign "$V1_CAMPAIGN" \
  --dry-run

benchmarks/v1/scripts/run-reproducibility.sh \
  --stage native \
  --campaign "$V1_CAMPAIGN" \
  --confirm-paid-browserstack
```

Use the same process for the World ID Arkworks OPRF prebuilt manifest and,
for Self passport, each manifest under
`target/v1-benchmarks/rapidsnark-ios-prebuilt/` and
`target/v1-benchmarks/rapidsnark-android-prebuilt/`. Keep their backend labels
and output directories distinct.

For the large Self applications, resolve the content-addressed app first:

```bash
benchmarks/v1/scripts/browserstack-app-cache.sh \
  lookup ios \
  target/v1-benchmarks/mobile-fixtures/groth16/register_sha256_sha256_sha256_rsa_65537_4096/fixture-manifest.json \
  /absolute/path/to/app.ipa
```

Only upload after exit status 3 confirms a cache miss. Persist the returned
immutable `bs://` URL with the campaign.

For Android recovery, run one function on one device per build. This prevents
one slow device or function from discarding otherwise valid cells:

```bash
benchmarks/v1/scripts/run-android-browserstack-shards.sh \
  --manifest target/v1-benchmarks/prebuilt-run-30041758043/android/manifest.json \
  --output-dir target/v1-benchmarks/provekit-android-shards \
  --only-function bench_mobile::bench_passport_complete_age_check_prepare \
  --device 'Samsung Galaxy S24-14.0' \
  --retry-failed
```

An App Automate `bs://` app handle is function-specific because the APK embeds
`bench_spec.json`. Reuse it only for the exact function, source SHA, warmup,
and iteration contract it was built for. The Espresso test runner is reusable
only after its executable code, manifest, and resources are confirmed
identical. Mobench must reject a returned function that differs from the
prepared manifest.

### 6a. Summarize cached Android recovery evidence

This recovery path is supporting evidence only. Use it only for retained,
function-specific App Automate handles when no exact-source package can be
uploaded. It does not satisfy or replace the primary one-warmup/five-sample
campaign.

Each workload root must contain exactly three `repetition-*` directories. Keep
the raw `build.json`, `schedule.json` when available, `session-<id>.json`, and
`device-<id>.log` files in each repetition directory. Do not delete them after
creating the compact summary.

```bash
RECOVERY_ROOT=benchmarks/v1/results/run-30041758043/provekit-android-cached-recovery

bun run benchmarks/v1/scripts/summarize-cached-android-recovery.ts \
  "$RECOVERY_ROOT/passport-prove" \
  bench_mobile::bench_passport_complete_age_check_prove \
  "$RECOVERY_ROOT/passport-prove-summary.json"

bun run benchmarks/v1/scripts/summarize-cached-android-recovery.ts \
  "$RECOVERY_ROOT/oprf-prove" \
  bench_mobile::bench_oprf_prove \
  "$RECOVERY_ROOT/oprf-prove-summary.json"

jq -e '
  .schema == "provekit.cached-android-recovery.v1"
  and .sampling_contract.repetitions == 3
  and .sampling_contract.total_warmups == 3
  and .sampling_contract.total_measured_samples == 6
  and .artifact_provenance.source_sha == null
  and ([.devices[].sample_count] | all(. == 6))
' \
  "$RECOVERY_ROOT/passport-prove-summary.json" \
  "$RECOVERY_ROOT/oprf-prove-summary.json"
```

Each cached artifact embeds one warmup plus two measured samples. The summary
aggregates three independent runs per device into the alternate contract of
three warmups plus six measured samples. It also retains app/test-suite
handles, build IDs, session IDs, device metadata, samples, and process peak
memory.

BrowserStack does not expose a downloadable APK or authoritative source SHA
for these retained `bs://` artifacts. A matching function and sampling
contract can be checked; exact source identity cannot. Label the output
**cached Android recovery (supporting evidence)** with unknown source SHA, and
do not combine it with exact-source primary measurements.

## 7. Run ProveKit browser/WASM through Automate

Start BrowserStack Local outside this command log. Resolve the available
iPhone SE 2022 OS version immediately before the run:

```bash
export BROWSERSTACK_LOCAL_IDENTIFIER=provekit-v1-unique-id
export BROWSERSTACK_OS_VERSION=resolved-version
export V1_WASM_TARGETS='macos_chrome_single ios_safari_single android_chrome_single'

benchmarks/v1/scripts/run-reproducibility.sh \
  --stage wasm \
  --campaign "$V1_CAMPAIGN" \
  --dry-run

benchmarks/v1/scripts/run-reproducibility.sh \
  --stage wasm \
  --campaign "$V1_CAMPAIGN" \
  --confirm-paid-browserstack
```

Resolve `BROWSERSTACK_OS_VERSION` from the live Automate catalog. Historical
device/OS pairs can disappear; for example, the successful retained Android
passport retry used Galaxy S21 with Android `12.0`, not the stale Android 13
matrix entry. The real-mobile WebDriver payload must omit `osName` from
`bstack:options`.

For Barretenberg, serve the frozen bundle:

```bash
benchmarks/v1/scripts/compile-noir-workloads.sh
(cd benchmarks/v1/barretenberg && bun install --frozen-lockfile && bun run build:web)
(cd benchmarks/v1/barretenberg && BARRETENBERG_BENCH_PORT=4174 bun run web/server.ts)
```

Then run each workload/phase cell:

```bash
cargo-mobench run-web \
  --url http://127.0.0.1:4174/ \
  --function 'barretenberg::oprf_taceo::prove' \
  --iterations 5 \
  --warmup 1 \
  --browser Safari \
  --os-version "$BROWSERSTACK_OS_VERSION" \
  --device 'iPhone SE 2022' \
  --build-name "provekit-v1-$V1_CAMPAIGN" \
  --session-name oprf-taceo-prove-iphone-se-2022 \
  --local-identifier "$BROWSERSTACK_LOCAL_IDENTIFIER" \
  --script-timeout-secs 1800 \
  --page-load-timeout-secs 120 \
  --output "target/v1-benchmarks/reproduction/$V1_CAMPAIGN/barretenberg-oprf-prove-ios.json" \
  --non-interactive \
  --yes
```

Repeat for `passport_complete_age_check`, `webauthn_assertion`, and
`oprf_taceo`, with `witness`, `prove`, `verify`, and `e2e`. Repeat on Android
Chrome. Do not rerun a retained five-sample cell merely because another cell
failed.

## 8. Validate and update the report

```bash
benchmarks/v1/scripts/run-reproducibility.sh \
  --stage validate \
  --campaign "$V1_CAMPAIGN"

bun run benchmarks/v1/scripts/generate-report-charts.ts

jq -e '
  [.. | objects | .samples? // empty]
  | all(length == 5)
' target/v1-benchmarks/reproduction/"$V1_CAMPAIGN"/*.json

git diff --check
```

Do not edit historical reports from this transcript. Update only the canonical
CSV through the export/validation path described in `REPRODUCIBILITY.md`.
