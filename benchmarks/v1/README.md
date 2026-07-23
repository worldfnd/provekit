# ProveKit V1 reproducible benchmarks

This directory is the source of truth for the ProveKit V1 announcement
benchmarks. It pins every external source, defines the comparison contract, and
keeps generated circuit/proving artifacts outside the repository under
`target/v1-benchmarks/`.

The benchmark suite has three workloads:

- passport age/assertion proving;
- a pure WebAuthn assertion proof, without registry inclusion or key
  registration;
- the World ID OPRF query/nullifier flow.

The intended native comparison is:

| Frontend | Proving backend | Mobile implementation |
| --- | --- | --- |
| Noir | ProveKit V1 | Existing Rust/native C ABI Mobench runner |
| Noir | Barretenberg | Native Barretenberg adapter |
| Circom | Groth16/Rapidsnark | Native C++ adapter |
| Circom | Groth16/Arkworks | Rust `circom-compat` adapter with generated Rust witnesses |

Browser/WASM runs are a separate execution surface. Native and WASM results
must never be merged into one device row.

Native Android and iOS proving use Rayon's normal platform-default worker
count through Mobench's `native-c-abi` runner. The benchmark does not impose an
Android-specific thread cap; the effective `rayon_threads` value is recorded
in the `MOBENCH_LIFECYCLE` start event as the normal global pool is lazily
initialized. The portable browser/WASM lane remains single-threaded for mobile
Safari compatibility and must be reported separately.

## Reproducibility contract

1. Use the exact commits in `sources.lock.json`.
2. Record the exact device and OS identifier resolved by BrowserStack.
3. Use one warmup and at least five measured samples for publication runs.
4. Record witness generation, initialization, proving, and verification as
   separate phases.
5. Record both:
   - the cold-download bundle, including runtime and any required CRS/SRS; and
   - the incremental circuit bundle, excluding an already-installed shared
     runtime.
6. Retain proof bytes, public outputs, circuit/backend complexity, and a
   verification result for every successful sample.
7. Do not compare circuits until `benchmark-contract.json` marks their
   statement as equivalent.

ProveKit V1 `prepare` output is intentionally nondeterministic. Independently
prepared PKP/PKV pairs are expected to have different bytes, hashes, and
serialized sizes; comparing hashes across preparations is invalid. Prepare
once per benchmark campaign, content-address and freeze that campaign's exact
pair, and use the same bundle for every native and browser sample. Never
combine samples from independently prepared ProveKit bundles.

The Barretenberg CRS is part of the cold-download bundle even though it is
universal rather than circuit-specific. Circom Groth16 `.zkey` files are part
of both the proving bundle and the circuit-specific setup.

## Large Groth16 mobile fixtures

The power-20 PTAU is a preparation-only artifact and must not be shipped to a
device. The generated Self keys are smaller but still substantial:

| Self circuit | Generated zkey |
| --- | ---: |
| RSA-4096 registration | 499,111,760 bytes |
| VC and disclosure | 69,717,184 bytes |

These keys are not as large as the 1,208,042,648-byte PTAU. They do compress
enough to matter for one-time distribution: zstd level 3 produced
285,591,572 bytes for registration and 40,024,363 bytes for disclosure.
Publication bundle tables should report both transfer and installed bytes.
Repeated device runs favor the installed, directly mmap-able form; the upload
cache removes the large transfer from each run.

Prepare one content-addressed mobile resource set per workload:

```bash
benchmarks/v1/scripts/prepare-groth16-mobile-fixture.sh \
  register_sha256_sha256_sha256_rsa_65537_4096
benchmarks/v1/scripts/prepare-groth16-mobile-fixture.sh vc_and_disclose
```

The output under `target/v1-benchmarks/mobile-fixtures/` uses copy-on-write
clones when the filesystem supports them, so the frozen resource does not
share a mutable inode with preparation output. It records every byte in
`fixture-manifest.json`. The reference WTNS is a proof-only harness input and
is not counted as circuit download size. It keeps witness generation out of
the Rapidsnark proving measurement; witness generation remains a separate
benchmark function.

Build one Mobench IPA/APK per workload. On iOS, keep the zkey as a normal
installed bundle resource and mmap it directly from `Bundle.main`; do not copy
it into Documents or a temporary directory. On Android, add `zkey` and `wtns`
to `androidResources.noCompress`, then use `AssetManager.openFd` and mmap the
asset's offset and length. Artifact hashing, app installation, file opening,
and mmap setup all happen before measured iterations.

BrowserStack App Automate accepts a 100-character `custom_id`, supports lookup
by that ID, and expires [XCUITest](https://www.browserstack.com/docs/app-automate/api-reference/xcuitest/apps)
and [Espresso](https://www.browserstack.com/docs/app-automate/api-reference/espresso/apps)
uploads after 30 days by default. Cache the prebuilt app by API family,
platform, fixture campaign hash, and final IPA/APK hash:

```bash
benchmarks/v1/scripts/browserstack-app-cache.sh \
  id ios path/to/fixture-manifest.json path/to/BenchRunner.ipa

# Read-only lookup; exit status 3 means the app is absent or expired.
BROWSERSTACK_USERNAME=... BROWSERSTACK_ACCESS_KEY=... \
  benchmarks/v1/scripts/browserstack-app-cache.sh \
  lookup ios path/to/fixture-manifest.json path/to/BenchRunner.ipa

# Explicit upload only after a cache miss.
BROWSERSTACK_USERNAME=... BROWSERSTACK_ACCESS_KEY=... \
  benchmarks/v1/scripts/browserstack-app-cache.sh \
  upload ios path/to/fixture-manifest.json path/to/BenchRunner.ipa
```

The pinned Mobench 0.1.48 `run-prebuilt` path currently uploads every app and
does not set or resolve a `custom_id`. Before paid Groth16 runs, extend Mobench
so `run-prebuilt` accepts a verified cached `app_url` or performs the same
lookup-before-upload operation. The XCUITest/Espresso test package may still
be uploaded per run; the large app-under-test must be reused.

Persist the returned immutable `bs://` app URL and upload time in the trusted
run artifact, validate it through the list endpoint before reuse, and
re-upload on absence or expiry. Schedule with that immutable URL, not the
mutable custom-ID alias. BrowserStack's App Automate API reference does not
publish an upload-size ceiling, so confirm the account limit before the first
registration-app upload; Mobench's 4 GiB local package limit is not evidence
of a BrowserStack service limit.

The locally generated `_0000.zkey` files use SnarkJS phase-2 setup directly
from the pinned PTAU. They are benchmark campaign artifacts, not a
multi-contributor production ceremony. Publication must either distribute the
exact hashed campaign keys or replace them with ceremony-backed keys and
record that provenance; independently regenerated zkeys define a new
campaign.

## Bootstrap

Prerequisites:

- Git
- `jq`
- the Rust toolchain from the repository `rust-toolchain.toml`
- a BrowserStack App Automate subscription for device runs

Fetch the pinned upstream sources without modifying an existing checkout:

```bash
benchmarks/v1/scripts/bootstrap-sources.sh
```

Sources are placed in:

```text
target/v1-benchmarks/sources/
```

The script refuses to replace or reset a source directory whose `HEAD` differs
from the lock file.

## Existing working lane

The ProveKit V1 native lane is already wired through `bench-mobile/` and
`.github/workflows/mobile-bench.yml`. Generate its embedded fixtures with:

```bash
MOBENCH_CI_PREPARE=1 ./bench-mobile/scripts/generate-fixtures.sh
```

For an announcement run, include prepare, prove, verify, and end-to-end
functions rather than only the historical prove-only defaults.

The same workflow builds four portable, single-thread Mobench 0.1.48 web
bundles for complete passport, fragmented passport, WebAuthn assertion, and
OPRF proving. Witnesses are generated in the secretless preparation job and
embedded per workload; they are never generated or downloaded during a timed
browser sample. Each workload is a separate bundle because the wasm-bindgen
interpreter used by the release backend cannot process the combined
multi-workload inventory module.

The first setup in each browser instance proves and verifies a valid canary and
requires a transcript-tampered copy to fail verification. That gate is outside
the measured proof phase. Publication runs use one warmup and five samples on
macOS Safari, Windows Chrome, iOS Safari, and Android Chrome and save a
source/bundle/session provenance sidecar next to every raw Mobench report.

## Bundle measurement

Create a tab-separated manifest with `scope`, `kind`, `path`, and an optional
MIME type for web artifacts:

```text
cold-download	runtime	path/to/runtime
cold-download	setup	path/to/powers-or-zkey
incremental	circuit	path/to/circuit	application/octet-stream
```

Then record sizes and hashes:

```bash
benchmarks/v1/scripts/measure-bundle.sh \
  path/to/bundle-files.tsv \
  target/v1-benchmarks/results/passport-provekit-bundle.json
```

All listed paths must be regular files. The output contains a SHA-256 for every
artifact and totals per scope.

## Current implementation boundary

- ProveKit native passport and OPRF proving already run through Mobench.
- The pure WebAuthn assertion is isolated, uses a deterministic input fixture,
  and is wired into `bench-mobile` for ProveKit V1. Proof bytes are not
  expected to be deterministic.
- World ID OPRF witness graphs and Arkworks proving keys are pinned and
  hash-verified; the pinned World ID source already contains their Mobench
  implementation.
- Self passport Circom and ProveKit passport are not equivalent statements:
  Self uses separate registration and disclosure proofs.
- Rapidsnark and the generic Circom mobile adapters are pinned but not yet
  linked into this repository's mobile benchmark crate.
- ProveKit V1 browser/WASM execution is wired through Mobench 0.1.48 and
  BrowserStack Automate. Native App Automate/XCUITest results remain separate.
- Barretenberg still has browser TypeScript smokes rather than a registered
  Mobench native or web adapter.
- No licensed semantically equivalent Circom WebAuthn circuit is currently
  available, so that matrix cell must be reported as unavailable rather than
  substituted.
- Self passport Arkworks witness generation remains blocked by dynamic Circom
  control flow; the existing Self Rapidsnark lane is host-only until its
  resource-aware native adapter is linked.

No workflow in this branch automatically spends BrowserStack capacity. Device
runs remain explicit workflow dispatches.
