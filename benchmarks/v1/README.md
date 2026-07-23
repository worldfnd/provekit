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

Current V1 `prepare` output is functionally reproducible but not
byte-deterministic: repeated preparation of the same WebAuthn circuit produced
valid PKP/PKV files with different hashes and serialized sizes. Build once per
benchmark campaign, freeze the exact prebuilt bundle, and use its manifest hash
for every native and browser sample in that campaign. Do not combine samples
that used independently prepared ProveKit bundles.

The Barretenberg CRS is part of the cold-download bundle even though it is
universal rather than circuit-specific. Circom Groth16 `.zkey` files are part
of both the proving bundle and the circuit-specific setup.

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
- The pure WebAuthn assertion is isolated, deterministically generated, and
  wired into `bench-mobile` for ProveKit V1.
- World ID OPRF witness graphs and Arkworks proving keys are pinned and
  hash-verified; the pinned World ID source already contains their Mobench
  implementation.
- Self passport Circom and ProveKit passport are not equivalent statements:
  Self uses separate registration and disclosure proofs.
- Rapidsnark and the generic Circom mobile adapters are pinned but not yet
  linked into this repository's mobile benchmark crate.
- Browser/WASM execution needs a web runner and BrowserStack Automate control
  plane; native App Automate/XCUITest runners cannot execute that lane.

No workflow in this branch automatically spends BrowserStack capacity. Device
runs remain explicit workflow dispatches.
