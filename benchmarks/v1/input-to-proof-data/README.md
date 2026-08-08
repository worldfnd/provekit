# Input-to-proof benchmark data

This campaign measures the complete local path from raw circuit inputs through fresh witness generation to serialized proof bytes. Verification and tamper rejection are correctness gates outside the headline duration.

`input-to-proof-samples.csv` intentionally extends the existing `benchmark-samples.csv` column order. Its final two columns are `timing_mode` and `input_to_proof_time_ms`.

- `cold_local`: a fresh app/browser process and proof runtime for every attempt. Locked assets are already local; downloads are excluded.
- `warm_reuse`: the runtime remains initialized, but witness generation and proving are repeated for every attempt.

The proof-only semantic-parity CSV is immutable and is not imported as input-to-proof evidence.

The campaign has four workloads. `passport_complete_age_check` preserves the earlier Passport lane; `passport_p1` is the additional exact source pair at `noir/passport_p1/src/main.nr` and `circom/passport_p1/passport_p1.circom`.

The expected coverage is 72 logical series and 432 rows:

- 4 semantic profiles
- 3 targets
- 3 proof stacks
- 2 timing modes
- 1 warmup plus 5 measured attempts

Mac preparation and execution:

```bash
bash benchmarks/v1/scripts/prepare-passport-p1-circom-browser.sh
bash benchmarks/v1/scripts/build-provekit-v1-wasm.sh
bash benchmarks/v1/wasm/scripts/build.sh
bash benchmarks/v1/barretenberg/web/build.sh
bun run benchmarks/v1/scripts/run-mac-input-to-proof.ts
bun run benchmarks/v1/input-to-proof-data/export.ts
bun test benchmarks/v1/input-to-proof-data/export.test.ts
```

After the native iPhone warm campaign and every six-launch fresh-process cold
batch have been fetched, export both completed targets with:

```bash
INPUT_TO_PROOF_EXPORT_TARGETS=mac_chrome,iphone_se_2022 \
  bun run benchmarks/v1/input-to-proof-data/export.ts
```

The iPhone exporter reads only passed BrowserStack build/session artifacts.
It expands a cold batch's six-report JSON array into launch indices zero
through five while retaining the shared build/session provenance.
It preserves build/session IDs and raw-report hashes. The historical staged
Circom Passport row sums registration and disclosure latency, payload, and
proof bytes while taking the larger of the two process-RSS peaks. A warmup's
per-attempt RSS remains blank because Mobench exposes sample RSS only for the
five measured iterations; the run-wide peak is not substituted.

Native ProveKit V1 exposes witness generation and proving as a single timed
operation. Its `input_to_proof_time_ms` and `prover_time_ms` therefore contain
that integrated operation, while `witness_time_ms` is blank. Native Noir and
Circom retain their directly measured witness/prove split.

The iPhone Circom OPRF rows identify `wasmi-0.46.0-circom-wasm` as the witness
backend and `rust-rapidsnark-0.1.4` as the prover. The timed region consumes raw
input, interprets the exact Circom witness Wasm, serializes WTNS, and serializes
the Rapidsnark proof. Other iPhone Circom workloads retain `rust-witness-0.1.6`.

Only the hash-matched final evidence set belongs under
`target/v1-benchmarks/input-to-proof/iphone/publication`. Failed attempts,
superseded valid runs from a different frozen bundle, tunnel logs, and retry
diagnostics remain alongside it under the broader `iphone/` evidence root but
are intentionally outside the export scan.

The Mac runner is resumable. It writes one immutable JSON file per logical
series under `target/v1-benchmarks/input-to-proof/mac-chrome`. Set
`INPUT_TO_PROOF_SERIES` to a schema series ID to run one series, and use
`--force` only when intentionally replacing that raw series.

Correctness fixtures such as `witness.gz` and `reference.wtns` may be used for
preflight comparison, but cannot enter the measured boundary or the proving
payload of an input-to-proof row. The payload consists of the circuit/proving
material and raw input needed to create that proof.
