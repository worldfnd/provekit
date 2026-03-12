# Passport Input Generator

A Rust crate for parsing passport data and generating circuit inputs for the `merkle_age_check` multi-circuit pipeline.

## Overview

This crate handles the Rust side of the `merkle_age_check` proving pipeline. It:

- Parses passport Machine Readable Zone (MRZ) data from DG1 and SOD
- Validates passport signatures against DSC and CSCA certificates
- Computes Poseidon2 commitment chains across circuits
- Generates per-circuit input structs for both TBS-720 and TBS-1300 chains
- Provides two output modes: TOML files (for use with `nargo prove`) or direct proving (no TOML, bypasses file I/O)

## Circuit Pipeline

The `merkle_age_check` circuit splits passport verification into a chain of smaller circuits. The chain depends on the TBS certificate size:

### TBS-720 (4 circuits)

Used when the DSC TBS certificate fits within 720 bytes.

```
t_add_dsc_720 → t_add_id_data_720 → t_add_integrity_commit → t_attest
```

| Circuit | Verifies | Output |
|---------|----------|--------|
| `t_add_dsc_720` | CSCA signature over DSC TBS cert | `comm_out_1 = Poseidon2(salt, country, tbs_cert)` |
| `t_add_id_data_720` | DSC signature over SOD signed attrs | `comm_out_2 = Poseidon2(salt, country, signed_attrs, dg1, econtent, nullifier)` |
| `t_add_integrity_commit` | DG1 hash inside eContent | Merkle leaf = `Poseidon2(hDG1, sod_hash)` |
| `t_attest` | Merkle membership proof | `(param_commitment, scoped_nullifier)` |

### TBS-1300 (5 circuits)

Used when the DSC TBS certificate exceeds 720 bytes (padded to 1300). DSC verification is split into two circuits using partial SHA256.

```
t_add_dsc_hash_1300 → t_add_dsc_verify_1300 → t_add_id_data_1300 → t_add_integrity_commit → t_attest
```

| Circuit | Role |
|---------|------|
| `t_add_dsc_hash_1300` | SHA256 of first 640 bytes of TBS cert, outputs intermediate state |
| `t_add_dsc_verify_1300` | Continues SHA256, verifies CSCA RSA signature |
| `t_add_id_data_1300` | Same as 720 variant but with 1300-byte TBS |
| `t_add_integrity_commit` | Shared with TBS-720 chain |
| `t_attest` | Shared with TBS-720 chain |

The expensive registration circuits (`t_add_*`) run once. The fast `t_attest` circuit (Poseidon-only, no RSA) runs repeatedly for each attestation against a Merkle tree root.

## Library API

### `PassportReader`

Wraps DG1 + SOD data and produces per-circuit input structs.

```rust
use passport_input_gen::{
    Binary, PassportReader,
    MerkleAge720Config, MerkleAge1300Config, MerkleAgeBaseConfig,
};

// Construct from parsed passport data
let reader = PassportReader::new(
    Binary::from_slice(&dg1_bytes),
    sod,
    false,          // mockdata = false for real passports
    None,           // csca_pubkey = None (will look up from embedded CSCA set)
);

// Validate signatures; returns CSCA key index used
let csca_idx = reader.validate()?;

// Generate TBS-720 circuit inputs
let config = MerkleAge720Config {
    base: MerkleAgeBaseConfig {
        current_date: 1735689600,
        min_age_required: 18,
        ..Default::default()
    },
};
let inputs = reader.to_merkle_age_720_inputs(csca_idx, config)?;

// Generate TBS-1300 circuit inputs
let config = MerkleAge1300Config {
    base: MerkleAgeBaseConfig {
        current_date: 1735689600,
        min_age_required: 18,
        ..Default::default()
    },
    ..Default::default()
};
let inputs = reader.to_merkle_age_1300_inputs(csca_idx, config)?;
```

### Config structs

Both `MerkleAge720Config` and `MerkleAge1300Config` hold application-level parameters not extracted from the passport itself:

| Field | Description |
|-------|-------------|
| `salt_1`, `salt_2` (720) / `salt_0`, `salt_1`, `salt_2` (1300) | Commitment salts chained across circuits |
| `r_dg1` | Blinding factor for DG1 Poseidon2 commitment |
| `current_date` | Unix timestamp used for age/expiry checks |
| `min_age_required` / `max_age_required` | Age range to prove (0 = no upper bound) |
| `merkle_root` | Current Merkle tree root (from sequencer) |
| `leaf_index` | Leaf index in the Merkle tree |
| `merkle_path` | Sibling hashes for the Merkle membership proof |
| `service_scope` / `service_subscope` | H(domain) and H(purpose) for scoped nullifiers |
| `nullifier_secret` | Optional secret for nullifier salting |

Default values are mock/placeholder values suitable for testing. In production, `merkle_root`, `leaf_index`, `merkle_path`, and the scope fields are provided by the sequencer.

### Output: TOML files

Save all per-circuit inputs as TOML files for use with `nargo prove`:

```rust
use std::path::Path;

// TBS-720: writes t_add_dsc_720.toml, t_add_id_data_720.toml,
//          t_add_integrity_commit.toml, t_attest.toml
inputs.save_all(Path::new("path/to/output/dir"))?;
```

### Output: Direct proving (no TOML)

Convert inputs directly to a proof without writing TOML to disk. Inputs are serialized to JSON, parsed against the circuit ABI, and passed to `provekit-prover`:

```rust
use provekit_prover::Prove;
use noirc_abi::input_parser::Format;

let json = serde_json::to_string(&inputs.add_dsc)?;
let input_map = Format::Json.parse(&json, prover.witness_generator.abi())?;
let proof = prover.prove(input_map)?;
```

## CLI

The `passport_cli` binary is a non-interactive CLI tool.

```
cargo run --release --bin passport_cli -- --tbs <720|1300> --mode <toml|prove> [OPTIONS]
```

### CLI flags

| Flag | Description |
|------|-------------|
| `--tbs <720\|1300>` | TBS variant (required) |
| `--mode <toml\|prove>` | Mode (required) |
| `--output-dir <PATH>` | Output directory for TOML files or proof files, relative to current dir. Defaults to `benchmark-inputs/tbs_{720,1300}/test` |
| `--save-logs` | Save per-circuit log files during prove mode |
| `--log-dir <PATH>` | Directory for log files, relative to current dir. Default: `noir-examples/noir-passport/merkle_age_check/benchmark-inputs/logs/test` |

### Examples

```bash
# Generate TBS-720 TOML files to the default directory
cargo run --release --bin passport_cli -- --tbs 720 --mode toml

# Generate TBS-720 TOML files to a custom directory
cargo run --release --bin passport_cli -- --tbs 720 --mode toml --output-dir my-inputs/tbs_720

# Generate TBS-1300 proofs with per-circuit logs saved to default log dir
cargo run --release --bin passport_cli -- --tbs 1300 --mode prove --save-logs

# Generate TBS-720 proofs with logs saved to a custom directory
cargo run --release --bin passport_cli -- --tbs 720 --mode prove --save-logs --log-dir my-logs/tbs_720
```

### TOML mode

Generates all Prover.toml files under the output directory (default shown below):

```
noir-examples/noir-passport/merkle_age_check/benchmark-inputs/
  tbs_720/test/
    t_add_dsc_720.toml
    t_add_id_data_720.toml
    t_add_integrity_commit.toml
    t_attest.toml
  tbs_1300/test/
    t_add_dsc_hash_1300.toml
    t_add_dsc_verify_1300.toml
    t_add_id_data_1300.toml
    t_add_integrity_commit.toml
    t_attest.toml
```

Use `--output-dir` to write TOML files to a different directory.

### Prove mode

Loads `.pkp` prover keys from the benchmark-inputs directory, generates proofs for all circuits in the chain (including `t_attest`), and writes `.np` proof files alongside the prover keys.

The CLI includes tracing-based performance profiling. Span durations, memory usage, and allocation counts are printed to stderr during proving.

When `--save-logs` is passed, a separate log file is created per circuit (e.g. `t_add_dsc_720.log`). ANSI escape codes are stripped from the log files. The default log directory is `noir-examples/noir-passport/merkle_age_check/benchmark-inputs/logs/test`; use `--log-dir` to override.

## Mock data

The `mock_generator` module generates synthetic passport data for testing. All internal structures (eContent, SignedAttributes, TBS certificate) use proper DER-encoded ASN.1, matching the encoding that real passport chips produce.

```rust
use passport_input_gen::mock_generator::{
    dg1_bytes_with_birthdate_expiry_date,
    generate_sod,              // TBS-720: DER-encoded TBS that fits within 720 bytes
    generate_sod_with_padded_tbs, // TBS-1300: extends TBS with a padding extension
};

// DOB: Jan 1, 2007 / Expiry: Jan 1, 2032
let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");

// TBS-720 SOD
let sod = generate_sod(&dg1, &dsc_priv, &dsc_pub, &csca_priv, &csca_pub);

// TBS-1300 SOD (extends TBS to ~850 bytes via a padding extension)
let sod = generate_sod_with_padded_tbs(
    &dg1, &dsc_priv, &dsc_pub, &csca_priv, &csca_pub, 850
);
```

### DG1 (MRZ)

`dg1_bytes_with_birthdate_expiry_date` builds a 95-byte DG1 with:

- A 5-byte ASN.1 tag prefix (`0x61 0x5B 0x5F 0x1F 0x58`)
- A 90-byte TD3 MRZ containing realistic fields (document type `P<`, country `UTO`, name `DOE<<JOHN<MOCK`, document number `L898902C3`)
- Correct ICAO 9303 check digits for the document number, date of birth, expiry, and composite fields

### SOD internal structures

| Component | Encoding |
|-----------|----------|
| eContent | DER-encoded `LDSSecurityObject` (ICAO OID `2.23.136.1.1.1`) with SHA-256 hashes for DG1 and a dummy DG2 |
| SignedAttributes | DER-encoded `SET OF Attribute` containing `contentType` and `messageDigest` |
| TBS Certificate | DER-encoded `TBSCertificate` (X.509 v3) with `basicConstraints`, `keyUsage`, and `subjectKeyIdentifier` extensions |

For the TBS-1300 path, `generate_sod_with_padded_tbs` adds an opaque X.509 extension to inflate the TBS to the target size rather than appending raw filler bytes.

### Mock keys

Mock RSA key pairs are embedded in `mock_keys`:

```rust
use passport_input_gen::mock_keys::{MOCK_CSCA_PRIV_KEY_B64, MOCK_DSC_PRIV_KEY_B64};
// MOCK_CSCA_PRIV_KEY_B64: RSA-4096 (CSCA)
// MOCK_DSC_PRIV_KEY_B64:  RSA-2048 (DSC)
```

## Testing

```bash
cargo test -p passport-input-gen
```

Tests verify:
- Commitment chain self-consistency for both TBS-720 and TBS-1300 (each commitment is re-computed independently and compared to the library output)
- DG1 structure: correct ASN.1 header, MRZ field positions, ICAO check digits
- DER validity of eContent (`LDSSecurityObject`), SignedAttributes (`SET OF Attribute`), and TBS certificate
- Full roundtrip hash chain: DG1 hash in eContent, eContent hash in SignedAttributes, DSC signature verification, CSCA signature verification, and byte-offset findability of hashes and the DSC modulus
- Padded TBS reaching target length while remaining valid
- SOD parsing for real passport data fixtures
- Partial SHA256 intermediate state computation
- Poseidon2 hash outputs
