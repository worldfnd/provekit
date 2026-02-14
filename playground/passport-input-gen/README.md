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

The `passport_cli` binary provides an interactive interface for both modes.

```
cargo run --release --bin passport_cli
```

You will be prompted to select:

1. **TBS variant** — `1` for TBS-720, `2` for TBS-1300
2. **Mode** — `1` to generate TOML files, `2` to generate proofs directly

### TOML mode

Generates all Prover.toml files under:

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

### Prove mode

Loads `.pkp` prover keys from the benchmark-inputs directory, generates proofs for all circuits in the chain (including `t_attest`), and writes `.np` proof files alongside the prover keys.

The CLI includes tracing-based performance profiling. Span durations, memory usage, and allocation counts are printed to stderr during proving.

## Mock data

The `mock_generator` module generates synthetic passport data for testing:

```rust
use passport_input_gen::mock_generator::{
    dg1_bytes_with_birthdate_expiry_date,
    generate_fake_sod,              // TBS-720: actual TBS ~400 bytes
    generate_fake_sod_with_padded_tbs, // TBS-1300: pads TBS to given size
};

// DOB: Jan 1, 2007 / Expiry: Jan 1, 2032
let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");

// TBS-720 SOD
let sod = generate_fake_sod(&dg1, &dsc_priv, &dsc_pub, &csca_priv, &csca_pub);

// TBS-1300 SOD (pads TBS to 850 bytes)
let sod = generate_fake_sod_with_padded_tbs(
    &dg1, &dsc_priv, &dsc_pub, &csca_priv, &csca_pub, 850
);
```

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
- Commitment chain correctness for TBS-720 (against known-good values from verified TOML files)
- Commitment chain self-consistency for TBS-1300
- SOD parsing for real passport data fixtures
- Partial SHA256 intermediate state computation
- Poseidon2 hash outputs
