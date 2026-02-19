# Passport Input Generator

A Rust crate for parsing passport data and generating circuit inputs for the `passport/` multi-circuit proving pipeline.

## Overview

This crate handles the Rust side of the 4-stage passport proving pipeline. It:

- Parses passport Machine Readable Zone (MRZ) data from DG1 and SOD
- Validates passport signatures against DSC and CSCA certificates
- Computes Poseidon2 commitment chains across circuits
- Generates per-circuit input structs for parameterized RSA variants (key sizes, padding, hash algorithms)
- Provides two output modes: TOML files (for use with `nargo prove`) or direct proving (no TOML, bypasses file I/O)

## Circuit Pipeline

The `passport/` circuits split passport verification into a fixed 4-stage chain:

```
sig-check/dsc → sig-check/id-data → data-check/integrity → merkle-attest/age/standard
```

| Stage | Circuit path | Verifies | Output |
|-------|-------------|----------|--------|
| 1 | `sig-check/dsc/tbs_{N}/rsa/{padding}/{csca_bits}/{hash}/` | CSCA signature over DSC TBS cert | `comm_out_1 = Poseidon2(salt, country, tbs_cert)` |
| 2 | `sig-check/id-data/tbs_{N}/rsa/{padding}/{dsc_bits}/{hash}/` | DSC signature over SOD signed attrs | `comm_out_2 = Poseidon2(salt, country, signed_attrs, dg1, econtent, nullifier)` |
| 3 | `data-check/integrity/sa_{hash}/dg_{hash}/` | DG1 hash integrity inside eContent | Merkle leaf = `Poseidon2(Poseidon2(r_dg1, packed_dg1), sod_hash)` |
| 4 | `merkle-attest/age/standard/` | Merkle membership proof | `(param_commitment, scoped_nullifier, leaf)` |

The expensive registration circuits (stages 1–3) run once per passport. Stage 4 runs repeatedly for each attestation against a Merkle tree root.

### Supported variants

| Parameter | Values |
|-----------|--------|
| TBS size | `700`, `1000`, `1200`, `1600` bytes |
| CSCA key size | `1024`, `2048`, `3072`, `4096`, `6144` bits |
| DSC key size | `1024`, `2048`, `3072`, `4096` bits |
| RSA padding | `pkcs` (PKCS#1 v1.5), `pss` (RSASSA-PSS) |
| Hash algorithm | `sha1`, `sha224`, `sha256`, `sha384`, `sha512` |

## Library API

### `PassportReader`

Wraps DG1 + SOD data and produces per-circuit input structs.

```rust
use passport_input_gen::{
    Binary, PassportReader,
    CircuitVariant, AttestConfig,
};
use passport_input_gen::parser::types::{RsaKeyBits, RsaPadding, DigestAlgorithm};

// Construct from parsed passport data
let reader = PassportReader::new(
    Binary::from_slice(&dg1_bytes),
    sod,
    false,  // mockdata = false for real passports
    None,   // csca_pubkey = None (looks up from embedded CSCA set)
);

// Validate signatures; returns CSCA key index used
let csca_idx = reader.validate()?;

// Select circuit variant (RSA-4096 CSCA, RSA-2048 DSC, PKCS1, SHA-256, TBS-700)
let variant = CircuitVariant::default();

// Configure attestation parameters
let config = AttestConfig {
    current_date:     1735689600,  // Jan 1, 2025
    min_age_required: 18,
    ..Default::default()
};

// Generate all 4 circuit inputs
let inputs = reader.to_passport_inputs(csca_idx, &variant, config)?;
```

### `CircuitVariant`

Selects which specific circuit binary the inputs target:

```rust
let variant = CircuitVariant {
    tbs_size:      700,                  // TBS cert max size
    csca_key_bits: RsaKeyBits::Rsa4096,  // CSCA key size
    dsc_key_bits:  RsaKeyBits::Rsa2048,  // DSC key size
    csca_padding:  RsaPadding::Pkcs1,    // CSCA signature padding
    dsc_padding:   RsaPadding::Pkcs1,    // DSC signature padding
    sa_hash:       DigestAlgorithm::SHA256,  // signed-attributes digest
    dg_hash:       DigestAlgorithm::SHA256,  // DG1 digest in eContent
};

// Derive the 4 circuit directory paths for this variant
let paths = variant.circuit_paths();
// e.g. "sig-check/dsc/tbs_700/rsa/pkcs/4096/sha256"
```

### `AttestConfig`

Application-level parameters not extracted from the passport itself:

| Field | Description |
|-------|-------------|
| `salt_1`, `salt_2` | Commitment salts chained across stages 1–3 |
| `r_dg1` | Blinding factor for the DG1 Poseidon2 commitment (Merkle leaf privacy) |
| `current_date` | Unix timestamp for age/expiry checks |
| `min_age_required` / `max_age_required` | Age range to prove (0 = no upper bound) |
| `merkle_root` | Current Merkle tree root (from sequencer). Set to `ZERO_FIELD` to auto-compute. |
| `leaf_index` | Leaf index in the Merkle tree |
| `merkle_path` | Sibling hashes for the Merkle membership proof (24 levels) |
| `service_scope` / `service_subscope` | H(domain) and H(purpose) for scoped nullifiers |
| `nullifier_secret` | Optional secret for nullifier salting |

Default values are suitable for testing. In production, `merkle_root`, `leaf_index`, `merkle_path`, and scope fields are provided by the sequencer.

### Output: TOML files

Save all per-circuit inputs as TOML files for use with `nargo prove`:

```rust
use std::path::Path;
use passport_input_gen::CircuitInputSet;

// Writes 4 TOML files named after each circuit
inputs.save_all(Path::new("path/to/output/dir"))?;
```

### Output: Direct proving (no TOML)

Convert inputs directly to a proof without writing TOML to disk. Inputs are serialized to JSON, parsed against the circuit ABI, and passed to `provekit-prover`:

```rust
use provekit_prover::Prove;
use noirc_abi::input_parser::Format;

let json = serde_json::to_string(&inputs.dsc_sig_check)?;
let input_map = Format::Json.parse(&json, prover.witness_generator.abi())?;
let proof = prover.prove(input_map)?;
```

## CLI

The `passport_cli` binary is a non-interactive CLI tool.

```
cargo run --release --bin passport_cli -- --mode <toml|prove> [OPTIONS]
```

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--mode <toml\|prove>` | *(required)* | Output mode |
| `--tbs-size <N>` | `700` | TBS certificate max size: `700`, `1000`, `1200`, `1600` |
| `--csca-key-bits <N>` | `4096` | CSCA RSA key size in bits: `1024`, `2048`, `3072`, `4096`, `6144` |
| `--dsc-key-bits <N>` | `2048` | DSC RSA key size in bits: `1024`, `2048`, `3072`, `4096` |
| `--csca-padding <s>` | `pkcs` | CSCA padding scheme: `pkcs` or `pss` |
| `--dsc-padding <s>` | `pkcs` | DSC padding scheme: `pkcs` or `pss` |
| `--sa-hash <s>` | `sha256` | Signed-attributes digest: `sha1`, `sha224`, `sha256`, `sha384`, `sha512` |
| `--dg-hash <s>` | `sha256` | DG1 digest in eContent: `sha1`, `sha224`, `sha256`, `sha384`, `sha512` |
| `--output-dir <PATH>` | *(auto)* | Output directory for TOML/proof files, relative to CWD |
| `--save-logs` | off | Save per-circuit log files during prove mode |
| `--log-dir <PATH>` | `benchmark-inputs/logs` | Directory for log files |

### Examples

```bash
# Generate TOML files for the default variant (RSA-4096/2048, PKCS1, SHA-256, TBS-700)
cargo run --release --bin passport_cli -- --mode toml

# Generate TOML files for RSA-2048 DSC, TBS-1000
cargo run --release --bin passport_cli -- --mode toml --tbs-size 1000 --dsc-key-bits 2048

# Generate TOML files for PSS padding with SHA-384
cargo run --release --bin passport_cli -- --mode toml --csca-padding pss --dsc-padding pss --sa-hash sha384 --dg-hash sha384

# Generate proofs with per-circuit logs
cargo run --release --bin passport_cli -- --mode prove --save-logs

# Custom output directory
cargo run --release --bin passport_cli -- --mode toml --output-dir my-inputs/tbs_700
```

### TOML mode

Generates 4 Prover.toml files under the output directory. The default output path is auto-derived from the variant:

```
noir-examples/passport/bin/generated-inputs/
  tbs_700/rsa/pkcs/sha256/dg_sha256/
    dsc-sig-check.toml
    id-data-sig-check.toml
    integrity.toml
    attest.toml
```

### Prove mode

Loads `.pkp` prover keys from `noir-examples/passport/bin/`, generates proofs for all 4 circuits, and writes `.np` proof files to the output directory.

The CLI includes tracing-based performance profiling: span durations, memory usage, and allocation counts are printed to stderr. When `--save-logs` is set, a separate log file is created per circuit with ANSI codes stripped.

## Mock data

The `mock_generator` module generates synthetic passport data for testing. All internal structures use proper DER-encoded ASN.1, matching real passport chips.

```rust
use passport_input_gen::mock_generator::{
    dg1_bytes_with_birthdate_expiry_date,
    generate_sod,                          // default SHA-256, PKCS1
    generate_sod_with_config,              // custom MockConfig
    generate_sod_with_padded_tbs,          // default config, padded TBS
    generate_sod_with_padded_tbs_and_config, // custom config, padded TBS
    MockConfig,
};
use passport_input_gen::parser::types::{DigestAlgorithm, RsaPadding};

// DOB: Jan 1, 2007 / Expiry: Jan 1, 2032
let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");

// Default SOD (SHA-256, PKCS1)
let sod = generate_sod(&dg1, &dsc_priv, &dsc_pub, &csca_priv, &csca_pub);

// Custom hash algorithm and PSS padding
let sod = generate_sod_with_config(&dg1, &dsc_priv, &dsc_pub, &csca_priv, &MockConfig {
    dg_hash:     DigestAlgorithm::SHA384,
    sa_hash:     DigestAlgorithm::SHA384,
    dsc_padding: RsaPadding::Pss,
    csc_padding: RsaPadding::Pss,
});

// Padded TBS (adds an opaque X.509 extension to inflate TBS to target size)
let sod = generate_sod_with_padded_tbs(&dg1, &dsc_priv, &dsc_pub, &csca_priv, &csca_pub, 850);
```

### DG1 (MRZ)

`dg1_bytes_with_birthdate_expiry_date` builds a 95-byte DG1 with:

- A 5-byte ASN.1 tag prefix (`0x61 0x5B 0x5F 0x1F 0x58`)
- A 90-byte TD3 MRZ with realistic fields (document type `P<`, country `UTO`, name `DOE<<JOHN<MOCK`, document number `L898902C3`)
- Correct ICAO 9303 check digits for document number, date of birth, expiry, and composite fields

### SOD internal structures

| Component | Encoding |
|-----------|----------|
| eContent | DER-encoded `LDSSecurityObject` (ICAO OID `2.23.136.1.1.1`) with configurable-algorithm hashes for DG1 and a dummy DG2 |
| SignedAttributes | DER-encoded `SET OF Attribute` containing `contentType` and `messageDigest` |
| TBS Certificate | DER-encoded `TBSCertificate` (X.509 v3) with `basicConstraints`, `keyUsage`, and `subjectKeyIdentifier` extensions |

`generate_sod_with_padded_tbs` inflates the TBS to the target size by adding an opaque X.509 extension (OID `1.3.6.1.4.1.99999.1`) rather than appending raw filler bytes, preserving valid DER structure.

### Mock keys

Pre-generated mock RSA key pairs are embedded in `mock_keys`:

```rust
use passport_input_gen::mock_keys::{MOCK_CSCA_PRIV_KEY_B64, MOCK_DSC_PRIV_KEY_B64};
// MOCK_CSCA_PRIV_KEY_B64: RSA-4096 (CSCA)
// MOCK_DSC_PRIV_KEY_B64:  RSA-2048 (DSC)
```

Keys for other sizes (1024, 3072, 6144) can be generated on the fly using `rsa::RsaPrivateKey::new()`, though this is slow for large sizes.

## Commitment chain

The Poseidon2 commitment chain is computed on the Rust side to produce correct `comm_in` values for each circuit stage. All functions are in `commitment.rs` and match their Noir counterparts exactly:

| Function | Matches Noir |
|----------|-------------|
| `hash_salt_country_tbs` | `hash_salt_country_tbs<TBS_MAX_SIZE>()` |
| `calculate_private_nullifier` | `calculate_private_nullifier<SIG>()` |
| `hash_salt_country_sa_dg1_econtent_nullifier` | `hash_salt_country_signed_attr_dg1_e_content_private_nullifier()` |
| `calculate_h_dg1` | `calculate_blinded_dg1()` |
| `calculate_sod_hash` | `calculate_sod_hash()` |
| `calculate_leaf` | `calculate_merkle_leaf()` |
| `compute_merkle_root` | `compute_merkle_root<N>()` |

## Testing

```bash
cargo test -p passport-input-gen
```

Tests verify:
- **Commitment chain self-consistency**: all 4 commitment values are re-computed independently from raw passport data and compared to the library output
- **DG1 structure**: correct ASN.1 header, MRZ field positions, ICAO check digits
- **DER validity**: eContent (`LDSSecurityObject`), SignedAttributes (`SET OF Attribute`), and TBS certificate
- **Full hash chain roundtrip**: DG1 hash in eContent, eContent hash in SignedAttributes, DSC signature verification, CSCA signature verification, byte-offset findability of hashes and the DSC modulus
- **Padded TBS**: reaches target length while remaining valid DER
- **SOD parsing**: real passport data fixtures
- **Poseidon2 hash outputs**: known-good values
- **Field count sanity**: packing of all buffer sizes (700/1000/1200/1600 TBS, 95 DG1, 220 signed attrs, 700 eContent, all RSA key sizes)
