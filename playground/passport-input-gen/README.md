# Passport Input Generator

A Rust crate for parsing passport data and generating circuit inputs for Noir Circuits.

## Overview

This crate provides functionality to:

- Parse passport Machine Readable Zone (MRZ) data from DG1 and SOD
- Validate passport signatures using DSC and CSCA certificates
- Generate mock passport data for testing
- Convert passport data to circuit inputs for Noir zero-knowledge circuits

### `PassportReader`

Main structure for reading and validating passport data.

**Structure:**

```rust
pub struct PassportReader {
    dg1:         Binary,                // DG1 (Machine Readable Zone) data
    sod:         SOD,                   // Security Object Document
    mockdata:    bool,                  // Flag indicating mock vs real passport data
    csca_pubkey: Option<RsaPublicKey>,  // Optional CSCA public key for mock data
}
```

**Key Behavior:**

- When `mockdata: false`: The reader searches for existing CSCA keys from a predefined set. Currently supports USA CSCA keys loaded from the system. The `validate()` method iterates through all available USA CSCA keys to find one that successfully validates the passport signature.

- When `mockdata: true`: The reader uses the provided `csca_pubkey` for validation. This is useful for testing with synthetic passport data generated using mock keys.

**Methods:**

- `validate() -> Result<usize, PassportError>` - Validates the passport signatures and returns the CSCA key index used. For mock data, always returns index 0. For real data, returns the index of the USA CSCA key that successfully validated the passport.
- `to_circuit_inputs(current_date: u64, min_age_required: u8, max_age_required: u8, csca_key_index: usize) -> Result<CircuitInputs, PassportError>` - Converts passport data to circuit inputs

#### `CircuitInputs`

Contains all necessary inputs for Noir circuits.

**Methods:**

- `to_toml_string() -> String` - Converts circuit inputs to TOML format string
- `save_to_toml_file<P: AsRef<Path>>(path: P) -> std::io::Result<()>` - Saves circuit inputs to a TOML file

### Mock Data Generation

#### `mock_generator` module

**Functions:**

- `dg1_bytes_with_birthdate_expiry_date(birthdate: &[u8; 6], expiry: &[u8; 6]) -> Vec<u8>` - Generates fake DG1 data with specified birth and expiry dates (format: YYMMDD)
- `generate_fake_sod(dg1: &[u8], dsc_priv: &RsaPrivateKey, dsc_pub: &RsaPublicKey, csca_priv: &RsaPrivateKey, _csca_pub: &RsaPublicKey) -> SOD` - Creates a synthetic SOD structure for testing

#### `mock_keys` module

**Constants:**

- `MOCK_CSCA_PRIV_KEY_B64: &str` - Base64-encoded mock CSCA private key for testing
- `MOCK_DSC_PRIV_KEY_B64: &str` - Base64-encoded mock DSC private key for testing

## Usage Example

```rust
use passport_input_gen::{PassportReader, mock_generator, mock_keys};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};

// Load mock keys
let csca_der = STANDARD.decode(mock_keys::MOCK_CSCA_PRIV_KEY_B64)?;
let csca_priv = RsaPrivateKey::from_pkcs8_der(&csca_der)?;
let csca_pub = csca_priv.to_public_key();

let dsc_der = STANDARD.decode(mock_keys::MOCK_DSC_PRIV_KEY_B64)?;
let dsc_priv = RsaPrivateKey::from_pkcs8_der(&dsc_der)?;
let dsc_pub = dsc_priv.to_public_key();

// Generate mock passport data
let dg1 = mock_generator::dg1_bytes_with_birthdate_expiry_date(b"900101", b"300101");
let sod = mock_generator::generate_fake_sod(&dg1, &dsc_priv, &dsc_pub, &csca_priv, &csca_pub);

// Create passport reader
let reader = PassportReader {
    dg1: Binary::from_slice(&dg1),
    sod,
    mockdata: true,
    csca_pubkey: Some(csca_pub),
};

// Validate passport
let csca_index = reader.validate()?;

// Generate circuit inputs
let current_timestamp = chrono::Utc::now().timestamp() as u64;
let inputs = reader.to_circuit_inputs(current_timestamp, 18, 70, csca_index)?;

// Export to TOML
inputs.save_to_toml_file("circuit_inputs.toml")?;
```

## Testing

The crate includes tests for mock data generation and validation. Run tests with:

```bash
cargo test
```
