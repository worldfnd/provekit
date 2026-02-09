# Merkle Age Check zkPassport Verification

This directory contains two approaches for zkPassport age verification with Merkle tree integration, optimized based on TBS certificate size.

## Approach 1: 4-Circuit Chain

**Used when**: TBS certificate actual length < 720 bytes (padded to exactly 720 bytes)

**Circuits**:
1. [t_add_dsc_720](t_add_dsc_720/) - Verify CSCA signed DSC certificate (720-byte TBS)
2. [t_add_id_data_720](t_add_id_data_720/) - Verify DSC signed passport data (720-byte TBS)
3. [t_add_integrity_commit](t_add_integrity_commit/) - Verify data integrity and generate Merkle leaf
4. [t_attest](t_attest/) - Fast attestation proof using Merkle tree membership

## Approach 2: 5-Circuit Chain

**Used when**: TBS certificate actual length >= 720 bytes (padded to exactly 1300 bytes)

**Circuits**:
1. [t_add_dsc_hash_1300](t_add_dsc_hash_1300/) - Process first 640 bytes of DSC certificate (SHA256 start)
2. [t_add_dsc_verify_1300](t_add_dsc_verify_1300/) - Complete SHA256 and verify CSCA signature
3. [t_add_id_data_1300](t_add_id_data_1300/) - Verify DSC signed passport data (1300-byte TBS)
4. [t_add_integrity_commit](t_add_integrity_commit/) - Verify data integrity and generate Merkle leaf
5. [t_attest](t_attest/) - Fast attestation proof using Merkle tree membership

`t_add_integrity_commit` and `t_attest` are shared between both approaches

## Circuit Flow

### Registration Phase (One-time, Expensive)
Both approaches verify passport authenticity through RSA signature verification and SHA256 hashing:
- Verify CSCA signed DSC certificate
- Verify DSC signed passport data
- Generate Merkle leaf: `leaf = Poseidon2(hDG1, sod_hash)`

### Attestation Phase (Repeatable, Fast)
The `t_attest` circuit provides fast, repeatable proofs:
- Uses only Poseidon hashing (no RSA or SHA256)
- Proves Merkle tree membership
- Verifies age requirements
- Generates service-scoped nullifiers for Sybil resistance

## Usage

Benchmark inputs have already been generated and are available in the `benchmark-inputs` directory.

Scripts are provided separately for Case 1 (4-circuit chain) and Case 2 (5-circuit chain). Navigate to the scripts directory and run the appropriate sequence:

```bash
cd scripts
```

### For Case 1 (TBS < 720 bytes):
```bash
# 1. Compile circuits
./case1/compile.sh

# 2. Prepare proving artifacts
./case1/prepare.sh

# 3. Generate proofs
./case1/prove.sh
```

### For Case 2 (TBS >= 720 bytes):
```bash
# 1. Compile circuits
./case2/compile.sh

# 2. Prepare proving artifacts
./case2/prepare.sh

# 3. Generate proofs
./case2/prove.sh
```