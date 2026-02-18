# noir-zkpassport

Noir ZK circuits for passport verification, forked from [zkPassport/circuits](https://github.com/zkpassport/circuits) and modified for Provekit's **Registration/Attestation** architecture.

## Architecture

### Registration Phase (One-time, Expensive) - Circuits 1-3

Proves the passport is valid and produces a **Merkle leaf** stored on-chain.

### Attestation Phase (Repeatable, Fast) - Circuit 4

Proves Merkle membership + age/expiry check + scoped nullifier. Can be re-run without repeating circuits 1-3.

## Circuits

| Circuit | Directory | Purpose | Parameterized By |
|---------|-----------|---------|------------------|
| 1 - DSC Sig Check | `bin/sig-check/dsc/` | Verify CSCA signed DSC certificate | TBS size, sig algo, key size, hash |
| 2 - ID Data Sig Check | `bin/sig-check/id-data/` | Verify DSC signed passport data (SOD) | TBS size, sig algo, key size, hash |
| 3 - Integrity + Leaf | `bin/data-check/integrity/` | Verify data integrity, produce Merkle leaf | SA hash, DG hash |
| 4 - Merkle Attestation | `bin/merkle-attest/age/standard/` | Merkle membership + age check | None (single variant) |

### Example: US Passport Pipeline

```
sig_check_dsc_tbs_700_rsa_pkcs_4096_sha256
  -> sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256
    -> data_check_integrity_sa_sha256_dg_sha256
      -> merkle_attest_age
```

### Example: Indian Passport Pipeline

```
sig_check_dsc_tbs_1600_ecdsa_nist_p256_sha256
  -> sig_check_id_data_tbs_1600_ecdsa_brainpool_384r1_sha384
    -> data_check_integrity_sa_sha384_dg_sha384
      -> merkle_attest_age
```

## Supported Algorithms

Inherited from zkPassport (unmodified):

- **RSA**: 1024, 2048, 3072, 4096, 6144 bit (PKCS#1 v1.5 and PSS)
- **ECDSA NIST**: P192, P224, P256, P384, P521
- **ECDSA Brainpool**: 192r1, 224r1, 256r1, 384r1, 512r1
- **Hash**: SHA1, SHA224, SHA256, SHA384, SHA512
- **TBS sizes**: 700, 1000, 1200, 1600

## Modifications from zkPassport

All modifications are marked with `// PROVEKIT MODIFICATION:` comments for audit traceability.

### Summary of Changes

| File | Change | Audit Impact |
|------|--------|--------------|
| `lib/commitment/csc-to-dsc/lib.nr` | Removed CSC registry Merkle verification; `csc_pubkey` is now a public circuit input, trust verified off-chain | Deletion only |
| `lib/commitment/common/lib.nr` | Added `calculate_sod_hash()`, `calculate_blinded_dg1()`, `calculate_merkle_leaf()` | 3 small functions (~30 lines) |
| `lib/commitment/integrity-to-leaf/` | **NEW** - replaces `integrity-to-disclosure`; outputs Merkle leaf instead of disclosure commitment | ~70 lines, core architectural diff |
| 284 DSC circuit `main.nr` files | Removed registry inputs, made `csc_pubkey` / `csc_pubkey_x`+`csc_pubkey_y` public | Input change only |
| 25 integrity circuit `main.nr` files | Removed DG2 hash extraction, added `r_dg1` blinding factor, output `(leaf, private_nullifier)` | Output change |
| `bin/merkle-attest/age/standard/` | **NEW** - Merkle membership proof + age check + scoped nullifier | ~90 lines, reuses audited libs |

### What was NOT changed (audited code reused as-is)

- All signature verification libraries (`sig-check/ecdsa/`, `sig-check/rsa/`, `sig-check/common/`)
- All data integrity checks (`data-check/integrity/`, `data-check/tbs-pubkey/`, `data-check/expiry/`)
- All utility code (`utils/` - MRZ parsing, ASN1 parsing, `find_subarray_index`, `unsafe_get_asn1_element_length`)
- Age comparison logic (`compare/age/`)
- Circuit 2 commitment (`commitment/dsc-to-id/`) - identical to zkPassport
- `compute_merkle_root()`, `calculate_scoped_nullifier()`, `calculate_private_nullifier()` in `commitment/common/`
- All 283 ID-data circuit variants (zero changes)

### What was removed (not needed)

- CSC certificate registry Merkle verification (circuit 1)
- DG2 hash extraction (circuit 3)
- EVM circuit variants
- Libraries: `bind/`, `disclose/`, `inclusion-check/`, `exclusion-check/`, `facematch/`, `outer/`, `commitment/scoped-nullifier/`, `commitment/integrity-to-disclosure/`

## Key Design Decisions

1. **SaltedValue pattern**: Kept as-is from zkPassport - avoids new soundness claims
2. **Private nullifier**: Uses zkPassport's `calculate_private_nullifier(dg1, e_content, sod_signature)` consistently across all circuits
3. **In-circuit offset computation**: All offsets (`tbs_certificate_len`, `signed_attributes_size`, `pubkey_offset`, `econtent_len`, `dg1_hash_offset`) are computed in-circuit via `unsafe_get_asn1_element_length` and `find_subarray_index` - none passed as external inputs
4. **No timestamp in param_commitment**: Matches zkPassport's approach
5. **Merkle leaf**: `leaf = Poseidon2(Poseidon2(r_dg1 || packed_dg1), calculate_sod_hash(e_content))` where `r_dg1` is a random blinding factor for privacy

## Building

```bash
# Compile a specific circuit
nargo compile --package sig_check_dsc_tbs_700_rsa_pkcs_4096_sha256

# Compile the attestation circuit
nargo compile --package merkle_attest_age

# Compile all circuits (takes a long time)
nargo compile
```

## Directory Structure

```
noir-zkpassport/
├── Nargo.toml                              # Workspace (13 libs + 592 circuits)
├── lib/
│   ├── sig-check/ecdsa/                    # UNMODIFIED - ECDSA verification (15 curves)
│   ├── sig-check/rsa/                      # UNMODIFIED - RSA verification (PKCS + PSS)
│   ├── sig-check/common/                   # UNMODIFIED - Hash wrappers (SHA1/224/256/384/512)
│   ├── data-check/tbs-pubkey/              # UNMODIFIED - Pubkey-in-TBS verification
│   ├── data-check/integrity/               # UNMODIFIED - DG1 + signed attrs hash checks
│   ├── data-check/expiry/                  # UNMODIFIED - Passport expiry check
│   ├── compare/age/                        # UNMODIFIED - Age comparison
│   ├── compare/date/                       # UNMODIFIED - Date comparison
│   ├── utils/                              # UNMODIFIED - MRZ, ASN1, packing, types
│   ├── commitment/common/                  # MODIFIED   - +calculate_sod_hash, +calculate_merkle_leaf
│   ├── commitment/csc-to-dsc/              # MODIFIED   - Removed registry check
│   ├── commitment/dsc-to-id/               # UNMODIFIED - commit_to_id()
│   └── commitment/integrity-to-leaf/       # NEW        - Replaces integrity-to-disclosure
├── bin/
│   ├── sig-check/dsc/                      # MODIFIED   - 284 variants, no registry inputs
│   ├── sig-check/id-data/                  # UNMODIFIED - 283 variants
│   ├── data-check/integrity/               # MODIFIED   - 25 variants, Merkle leaf output
│   └── merkle-attest/age/standard/         # NEW        - 1 variant, Merkle attestation
└── modify_circuits.py                      # Script used to bulk-modify circuits
```
