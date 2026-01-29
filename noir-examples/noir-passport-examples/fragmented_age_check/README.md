# Fragmented zkPassport Age Verification

This directory contains two approaches for zkPassport age verification, optimized based on TBS certificate size.

## Approach 1: 4-Circuit Chain

**Used when**: TBS certificate actual length < 720 bytes (padded to exactly 720 bytes)

**Circuits**:
1. [sig_check_dsc_720](sig_check_dsc_720/) - Verify CSCA signed DSC certificate
2. [sig_check_id_data_720](sig_check_id_data_720/) - Verify DSC signed passport data
3. [data_check_integrity_sa](data_check_integrity_sa/) - Verify data integrity (DG1 → eContent → SignedAttributes)
4. [compare_age](compare_age/) - Extract DOB from MRZ, compute age, generate nullifier

## Approach 2: 5-Circuit Chain

**Used when**: TBS certificate actual length >= 720 bytes (padded to exactly 1300 bytes)

**Circuits**:
1. [sig_check_dsc_1300_hash](sig_check_dsc_1300_hash/) - Process first 640 bytes of DSC certificate (SHA256 start)
2. [sig_check_dsc_1300_verify](sig_check_dsc_1300_verify/) - Complete SHA256 and verify CSCA signature
3. [sig_check_id_data_1300](sig_check_id_data_1300/) - Verify DSC signed passport data
4. [data_check_integrity_sa](data_check_integrity_sa/) - Verify data integrity (DG1 → eContent → SignedAttributes)
5. [compare_age](compare_age/) - Extract DOB from MRZ, compute age, generate nullifier

