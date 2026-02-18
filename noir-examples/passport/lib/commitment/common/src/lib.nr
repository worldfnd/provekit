use poseidon::poseidon2::Poseidon2;
use utils::{
    constants::{DG1_LENGTH, ECONTENT_LENGTH, SIGNED_ATTRS_LENGTH, YYMMDD_DATE_LENGTH},
    get_issuing_country_from_mrz,
    pack_be_bytes_into_field,
    pack_be_bytes_into_fields,
    pack_le_bytes_into_fields,
    poseidon2_hash_packed,
    types::{
        Alpha2CountryCode, Alpha3CountryCode, DG1Data, EContentData, MRZExpiryDate, SaltedValue,
        SignedAttrsData,
    },
};

pub mod tests;

pub global CSC_CERT_TYPE: u8 = 1;
pub global DSC_CERT_TYPE: u8 = 2;

pub fn normalize_dg2_hash<let DG2_HASH_SIZE: u32>(dg2_hash: [u8; DG2_HASH_SIZE]) -> Field {
    let packed_dg2_hash: [Field; _] = pack_le_bytes_into_fields::<31, _>(dg2_hash);
    Poseidon2::hash(packed_dg2_hash, (DG2_HASH_SIZE + 30) / 31)
}

pub fn calculate_scoped_nullifier(
    salted_private_nullifier: SaltedValue<Field>,
    service_scope: Field,
    service_subscope: Field,
    nullifier_secret: Field,
) -> Field {
    if salted_private_nullifier.value == 0 {
        // If the private nullifier value is 0, it means it is hidden behind its salted hash
        // inside the circuit, so we just return 0 making this proof not usable to derive
        // the scoped nullifier
        0
    }
    // A nullifier secret set to 0 means it should be ignored and the nullifier should be computed without it
    // Otherwise, the nullifier should be computed with the secret
    else if nullifier_secret != 0 {
        Poseidon2::hash(
            [salted_private_nullifier.value, service_scope, service_subscope, nullifier_secret],
            4,
        )
    } else {
        Poseidon2::hash(
            [salted_private_nullifier.value, service_scope, service_subscope],
            3,
        )
    }
}

/// Only used for testing purposes for now
pub fn has_value_in_tags<let BIT_SIZE: u32, let TAGS_LEN: u32>(
    tags: [Field; TAGS_LEN],
    value: Alpha2CountryCode,
) -> bool {
    // Index for A
    let START_ASCII_INDEX: u32 = 65;
    let value_bytes = value.as_bytes();
    let converted_value = (value_bytes[0] as u32 - START_ASCII_INDEX) * 26
        + (value_bytes[1] as u32 - START_ASCII_INDEX);
    let mut result = false;
    let mut tags_bits: [[u1; BIT_SIZE]; TAGS_LEN] = [[0; BIT_SIZE]; TAGS_LEN];
    for i in 0..TAGS_LEN {
        tags[i].assert_max_bit_size::<BIT_SIZE>();
        tags_bits[i] = tags[i].to_le_bits();
    }
    for i in 0..TAGS_LEN {
        for j in 0..BIT_SIZE {
            let actual_index = (i * BIT_SIZE) + j;
            let has_bit_in_tag = (tags_bits[i][j] != 0);
            if (has_bit_in_tag) & (actual_index == converted_value) {
                result = true;
            }
        }
    }
    result
}

pub fn calculate_certificate_registry_leaf<let N: u32>(
    tags: [Field; 3],
    cert_type: u8,
    country: Alpha3CountryCode,
    public_key: [u8; N],
) -> Field {
    // Pack certificate type and country code into a single field
    let country_bytes: [u8; 3] = country.as_bytes();
    let unpacked_bytes: [u8; 4] =
        [cert_type as u8, country_bytes[0], country_bytes[1], country_bytes[2]];
    // Prepare and hash Poseidon2 inputs
    let mut hash_inputs: [Field; 4 + (N + 30) / 31] = std::mem::zeroed();
    hash_inputs[0] = tags[0];
    hash_inputs[1] = tags[1];
    hash_inputs[2] = tags[2];
    hash_inputs[3] = utils::pack_be_bytes_into_field::<4, 31>(unpacked_bytes);
    let packed_pubkey = utils::pack_be_bytes_into_fields::<N, (N + 30) / 31, 31>(public_key);
    for i in 0..packed_pubkey.len() {
        hash_inputs[4 + i] = packed_pubkey[i] as Field;
    }
    Poseidon2::hash(hash_inputs, hash_inputs.len())
}

pub fn get_country_from_dg1(dg1: DG1Data) -> Alpha3CountryCode {
    get_issuing_country_from_mrz(dg1).as_str_unchecked()
}

pub fn hash_salt_country_tbs<let TBS_MAX_SIZE: u32>(
    salt: Field,
    country: Alpha3CountryCode,
    tbs: [u8; TBS_MAX_SIZE],
) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let mut hash_inputs: [Field; 2 + ((TBS_MAX_SIZE + 30) / 31)] =
        [0; 2 + ((TBS_MAX_SIZE + 30) / 31)];
    hash_inputs[0] = salt;

    let packed_country: Field = pack_be_bytes_into_fields::<3, 1, 31>(country_bytes)[0];
    hash_inputs[1] = packed_country;

    let packed_tbs: [Field; (TBS_MAX_SIZE + 30) / 31] =
        pack_be_bytes_into_fields::<TBS_MAX_SIZE, _, 31>(tbs);
    for i in 0..((TBS_MAX_SIZE + 30) / 31) {
        hash_inputs[2 + i] = packed_tbs[i];
    }

    Poseidon2::hash(hash_inputs, 2 + ((TBS_MAX_SIZE + 30) / 31))
}

pub fn hash_salt_dg1_dg2_hash_private_nullifier(
    salted_dg1: SaltedValue<DG1Data>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg2_hash: SaltedValue<Field>,
    salted_dg2_hash_type: SaltedValue<u32>,
    salted_private_nullifier: SaltedValue<Field>,
) -> Field {
    let mut hash_inputs: [Field; 5] = std::mem::zeroed();

    hash_inputs[0] = salted_dg1.get_hash();
    hash_inputs[1] = salted_expiry_date.get_hash();
    // Commits over the "normalised" dg2 hash
    // i.e. the hash of dg2 hashed into a single field with Poseidon2
    hash_inputs[2] = salted_dg2_hash.get_hash();
    // Commit over the dg2 hash type (SHA1, SHA224, SHA256, SHA384 or SHA512)
    hash_inputs[3] = salted_dg2_hash_type.get_hash();
    hash_inputs[4] = salted_private_nullifier.get_hash();

    Poseidon2::hash(hash_inputs, 5)
}

pub fn calculate_private_nullifier<let SIG: u32>(
    dg1: DG1Data,
    e_content: EContentData,
    sod_sig: [u8; SIG],
) -> Field {
    let mut hash_inputs
        : [Field; (DG1_LENGTH + 30) / 31 + (ECONTENT_LENGTH + 30) / 31 + (SIG + 30) / 31] =
        std::mem::zeroed();

    let packed_dg1: [Field; (DG1_LENGTH + 30) / 31] =
        pack_be_bytes_into_fields::<DG1_LENGTH, _, 31>(dg1);
    for i in 0..((DG1_LENGTH + 30) / 31) {
        hash_inputs[i] = packed_dg1[i];
    }

    let packed_e_content: [Field; (ECONTENT_LENGTH + 30) / 31] =
        pack_be_bytes_into_fields::<ECONTENT_LENGTH, _, 31>(e_content);
    for i in 0..((ECONTENT_LENGTH + 30) / 31) {
        hash_inputs[(DG1_LENGTH + 30) / 31 + i] = packed_e_content[i];
    }

    let packed_sod_sig: [Field; (SIG + 30) / 31] = pack_be_bytes_into_fields::<SIG, _, 31>(sod_sig);
    for i in 0..((SIG + 30) / 31) {
        hash_inputs[(DG1_LENGTH + 30) / 31 + ((ECONTENT_LENGTH + 30) / 31) + i] = packed_sod_sig[i];
    }

    Poseidon2::hash(
        hash_inputs,
        (DG1_LENGTH + 30) / 31 + ((ECONTENT_LENGTH + 30) / 31) + (SIG + 30) / 31,
    )
}

pub fn hash_salt_country_signed_attr_dg1_e_content_private_nullifier(
    salt: Field,
    country: Alpha3CountryCode,
    signed_attr: SignedAttrsData,
    signed_attr_size: Field,
    dg1: DG1Data,
    e_content: EContentData,
    private_nullifier: Field,
) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();

    let mut hash_inputs
        : [Field; 4 + (SIGNED_ATTRS_LENGTH + 30) / 31 + ((DG1_LENGTH + 30) / 31) + ((ECONTENT_LENGTH + 30) / 31)] =
        std::mem::zeroed();
    hash_inputs[0] = salt;

    let packed_country: Field = pack_be_bytes_into_fields::<3, 1, 31>(country_bytes)[0];
    hash_inputs[1] = packed_country;

    let packed_signed_attr: [Field; (SIGNED_ATTRS_LENGTH + 30) / 31] =
        pack_be_bytes_into_fields::<SIGNED_ATTRS_LENGTH, _, 31>(signed_attr);
    for i in 0..((SIGNED_ATTRS_LENGTH + 30) / 31) {
        hash_inputs[2 + i] = packed_signed_attr[i];
    }

    hash_inputs[2 + (SIGNED_ATTRS_LENGTH + 30) / 31] = signed_attr_size;

    let packed_dg1: [Field; (DG1_LENGTH + 30) / 31] =
        pack_be_bytes_into_fields::<DG1_LENGTH, _, 31>(dg1);
    for i in 0..((DG1_LENGTH + 30) / 31) {
        hash_inputs[3 + (SIGNED_ATTRS_LENGTH + 30) / 31 + i] = packed_dg1[i];
    }

    let packed_e_content: [Field; (ECONTENT_LENGTH + 30) / 31] =
        pack_be_bytes_into_fields::<ECONTENT_LENGTH, _, 31>(e_content);
    for i in 0..((ECONTENT_LENGTH + 30) / 31) {
        hash_inputs[3 + (SIGNED_ATTRS_LENGTH + 30) / 31 + ((DG1_LENGTH + 30) / 31) + i] =
            packed_e_content[i];
    }
    hash_inputs[3
    + (SIGNED_ATTRS_LENGTH + 30) / 31
    + ((DG1_LENGTH + 30) / 31)
    + ((ECONTENT_LENGTH + 30) / 31)] = private_nullifier;

    Poseidon2::hash(
        hash_inputs,
        4
            + (SIGNED_ATTRS_LENGTH + 30) / 31
            + ((DG1_LENGTH + 30) / 31)
            + ((ECONTENT_LENGTH + 30) / 31),
    )
}

// Returns the merkle root of the tree from the provided leaf, index and hash_path, using the Poseidon2 hash function
// Arity is expected to be 2 and the the tree depth is equal to the hash_path array length
pub fn compute_merkle_root<let N: u32>(leaf: Field, index: Field, hash_path: [Field; N]) -> Field {
    let index_bits: [u1; N] = index.to_le_bits();
    let mut current = leaf;
    for i in 0..N {
        let path_bit = index_bits[i] == 1;
        let (hash_left, hash_right) = if path_bit {
            (hash_path[i], current)
        } else {
            (current, hash_path[i])
        };
        current = Poseidon2::hash([hash_left, hash_right], 2);
    }
    current
}

pub fn calculate_attestation_registry_leaf<let ROOT_KEY_SIZE: u32>(
    root_key_type: u8,
    root_key: [u8; ROOT_KEY_SIZE],
) -> Field {
    let mut bytes: [u8; ROOT_KEY_SIZE + 1] = [0; ROOT_KEY_SIZE + 1];
    bytes[0] = root_key_type;
    for i in 0..ROOT_KEY_SIZE {
        bytes[1 + i] = root_key[i];
    }
    poseidon2_hash_packed(bytes, ROOT_KEY_SIZE + 1)
}

// PROVEKIT MODIFICATION: Added for Merkle leaf construction in Registration phase.
// Hashes eContent into a single Field for use in leaf = Poseidon2(blinded_dg1, sod_hash).
pub fn calculate_sod_hash(e_content: EContentData) -> Field {
    let packed: [Field; (ECONTENT_LENGTH + 30) / 31] =
        pack_be_bytes_into_fields::<ECONTENT_LENGTH, _, 31>(e_content);
    Poseidon2::hash(packed, (ECONTENT_LENGTH + 30) / 31)
}

// PROVEKIT MODIFICATION: Added for Merkle leaf construction.
// Computes blinded_dg1 = Poseidon2(r_dg1 || packed_dg1) for privacy-preserving leaf.
pub fn calculate_blinded_dg1(r_dg1: Field, dg1: DG1Data) -> Field {
    let packed_dg1: [Field; (DG1_LENGTH + 30) / 31] =
        pack_be_bytes_into_fields::<DG1_LENGTH, _, 31>(dg1);
    let mut blinding_input: [Field; 1 + (DG1_LENGTH + 30) / 31] = std::mem::zeroed();
    blinding_input[0] = r_dg1;
    for i in 0..((DG1_LENGTH + 30) / 31) {
        blinding_input[1 + i] = packed_dg1[i];
    }
    Poseidon2::hash(blinding_input, blinding_input.len())
}

// PROVEKIT MODIFICATION: Added for Merkle leaf construction.
// leaf = Poseidon2(blinded_dg1, sod_hash)
pub fn calculate_merkle_leaf(r_dg1: Field, dg1: DG1Data, e_content: EContentData) -> Field {
    let blinded_dg1 = calculate_blinded_dg1(r_dg1, dg1);
    let sod_hash = calculate_sod_hash(e_content);
    Poseidon2::hash([blinded_dg1, sod_hash], 2)
}
