use common::{
    get_country_from_dg1,
    hash_salt_country_signed_attr_dg1_e_content_private_nullifier,
    hash_salt_dg1_private_nullifier
};
use utils::{get_expiry_date_from_mrz, types::SaltedValue};

/*
############################################################
# Circuit C - Integrity to Disclosure Commitment
############################################################
# Transitions from integrity verification commitment to disclosure commitment
############################################################

# Inputs/Outputs
############################################################
comm_in                 `assert comm_in == H(salt_in, country, signed_attr, signed_attr_size, dg1, e_content, private_nullifier)`
salt_in                 salt used in the integrity commitment
salted_dg1              salted DG1 data (MRZ)
expiry_date_salt        salt for expiry date
signed_attributes       the signed attributes from the passport
signed_attributes_size  actual size of signed attributes
e_content               the eContent containing data group hashes
salted_private_nullifier salted private nullifier value
comm_out                `H(salted_dg1_hash, salted_expiry_date_hash, salted_private_nullifier_hash)`

# What this proves
############################################################
- Verifies that comm_in matches the expected hash of integrity data
- Produces comm_out as a commitment to salted disclosure values
*/
pub fn commit_to_disclosure<let SA_SIZE: u32, let ECONTENT_SIZE: u32>(
    comm_in: Field,
    salt_in: Field,
    salted_dg1: SaltedValue<[u8; 95]>,
    expiry_date_salt: Field,
    signed_attributes: [u8; SA_SIZE],
    signed_attributes_size: Field,
    e_content: [u8; ECONTENT_SIZE],
    salted_private_nullifier: SaltedValue<Field>,
) -> Field {
    let country = get_country_from_dg1(salted_dg1.value);
    assert(
        comm_in
            == hash_salt_country_signed_attr_dg1_e_content_private_nullifier(
                salt_in,
                country,
                signed_attributes,
                signed_attributes_size,
                salted_dg1.value,
                e_content,
                salted_private_nullifier.value,
            ),
        "Commitment from 2nd subproof doesn't match in 3rd subproof",
    );

    let salted_expiry_date =
        SaltedValue::from_value(expiry_date_salt, get_expiry_date_from_mrz(salted_dg1.value));

    let comm_out = hash_salt_dg1_private_nullifier(
        salted_dg1,
        salted_expiry_date,
        salted_private_nullifier,
    );
    comm_out
}
