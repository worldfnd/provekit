use common::{
    get_country_from_dg1, hash_salt_country_signed_attr_dg1_private_nullifier,
    hash_salt_dg1_private_nullifier,
};

/*
############################################################
# Circuit C
############################################################
# Verifies the integrity of the ePassport data
############################################################

# Inputs/Outputs
############################################################
current_date
comm_in                 `assert comm_in == H(salt, country, signed_attr, sod_sig)`
salt
id_data
private_nullifier       `assert private_nullifier == H(dg1, sod_sig)`
comm_out                `H(salt, dg1, private_nullifier)`

# Checks
############################################################
- Check that passport expiry date <= current date
- Checks that the dg1 hash is present in econtent
- Checks that the hash of econtent is present in signed_attr
*/
pub fn commit_to_disclosure<let SA_SIZE: u32>(
    comm_in: Field,
    salt: Field,
    dg1: [u8; 95],
    signed_attributes: [u8; SA_SIZE],
    signed_attributes_size: Field,
    private_nullifier: Field,
) -> Field {
    let country = get_country_from_dg1(dg1);
    assert(
        comm_in
            == hash_salt_country_signed_attr_dg1_private_nullifier(
                salt,
                country,
                signed_attributes,
                signed_attributes_size,
                dg1,
                private_nullifier,
            ),
    );
    // println(f"comm_in: {comm_in}");
    // println(f"private_nullifier: {private_nullifier}");
    let comm_out = hash_salt_dg1_private_nullifier(salt, dg1, private_nullifier);
    // println(f"comm_out: {comm_out}");
    comm_out
}
