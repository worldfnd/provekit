// Verify data integrity chain (DG1 -> eContent -> SignedAttributes)
use commitment::commit_to_disclosure;
use data_check_integrity::{
    check_dg1_hash_within_sod, check_signed_attributes_sha256,
};
use utils::{
    types::{DG1Data, EContentData, SaltedValue, SignedAttrsData},
};

fn main(
    comm_in: pub Field,
    salt_in: Field,
    salted_dg1: SaltedValue<DG1Data>,
    dg1_padded_length: u64,
    dg1_hash_offset: u32,
    expiry_date_salt: Field,
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    e_content_len: u32,
    signed_attributes_size: u32,
    salted_private_nullifier: SaltedValue<Field>,
) -> pub Field {
    check_dg1_hash_within_sod(salted_dg1.value, dg1_padded_length, e_content, e_content_len, dg1_hash_offset);
    check_signed_attributes_sha256(signed_attributes, e_content, e_content_len);
    let comm_out = commit_to_disclosure(
        comm_in,
        salt_in,
        salted_dg1,
        expiry_date_salt,
        signed_attributes,
        signed_attributes_size as Field,
        e_content,
        salted_private_nullifier,
    );
    comm_out
}
