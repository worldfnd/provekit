// PROVEKIT MODIFICATION: Replaced disclosure commitment with Merkle leaf output.
// Removed DG2 hash extraction. Added r_dg1 blinding factor.
// Original: auto-generated from src/ts/scripts/circuit-builder.ts
use commitment::commit_to_leaf;
use data_check_integrity::{
    check_dg1_sha384, check_signed_attributes_sha384,
};
use utils::{
    types::{DG1Data, EContentData, SaltedValue, SignedAttrsData},
};

fn main(
    comm_in: pub Field,
    salt_in: Field,
    salted_dg1: SaltedValue<DG1Data>,
    r_dg1: Field,

    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    salted_private_nullifier: SaltedValue<Field>,
) -> pub (Field, Field) {
    // Get the length of e_content by parsing the ASN.1
    // Safety: This is safe because the length must be correct for econtent to hash to
    // the expected digest in signed attributes as checked below in check_signed_attributes_sha384
    let e_content_size = unsafe { utils::unsafe_get_asn1_element_length(e_content) };
    // Check the integrity of the data
    check_dg1_sha384(salted_dg1.value, e_content, e_content_size);
    // Get the length of signed_attributes by parsing the ASN.1
    // Safety: This is safe because the length was checked in the ID data circuit and the whole signed attributes
    // was committed over in that same circuit
    let signed_attributes_size =
        unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };
    check_signed_attributes_sha384(signed_attributes, e_content, e_content_size);
    // PROVEKIT MODIFICATION: Output Merkle leaf instead of disclosure commitment
    let (leaf, private_nullifier) = commit_to_leaf(
        comm_in,
        salt_in,
        salted_dg1,
        signed_attributes,
        signed_attributes_size as Field,
        e_content,
        salted_private_nullifier,
        r_dg1,
    );
    (leaf, private_nullifier)
}
