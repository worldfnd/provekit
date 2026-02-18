// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_ecdsa_pubkey_in_tbs;
use sig_check_common::sha512_and_check_data_to_sign;
use sig_check_ecdsa::verify_nist_p521;
use utils::{split_array, types::{DG1Data, EContentData, SignedAttrsData}};

fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    dsc_pubkey_x: [u8; 66],
    dsc_pubkey_y: [u8; 66],
    sod_signature: [u8; 132],
    tbs_certificate: [u8; 1600],
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
) -> pub Field {
    // Get the length of signed_attributes by parsing the ASN.1
    // Safety: This is safe because the length must be correct for the hash and signature to be valid
    let signed_attributes_size =
        unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };
    let (r, s) = split_array(sod_signature);
    let msg_hash = sha512_and_check_data_to_sign(signed_attributes, signed_attributes_size);
    verify_ecdsa_pubkey_in_tbs(dsc_pubkey_x, dsc_pubkey_y, tbs_certificate);
    assert(
        verify_nist_p521(dsc_pubkey_x, dsc_pubkey_y, r, s, msg_hash),
        "ECDSA signature verification failed",
    );
    let comm_out = commit_to_id(
        comm_in,
        salt_in,
        salt_out,
        dg1,
        tbs_certificate,
        sod_signature,
        signed_attributes,
        signed_attributes_size as Field,
        e_content,
    );
    comm_out
}
