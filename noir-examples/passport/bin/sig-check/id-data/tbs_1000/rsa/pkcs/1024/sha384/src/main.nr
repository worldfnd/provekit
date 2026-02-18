// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_rsa_pubkey_in_tbs;
use sig_check_rsa::verify_signature;
use utils::types::{DG1Data, EContentData, SignedAttrsData};

fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    dsc_pubkey: [u8; 128],
    dsc_pubkey_redc_param: [u8; 129],
    sod_signature: [u8; 128],
    tbs_certificate: [u8; 1000],
    signed_attributes: SignedAttrsData,
    exponent: u32,
    e_content: EContentData,
) -> pub Field {
    verify_rsa_pubkey_in_tbs(dsc_pubkey, tbs_certificate);
    // Get the length of signed_attributes by parsing the ASN.1
    // Safety: This is safe because the length must be correct for the hash and signature to be valid
    let signed_attributes_size =
        unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };
    assert(
        verify_signature::<128, 0, 220, 48>(
            dsc_pubkey,
            sod_signature,
            dsc_pubkey_redc_param,
            exponent,
            signed_attributes,
            signed_attributes_size,
            0,
        ),
        "RSA signature verification failed",
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
