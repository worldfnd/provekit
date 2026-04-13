use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_rsa_pubkey_in_tbs;
use sig_check_rsa::verify_signature;
use utils::get_asn1_element_length;
use utils::types::{DG1Data, EContentData, SignedAttrsData};

fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    dsc_pubkey: [u8; 256],
    dsc_pubkey_redc_param: [u8; 257],
    dsc_pubkey_offset_in_dsc_cert: u32,
    exponent: u32,
    exponent_offset_in_dsc_cert: u32,
    sod_signature: [u8; 256],
    tbs_certificate: [u8; 1300],
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
) -> pub Field {
    // Compute TBS certificate length from DER header
    assert(tbs_certificate[0] == 0x30, "TBS must start with SEQUENCE tag");
    let tbs_certificate_len = get_asn1_element_length(tbs_certificate);

    verify_rsa_pubkey_in_tbs(
        dsc_pubkey,
        tbs_certificate,
        dsc_pubkey_offset_in_dsc_cert,
        tbs_certificate_len,
        exponent,
        exponent_offset_in_dsc_cert,
    );

    // Compute signed_attributes_size from ASN.1 header
    let signed_attributes_size = get_asn1_element_length(signed_attributes);

    assert(
        verify_signature::<256, 0, 200, 32>(
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
