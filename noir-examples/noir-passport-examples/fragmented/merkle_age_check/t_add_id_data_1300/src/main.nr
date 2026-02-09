use commitment::commit_to_id;
use data_check_tbs_pubkey::{verify_rsa_pubkey_in_tbs};
use sig_check_rsa::verify_signature;
use utils::types::{DG1Data, EContentData, SignedAttrsData};

fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    dsc_pubkey: [u8; 256],
    dsc_pubkey_redc_param: [u8; 257],
    dsc_pubkey_offset_in_dsc_cert: u32,
    sod_signature: [u8; 256],
    tbs_certificate: [u8; 1300],
    signed_attributes: SignedAttrsData,
    signed_attributes_size: u64,
    exponent: u32,
    e_content: EContentData,
) -> pub Field {
    verify_rsa_pubkey_in_tbs(dsc_pubkey, tbs_certificate,dsc_pubkey_offset_in_dsc_cert);

    assert(
        verify_signature::<256, 0, 200, 32>(
            dsc_pubkey,
            sod_signature,
            dsc_pubkey_redc_param,
            exponent,
            signed_attributes,
            signed_attributes_size as u32,
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
