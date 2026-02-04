// Verify CSCA signed DSC certificate (720-byte TBS)
use commitment::hash_salt_country_tbs;
use sig_check_rsa::verify_signature;
use utils::types::Alpha3CountryCode;

fn main(
    csc_pubkey: pub [u8; 512],
    salt: Field,
    country: Alpha3CountryCode,
    tbs_certificate: [u8; 720],
    csc_pubkey_redc_param: [u8; 513],
    dsc_signature: [u8; 512],
    exponent: u32,
    tbs_certificate_len: u32,
) -> pub Field {
    // Validate tbs_certificate_len bounds
    assert(
        tbs_certificate_len <= 720,
        "tbs_certificate_len must not exceed 720"
    );

    assert(
        verify_signature::<512, 0, 720, 32>(
            csc_pubkey,
            dsc_signature,
            csc_pubkey_redc_param,
            exponent,
            tbs_certificate,
            tbs_certificate_len,
            0,
        ),
        "RSA signature verification failed",
    );
    let comm_out = hash_salt_country_tbs(
        salt,
        country,
        tbs_certificate,
    );
    comm_out
}
