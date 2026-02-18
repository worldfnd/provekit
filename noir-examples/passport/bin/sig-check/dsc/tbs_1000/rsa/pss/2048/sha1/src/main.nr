// PROVEKIT MODIFICATION: Removed CSC registry Merkle verification.
// CSC trust is verified off-chain. csc_pubkey is a public input.
// Original: auto-generated from src/ts/scripts/circuit-builder.ts
use commitment::commit_to_dsc;
use sig_check_rsa::verify_signature;
use utils::types::Alpha3CountryCode;

fn main(
    salt: Field,
    country: Alpha3CountryCode,
    tbs_certificate: [u8; 1000],
    csc_pubkey: pub [u8; 256],
    csc_pubkey_redc_param: [u8; 257],
    dsc_signature: [u8; 256],
    exponent: u32,
    pss_salt_len: u32,
) -> pub Field {
    // Get the length of tbs_certificate by parsing the ASN.1
    // Safety: This is safe because the length must be correct for the hash and signature to be valid
    let tbs_certificate_len = unsafe { utils::unsafe_get_asn1_element_length(tbs_certificate) };
    assert(
        verify_signature::<256, 1, 1000, 20>(
            csc_pubkey,
            dsc_signature,
            csc_pubkey_redc_param,
            exponent,
            tbs_certificate,
            tbs_certificate_len,
            pss_salt_len,
        ),
        "RSA signature verification failed",
    );
        // PROVEKIT MODIFICATION: Simplified call - removed registry params (was 8 args, now 3)
        let comm_out = commit_to_dsc(
        country,
        tbs_certificate,
        salt,
    );
    comm_out
}
