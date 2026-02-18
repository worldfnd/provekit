// PROVEKIT MODIFICATION: Removed CSC registry Merkle verification.
// CSC trust is verified off-chain. csc_pubkey_x and csc_pubkey_y are public inputs.
// Original: auto-generated from src/ts/scripts/circuit-builder.ts
use commitment::commit_to_dsc;
use sig_check_common::sha256_and_check_data_to_sign;
use sig_check_ecdsa::verify_brainpool_224r1;
use utils::{split_array, types::Alpha3CountryCode};

fn main(
    salt: Field,
    country: Alpha3CountryCode,
    csc_pubkey_x: pub [u8; 28],
    csc_pubkey_y: pub [u8; 28],
    dsc_signature: [u8; 56],
    tbs_certificate: [u8; 1200],
) -> pub Field {
    // Get the length of tbs_certificate by parsing the ASN.1
    // Safety: This is safe because the length must be correct for the hash and signature to be valid
    let tbs_certificate_len = unsafe { utils::unsafe_get_asn1_element_length(tbs_certificate) };
    let (r, s) = split_array(dsc_signature);
    let msg_hash = sha256_and_check_data_to_sign(tbs_certificate, tbs_certificate_len);
    assert(
        verify_brainpool_224r1(csc_pubkey_x, csc_pubkey_y, r, s, msg_hash),
        "ECDSA signature verification failed",
    );
        // PROVEKIT MODIFICATION: Simplified call - removed registry params (was 8 args, now 3)
        let comm_out = commit_to_dsc(
        country,
        tbs_certificate,
        salt,
    );
    comm_out
}
