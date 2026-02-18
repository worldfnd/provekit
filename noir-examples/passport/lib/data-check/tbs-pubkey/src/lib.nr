pub mod tests;

/// Check that an RSA public key exists in a certificate TBS
pub fn verify_rsa_pubkey_in_tbs<let PUBKEY_SIZE: u32, let TBS_SIZE: u32>(
    pubkey: [u8; PUBKEY_SIZE],
    tbs: [u8; TBS_SIZE],
) {
    let pubkey_offset = utils::find_subarray_index(pubkey, tbs);
    for i in 0..PUBKEY_SIZE {
        assert(tbs[i + pubkey_offset] == pubkey[i], "Public key of DSC not found in TBS");
    }
}

/// Check that an ECDSA public key x and y coord exists in a certificate TBS
pub fn verify_ecdsa_pubkey_in_tbs<let PUBKEY_SIZE: u32, let TBS_SIZE: u32>(
    pubkey_x: [u8; PUBKEY_SIZE],
    pubkey_y: [u8; PUBKEY_SIZE],
    tbs: [u8; TBS_SIZE],
) {
    let pubkey_offset = utils::find_subarray_index(pubkey_x, tbs);
    for i in 0..PUBKEY_SIZE {
        // We only need to check that the y coord is found after the x coord, since
        // find_substring_index() already guarantees that the x coord exists in the TBS
        assert(
            tbs[i + pubkey_offset + PUBKEY_SIZE] == pubkey_y[i],
            "Public key y coord not found in TBS",
        );
    }
}
