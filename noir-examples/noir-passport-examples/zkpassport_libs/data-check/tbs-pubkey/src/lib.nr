pub fn verify_rsa_pubkey_in_tbs<let DSC_KEY_SIZE: u32, let TBS_CERT_SIZE: u32>(
    dsc_pubkey: [u8; DSC_KEY_SIZE],
    tbs_certificate: [u8; TBS_CERT_SIZE],
    pubkey_offset: u32,
) {
    // Check that the public key of the DSC is the same as the one in the TBS certificate.
    // And since the TBS certificate is the data signed by the private key of the CSCA certificate
    // we can make sure the DSC, which signed the data of the passport, has been signed by the
    // root certificate of the issuing State (i.e. CSCA certificate) by verifying the signature below
    for i in 0..DSC_KEY_SIZE {
        assert(tbs_certificate[i + pubkey_offset] == dsc_pubkey[i]);
    }
}

pub fn verify_ecdsa_pubkey_in_tbs<let DSC_KEY_SIZE: u32, let TBS_CERT_SIZE: u32>(
    dsc_pubkey_x: [u8; DSC_KEY_SIZE],
    dsc_pubkey_y: [u8; DSC_KEY_SIZE],
    tbs_certificate: [u8; TBS_CERT_SIZE],
    pubkey_offset: u32,
) {
    // Check that the public key of the DSC is the same as the one in the TBS certificate.
    // And since the TBS certificate is the data signed by the private key of the CSCA certificate
    // we can make sure the DSC, which signed the data of the passport, has been signed by the
    // root certificate of the issuing State (i.e. CSCA certificate) by verifying the signature below
    for i in 0..DSC_KEY_SIZE {
        assert(tbs_certificate[i + pubkey_offset] == dsc_pubkey_x[i]);
        assert(tbs_certificate[i + pubkey_offset + DSC_KEY_SIZE] == dsc_pubkey_y[i]);
    }
}

