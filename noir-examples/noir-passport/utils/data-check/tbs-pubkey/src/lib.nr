pub fn verify_rsa_pubkey_in_tbs<let DSC_KEY_SIZE: u32, let TBS_CERT_SIZE: u32>(
    dsc_pubkey: [u8; DSC_KEY_SIZE],
    tbs_certificate: [u8; TBS_CERT_SIZE],
    pubkey_offset: u32,
    tbs_certificate_len: u32,
) {
    // Ensure the pubkey lies entirely within the signed (authenticated) region of the TBS,
    assert(
        pubkey_offset + DSC_KEY_SIZE <= tbs_certificate_len,
        "pubkey_offset + DSC_KEY_SIZE exceeds signed TBS length",
    );

    // Validate SubjectPublicKeyInfo structural context from TBS bytes.
    // The modulus must be the first element of an RSAPublicKey SEQUENCE:
    //
    //   RSAPublicKey ::= SEQUENCE { modulus INTEGER, exponent INTEGER }
    //
    // DER encoding (determined from TBS bytes, not from dsc_pubkey):
    //
    //   Leading zero:     30 82 XX XX   02 82 01 01 00   [modulus]
    //                     ^SEQUENCE     ^INTEGER          ^pubkey_offset
    //                     offset-9      offset-5
    //
    //   No leading zero:  30 82 XX XX   02 82 01 00   [modulus]
    //                     ^SEQUENCE     ^INTEGER       ^pubkey_offset
    //                     offset-8      offset-4
    assert(pubkey_offset >= 9, "pubkey_offset too small for DER SPKI prefix");

    // Determine encoding form from TBS bytes 
    // Check leading-zero form: INTEGER header (02 82 HH LL 00) at offset-5
    let is_leading_zero: bool = (tbs_certificate[pubkey_offset - 5] == 0x02)
        & (tbs_certificate[pubkey_offset - 4] == 0x82)
        & (tbs_certificate[pubkey_offset - 3] as u32 == (DSC_KEY_SIZE + 1) / 256)
        & (tbs_certificate[pubkey_offset - 2] as u32 == (DSC_KEY_SIZE + 1) % 256)
        & (tbs_certificate[pubkey_offset - 1] == 0x00);

    // Check no-leading-zero form: INTEGER header (02 82 HH LL) at offset-4
    let is_no_leading_zero: bool = (tbs_certificate[pubkey_offset - 4] == 0x02)
        & (tbs_certificate[pubkey_offset - 3] == 0x82)
        & (tbs_certificate[pubkey_offset - 2] as u32 == DSC_KEY_SIZE / 256)
        & (tbs_certificate[pubkey_offset - 1] as u32 == DSC_KEY_SIZE % 256);

    assert(
        is_leading_zero | is_no_leading_zero,
        "Invalid DER INTEGER encoding for RSA modulus",
    );

    // Verify the INTEGER is the first child of an RSAPublicKey SEQUENCE (tag 0x30).
    // This ensures the modulus is inside SubjectPublicKeyInfo, not at an arbitrary
    // location (e.g. extensions) where the same byte pattern might coincidentally appear.
    if is_leading_zero {
        assert(
            tbs_certificate[pubkey_offset - 9] == 0x30,
            "Expected RSAPublicKey SEQUENCE tag",
        );
        assert(
            tbs_certificate[pubkey_offset - 8] == 0x82,
            "Expected RSAPublicKey SEQUENCE long-form length",
        );
    } else {
        assert(
            tbs_certificate[pubkey_offset - 8] == 0x30,
            "Expected RSAPublicKey SEQUENCE tag",
        );
        assert(
            tbs_certificate[pubkey_offset - 7] == 0x82,
            "Expected RSAPublicKey SEQUENCE long-form length",
        );
    }

    // Verify the pubkey bytes match the TBS certificate at the given offset.
    for i in 0..DSC_KEY_SIZE {
        assert(tbs_certificate[i + pubkey_offset] == dsc_pubkey[i]);
    }
}

/// Build a 300-byte TBS with a 256-byte pubkey embedded at `offset` with correct
/// DER SubjectPublicKeyInfo structure: SEQUENCE { INTEGER(modulus), ... }
fn build_test_tbs(pubkey: [u8; 256], offset: u32) -> [u8; 300] {
    let mut tbs: [u8; 300] = [0; 300];
    let has_leading_zero = pubkey[0] as u32 >= 0x80;
    if has_leading_zero {
        // RSAPublicKey SEQUENCE at offset-9: 30 82 XX XX
        tbs[offset - 9] = 0x30;
        tbs[offset - 8] = 0x82;
        tbs[offset - 7] = 0x01; // SEQUENCE length high byte (placeholder)
        tbs[offset - 6] = 0x0A; // SEQUENCE length low byte (placeholder)
        // INTEGER at offset-5: 02 82 01 01 00 [256 bytes]
        tbs[offset - 5] = 0x02;
        tbs[offset - 4] = 0x82;
        tbs[offset - 3] = 0x01; // (256+1)/256 = 1
        tbs[offset - 2] = 0x01; // (256+1)%256 = 1
        tbs[offset - 1] = 0x00; // leading zero
    } else {
        // RSAPublicKey SEQUENCE at offset-8: 30 82 XX XX
        tbs[offset - 8] = 0x30;
        tbs[offset - 7] = 0x82;
        tbs[offset - 6] = 0x01; // SEQUENCE length high byte (placeholder)
        tbs[offset - 5] = 0x09; // SEQUENCE length low byte (placeholder)
        // INTEGER at offset-4: 02 82 01 00 [256 bytes]
        tbs[offset - 4] = 0x02;
        tbs[offset - 3] = 0x82;
        tbs[offset - 2] = 0x01; // 256/256 = 1
        tbs[offset - 1] = 0x00; // 256%256 = 0
    }
    for i in 0..256 {
        tbs[offset + i] = pubkey[i];
    }
    tbs
}

/// Valid case: pubkey within signed region, correct SPKI structure (leading zero case).
#[test]
fn test_valid_pubkey_with_leading_zero() {
    let mut pubkey: [u8; 256] = [0xAA; 256];
    pubkey[0] = 0x90; // >= 0x80 -> leading zero
    let offset: u32 = 15;
    let tbs = build_test_tbs(pubkey, offset);
    let tbs_len: u32 = 271; // offset + 256
    verify_rsa_pubkey_in_tbs(pubkey, tbs, offset, tbs_len);
}

/// Valid case: pubkey within signed region, correct SPKI structure (no leading zero case).
#[test]
fn test_valid_pubkey_without_leading_zero() {
    let mut pubkey: [u8; 256] = [0x55; 256];
    pubkey[0] = 0x7F; // < 0x80 -> no leading zero
    let offset: u32 = 15;
    let tbs = build_test_tbs(pubkey, offset);
    let tbs_len: u32 = 271;
    verify_rsa_pubkey_in_tbs(pubkey, tbs, offset, tbs_len);
}

/// Pubkey offset extends beyond signed TBS length -> must fail.
#[test(should_fail_with = "pubkey_offset + DSC_KEY_SIZE exceeds signed TBS length")]
fn test_pubkey_offset_beyond_signed_length_fails() {
    let mut pubkey: [u8; 256] = [0xAA; 256];
    pubkey[0] = 0x90;
    let offset: u32 = 15;
    let tbs = build_test_tbs(pubkey, offset);
    let tbs_len: u32 = 200; // too small
    verify_rsa_pubkey_in_tbs(pubkey, tbs, offset, tbs_len);
}

/// Invalid DER INTEGER encoding before modulus -> must fail.
#[test(should_fail_with = "Invalid DER INTEGER encoding for RSA modulus")]
fn test_invalid_der_integer_encoding_fails() {
    let mut pubkey: [u8; 256] = [0xAA; 256];
    pubkey[0] = 0x90;
    let offset: u32 = 15;
    let mut tbs = build_test_tbs(pubkey, offset);
    // Corrupt the INTEGER tag to break both leading-zero and no-leading-zero forms
    tbs[offset - 5] = 0x04; // OCTET STRING instead of INTEGER
    tbs[offset - 4] = 0x04; // also corrupt offset-4 to break form_b
    let tbs_len: u32 = 271;
    verify_rsa_pubkey_in_tbs(pubkey, tbs, offset, tbs_len);
}

/// Missing RSAPublicKey SEQUENCE wrapper -> must fail.
#[test(should_fail_with = "Expected RSAPublicKey SEQUENCE tag")]
fn test_missing_sequence_wrapper_fails() {
    let mut pubkey: [u8; 256] = [0xAA; 256];
    pubkey[0] = 0x90;
    let offset: u32 = 15;
    let mut tbs = build_test_tbs(pubkey, offset);
    // Corrupt the SEQUENCE tag
    tbs[offset - 9] = 0x04; // not a SEQUENCE
    let tbs_len: u32 = 271;
    verify_rsa_pubkey_in_tbs(pubkey, tbs, offset, tbs_len);
}

/// Pubkey bytes at valid DER structure but bytes don't match dsc_pubkey -> must fail.
#[test(should_fail)]
fn test_pubkey_mismatch_fails() {
    let mut pubkey: [u8; 256] = [0xAA; 256];
    pubkey[0] = 0x90;
    let offset: u32 = 15;
    let tbs = build_test_tbs(pubkey, offset);
    // Provide a different pubkey for comparison
    let mut wrong_pubkey: [u8; 256] = [0xBB; 256];
    wrong_pubkey[0] = 0x90;
    let tbs_len: u32 = 271;
    verify_rsa_pubkey_in_tbs(wrong_pubkey, tbs, offset, tbs_len);
}
