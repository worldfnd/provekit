use common::assert_allowed_rsa_exponent;

/// Verifies that `dsc_pubkey` and `exponent` are present at the specified offsets
/// within the authenticated `tbs_certificate`.
///
/// `pubkey_offset`   -- byte index in `tbs_certificate` where the modulus bytes start.
/// `exponent_offset` -- byte index in `tbs_certificate` where the exponent value bytes
///                      start (i.e. the first byte of the DER INTEGER value field,
///                      including any DER sign byte for two's-complement encoding).
pub fn verify_rsa_pubkey_in_tbs<let DSC_KEY_SIZE: u32, let TBS_CERT_SIZE: u32>(
    dsc_pubkey: [u8; DSC_KEY_SIZE],
    tbs_certificate: [u8; TBS_CERT_SIZE],
    pubkey_offset: u32,
    tbs_certificate_len: u32,
    exponent: u32,
    exponent_offset: u32,
) {
    // Ensure the given bounds respect the absolute length of our buffer.
    assert(
        tbs_certificate_len <= TBS_CERT_SIZE,
        "tbs_certificate_len exceeds maximum TBS_CERT_SIZE",
    );

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

    assert(is_leading_zero | is_no_leading_zero, "Invalid DER INTEGER encoding for RSA modulus");

    // Verify the INTEGER is the first child of an RSAPublicKey SEQUENCE (tag 0x30).
    // This ensures the modulus is inside SubjectPublicKeyInfo, not at an arbitrary
    // location (e.g. extensions) where the same byte pattern might coincidentally appear.
    if is_leading_zero {
        assert(tbs_certificate[pubkey_offset - 9] == 0x30, "Expected RSAPublicKey SEQUENCE tag");
        assert(
            tbs_certificate[pubkey_offset - 8] == 0x82,
            "Expected RSAPublicKey SEQUENCE long-form length",
        );
    } else {
        assert(tbs_certificate[pubkey_offset - 8] == 0x30, "Expected RSAPublicKey SEQUENCE tag");
        assert(
            tbs_certificate[pubkey_offset - 7] == 0x82,
            "Expected RSAPublicKey SEQUENCE long-form length",
        );
    }

    // Verify the pubkey bytes match the TBS certificate at the given offset.
    for i in 0..DSC_KEY_SIZE {
        assert(tbs_certificate[i + pubkey_offset] == dsc_pubkey[i]);
    }

    // Validate exponent is in the allowed set.
    assert_allowed_rsa_exponent(exponent);

    let exponent_byte_count: u32 = if exponent < 0x100 { 1 } else { 3 };
    assert(
        exponent_offset + exponent_byte_count <= tbs_certificate_len,
        "Exponent bytes exceed signed TBS length",
    );

    // Verify exponent bytes match the authenticated TBS certificate at exponent_offset.
    //
    // All 8 allowed exponents are either 1 byte (exponent=3) or 3 bytes (all others).
    //
    // 3-byte exponents and their expected DER value bytes:
    //   38129  (0x94F1)   -> [0x00, 0x94, 0xF1]  (sign byte needed, MSB >= 128)
    //   56611  (0xDD23)   -> [0x00, 0xDD, 0x23]  (sign byte needed, MSB >= 128)
    //   65537  (0x010001) -> [0x01, 0x00, 0x01]
    //   107903 (0x01A57F) -> [0x01, 0xA5, 0x7F]
    //   109729 (0x01ACA1) -> [0x01, 0xAC, 0xA1]
    //   122125 (0x01DD0D) -> [0x01, 0xDD, 0x0D]
    //   130689 (0x01FE81) -> [0x01, 0xFE, 0x81]
    //
    assert(tbs_certificate[exponent_offset - 2] == 0x02); // INTEGER tag
    assert(tbs_certificate[exponent_offset - 1] == exponent_byte_count as u8); // INTEGER length byte
    // For the 3-byte case, u32 >> 16 naturally gives 0x00 for exponents needing a sign byte,
    // and the expected 3-byte sequence matches the DER value encoding directly.
    if exponent < 0x100 {
        assert(exponent_offset < TBS_CERT_SIZE, "Exponent offset out of bounds");
        // 1-byte exponent (only exponent=3 in the allowed list).
        // exponent_offset must point to the single value byte in TBS.
        assert(tbs_certificate[exponent_offset] == exponent as u8, "Exponent mismatch in TBS");
    } else {
        // 3-byte exponent. exponent_offset points to the first value byte (incl. sign byte).
        assert(exponent_offset + 3 <= TBS_CERT_SIZE, "Exponent bytes out of bounds");
        assert(
            tbs_certificate[exponent_offset] == ((exponent >> 16) & 0xFF) as u8,
            "Exponent byte 0 mismatch in TBS",
        );
        assert(
            tbs_certificate[exponent_offset + 1] == ((exponent >> 8) & 0xFF) as u8,
            "Exponent byte 1 mismatch in TBS",
        );
        assert(
            tbs_certificate[exponent_offset + 2] == (exponent & 0xFF) as u8,
            "Exponent byte 2 mismatch in TBS",
        );
    }
}

/// Build a 300-byte TBS with a 256-byte pubkey embedded at `offset` with correct
/// DER SubjectPublicKeyInfo structure: SEQUENCE { INTEGER(modulus), INTEGER(exponent) }
/// Exponent 65537 (0x010001) is written as DER INTEGER at offset+256:
///   02 03 01 00 01  (tag, length, value bytes)
/// exponent_offset = offset + 258 (first value byte).
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
    // Exponent INTEGER: 02 03 [01 00 01] immediately after modulus
    tbs[offset + 256] = 0x02; // INTEGER tag
    tbs[offset + 257] = 0x03; // length = 3
    tbs[offset + 258] = 0x01; // exponent value byte 0 (65537 = 0x010001)
    tbs[offset + 259] = 0x00; // exponent value byte 1
    tbs[offset + 260] = 0x01; // exponent value byte 2
    tbs
}

#[test]
fn test_verify_rsa_pubkey_in_tbs_with_allowed_exponent_65537() {
    let mut modulus: [u8; 256] = [0xAA; 256];
    modulus[0] = 0x90; // leading-zero DER INTEGER form
    let offset: u32 = 15;
    let tbs = build_test_tbs(modulus, offset);
    let tbs_len: u32 = offset + 261;
    verify_rsa_pubkey_in_tbs(modulus, tbs, offset, tbs_len, 65537, offset + 258);
}

#[test]
fn test_verify_rsa_pubkey_in_tbs_with_allowed_exponent_3() {
    let mut modulus: [u8; 256] = [0xAA; 256];
    modulus[0] = 0x90;
    let offset: u32 = 15;
    let mut tbs = build_test_tbs(modulus, offset);
    // Replace default exponent (65537) with exponent=3 encoded at the same value offset.
    tbs[offset + 257] = 0x01; // DER INTEGER length
    tbs[offset + 258] = 0x03;
    tbs[offset + 259] = 0x00; // clear leftover bytes
    tbs[offset + 260] = 0x00;
    let tbs_len: u32 = offset + 261;
    verify_rsa_pubkey_in_tbs(modulus, tbs, offset, tbs_len, 3, offset + 258);
}

#[test]
fn test_verify_rsa_pubkey_in_tbs_with_allowed_exponent_56611() {
    let mut modulus: [u8; 256] = [0xAA; 256];
    modulus[0] = 0x90;
    let offset: u32 = 15;
    let mut tbs = build_test_tbs(modulus, offset);
    // 56611 = 0xDD23 -> DER value bytes [0x00, 0xDD, 0x23] (sign byte required).
    tbs[offset + 258] = 0x00;
    tbs[offset + 259] = 0xDD;
    tbs[offset + 260] = 0x23;
    let tbs_len: u32 = offset + 261;
    verify_rsa_pubkey_in_tbs(modulus, tbs, offset, tbs_len, 56611, offset + 258);
}

#[test(should_fail_with = "Unsupported RSA exponent")]
fn test_verify_rsa_pubkey_in_tbs_rejects_exponent_1() {
    let mut modulus: [u8; 256] = [0xAA; 256];
    modulus[0] = 0x90;
    let offset: u32 = 15;
    let mut tbs = build_test_tbs(modulus, offset);
    tbs[offset + 258] = 0x01;
    let tbs_len: u32 = offset + 261;
    verify_rsa_pubkey_in_tbs(modulus, tbs, offset, tbs_len, 1, offset + 258);
}

#[test(should_fail_with = "Exponent mismatch in TBS")]
fn test_verify_rsa_pubkey_in_tbs_rejects_wrong_exponent_bytes() {
    let mut modulus: [u8; 256] = [0xAA; 256];
    modulus[0] = 0x90;
    let offset: u32 = 15;
    let mut tbs = build_test_tbs(modulus, offset);
    // TBS has exponent byte = 0x07, but we claim exponent = 3.
    tbs[offset + 257] = 0x01; // DER INTEGER length
    tbs[offset + 258] = 0x07;
    let tbs_len: u32 = offset + 261;
    verify_rsa_pubkey_in_tbs(modulus, tbs, offset, tbs_len, 3, offset + 258);
}

/// Valid case: pubkey within signed region, correct SPKI structure (leading zero case).
#[test]
fn test_valid_pubkey_with_leading_zero() {
    let mut pubkey: [u8; 256] = [0xAA; 256];
    pubkey[0] = 0x90; // >= 0x80 -> leading zero
    let offset: u32 = 15;
    let tbs = build_test_tbs(pubkey, offset);
    let tbs_len: u32 = offset + 261;
    verify_rsa_pubkey_in_tbs(pubkey, tbs, offset, tbs_len, 65537, offset + 258);
}

/// Valid case: pubkey within signed region, correct SPKI structure (no leading zero case).
#[test]
fn test_valid_pubkey_without_leading_zero() {
    let mut pubkey: [u8; 256] = [0x55; 256];
    pubkey[0] = 0x7F; // < 0x80 -> no leading zero
    let offset: u32 = 15;
    let tbs = build_test_tbs(pubkey, offset);
    let tbs_len: u32 = offset + 261;
    verify_rsa_pubkey_in_tbs(pubkey, tbs, offset, tbs_len, 65537, offset + 258);
}

/// Pubkey offset extends beyond signed TBS length -> must fail.
#[test(should_fail_with = "pubkey_offset + DSC_KEY_SIZE exceeds signed TBS length")]
fn test_pubkey_offset_beyond_signed_length_fails() {
    let mut pubkey: [u8; 256] = [0xAA; 256];
    pubkey[0] = 0x90;
    let offset: u32 = 15;
    let tbs = build_test_tbs(pubkey, offset);
    let tbs_len: u32 = 200; // too small
    verify_rsa_pubkey_in_tbs(pubkey, tbs, offset, tbs_len, 65537, offset + 258);
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
    let tbs_len: u32 = offset + 261;
    verify_rsa_pubkey_in_tbs(pubkey, tbs, offset, tbs_len, 65537, offset + 258);
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
    let tbs_len: u32 = offset + 261;
    verify_rsa_pubkey_in_tbs(pubkey, tbs, offset, tbs_len, 65537, offset + 258);
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
    let tbs_len: u32 = offset + 261;
    verify_rsa_pubkey_in_tbs(wrong_pubkey, tbs, offset, tbs_len, 65537, offset + 258);
}

#[test(should_fail_with = "Exponent bytes exceed signed TBS length")]
fn test_verify_rsa_pubkey_in_tbs_exponent_exceeds_signed_length() {
    let mut modulus: [u8; 256] = [0xAA; 256];
    modulus[0] = 0x90;
    let offset: u32 = 15;
    let tbs = build_test_tbs(modulus, offset);
    // TBS signed length barely covers modulus, but doesn't cover exponent
    let tbs_len: u32 = offset + 256;
    verify_rsa_pubkey_in_tbs(modulus, tbs, offset, tbs_len, 65537, offset + 258);
}

#[test]
fn test_valid_pubkey_without_leading_zero_exponent_3() {
    let mut pubkey: [u8; 256] = [0x55; 256];
    pubkey[0] = 0x7F; // < 0x80 -> no leading zero
    let offset: u32 = 15;
    let mut tbs = build_test_tbs(pubkey, offset);
    tbs[offset + 257] = 0x01; // DER INTEGER length
    tbs[offset + 258] = 0x03;
    tbs[offset + 259] = 0x00; // clear leftover bytes
    tbs[offset + 260] = 0x00;
    let tbs_len: u32 = offset + 261;
    verify_rsa_pubkey_in_tbs(pubkey, tbs, offset, tbs_len, 3, offset + 258);
}
