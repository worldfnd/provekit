use common::assert_allowed_rsa_exponent;

/// Verifies that `dsc_pubkey` and `exponent` are present at the specified offsets
/// within the authenticated `tbs_certificate`. Note: No DER parsing is performed.
/// The prover supplies the offsets directly for both modulus and exponent.
///
/// `pubkey_offset`   -- byte index in `tbs_certificate` where the modulus bytes start.
/// `exponent_offset` -- byte index in `tbs_certificate` where the exponent value bytes
///                      start (i.e. the first byte of the DER INTEGER value field,
///                      including any DER sign byte for two's-complement encoding).
// TODO: Enforce strict DER INTEGER encoding for RSA modulus and exponent.
pub fn verify_rsa_pubkey_in_tbs<let DSC_KEY_SIZE: u32, let TBS_CERT_SIZE: u32>(
    dsc_pubkey: [u8; DSC_KEY_SIZE],
    tbs_certificate: [u8; TBS_CERT_SIZE],
    pubkey_offset: u32,
    exponent: u32,
    exponent_offset: u32,
) {
    assert(
        pubkey_offset + DSC_KEY_SIZE <= TBS_CERT_SIZE,
        "pubkey_offset + DSC_KEY_SIZE exceeds TBS certificate size",
    );

    // Verify modulus bytes match what is in the authenticated TBS certificate.
    for i in 0..DSC_KEY_SIZE {
        assert(tbs_certificate[i + pubkey_offset] == dsc_pubkey[i]);
    }

    // Validate exponent is in the allowed set.
    assert_allowed_rsa_exponent(exponent);

    // Verify exponent bytes match the authenticated TBS certificate at exponent_offset.
    //
    // All 8 allowed exponents are either 1 byte (exponent=3) or 3 bytes (all others).
    //
    // 3-byte exponents and their expected DER value bytes:
    //   38129  (0x94B1)   -> [0x00, 0x94, 0xB1]  (sign byte needed, MSB >= 128)
    //   56611  (0xDD23)   -> [0x00, 0xDD, 0x23]  (sign byte needed, MSB >= 128)
    //   65537  (0x010001) -> [0x01, 0x00, 0x01]
    //   107903 (0x01A57F) -> [0x01, 0xA5, 0x7F]
    //   109729 (0x01AC61) -> [0x01, 0xAC, 0x61]
    //   122125 (0x01DC0D) -> [0x01, 0xDC, 0x0D]
    //   130689 (0x01FF01) -> [0x01, 0xFF, 0x01]
    //
    // For the 3-byte case, u32 >> 16 naturally gives 0x00 for exponents needing a sign byte,
    // and the expected 3-byte sequence matches the DER value encoding directly.
    if exponent < 0x100 {
        // 1-byte exponent (only exponent=3 in the allowed list).
        // exponent_offset must point to the single value byte in TBS.
        assert(
            tbs_certificate[exponent_offset] == exponent as u8,
            "Exponent mismatch in TBS",
        );
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

#[test]
fn test_verify_rsa_pubkey_in_tbs_with_allowed_exponent_65537() {
    let modulus: [u8; 4] = [0x90, 0x11, 0x22, 0x33];
    let mut tbs: [u8; 32] = [0; 32];

    // Modulus at offset 0 (no DER header needed, offset is provided directly)
    for i in 0..4 {
        tbs[i] = modulus[i];
    }
    // Exponent 65537 = [0x01, 0x00, 0x01] at offset 4
    tbs[4] = 0x01;
    tbs[5] = 0x00;
    tbs[6] = 0x01;

    verify_rsa_pubkey_in_tbs(modulus, tbs, 0, 65537, 4);
}

#[test]
fn test_verify_rsa_pubkey_in_tbs_with_allowed_exponent_3() {
    let modulus: [u8; 4] = [0x10, 0x11, 0x22, 0x33];
    let mut tbs: [u8; 32] = [0; 32];

    for i in 0..4 {
        tbs[i] = modulus[i];
    }
    // Exponent 3 = [0x03] at offset 4 (1 byte)
    tbs[4] = 0x03;

    verify_rsa_pubkey_in_tbs(modulus, tbs, 0, 3, 4);
}

#[test]
fn test_verify_rsa_pubkey_in_tbs_with_allowed_exponent_56611() {
    let modulus: [u8; 4] = [0x90, 0x11, 0x22, 0x33];
    let mut tbs: [u8; 32] = [0; 32];

    for i in 0..4 {
        tbs[i] = modulus[i];
    }
    // 56611 = 0xDD23, MSB >= 128, DER sign byte needed -> [0x00, 0xDD, 0x23]
    tbs[4] = 0x00;
    tbs[5] = 0xDD;
    tbs[6] = 0x23;

    verify_rsa_pubkey_in_tbs(modulus, tbs, 0, 56611, 4);
}

#[test(should_fail_with = "Unsupported RSA exponent")]
fn test_verify_rsa_pubkey_in_tbs_rejects_exponent_1() {
    let modulus: [u8; 4] = [0x90, 0x11, 0x22, 0x33];
    let mut tbs: [u8; 32] = [0; 32];

    for i in 0..4 {
        tbs[i] = modulus[i];
    }
    tbs[4] = 0x01;

    verify_rsa_pubkey_in_tbs(modulus, tbs, 0, 1, 4);
}

#[test(should_fail_with = "Exponent mismatch in TBS")]
fn test_verify_rsa_pubkey_in_tbs_rejects_wrong_exponent_bytes() {
    let modulus: [u8; 4] = [0x90, 0x11, 0x22, 0x33];
    let mut tbs: [u8; 32] = [0; 32];

    for i in 0..4 {
        tbs[i] = modulus[i];
    }
    // TBS has exponent byte = 0x07, but we claim exponent = 3
    tbs[4] = 0x07;

    verify_rsa_pubkey_in_tbs(modulus, tbs, 0, 3, 4);
}
