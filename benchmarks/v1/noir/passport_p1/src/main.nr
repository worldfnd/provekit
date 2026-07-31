// P1 is deliberately isolated from the historical Passport examples.  It
// mirrors the P1 Circom profile in benchmarks/v1/circom/passport_p1:
// * 93-byte Self DG1 and the Self fixed SOD buffers;
// * SHA-256 DG1/eContent/signed-attributes integrity;
// * PKCS#1 v1.5 SHA-256, e=65537, 4096-bit DSC verification;
// * the original circomlib Poseidon DSC registry leaf and binary path;
// * YYMMDD expiry and minimum-age checks.
//
// `poseidon::poseidon::bn254` is the original Poseidon implementation.  Do
// not replace it with the package's Poseidon2 API: Self's registry is built
// with circomlib Poseidon.
use poseidon::poseidon::bn254::{hash_2, hash_3, hash_4, hash_16};
use sha256::sha256_var;
use bignum::{params::BigNumParams, RuntimeBigNum};
use rsa::rsa::verify_sha256_pkcs1v15;
use utils::check_zero_padding;

global DG1_LEN: u32 = 93;
global RAW_DSC_LEN: u32 = 1792;
global ECONTENT_LEN: u32 = 512;
global SIGNED_ATTR_LEN: u32 = 256;
global DSC_KEY_LEN: u32 = 512;
global DSC_REDC_LEN: u32 = 513;
global TREE_DEPTH: u32 = 21;
global PACK_BYTES: u32 = 31;
global DSC_PUBKEY_PREFIX_LEN: u32 = 33;

fn assert_decimal_digits<let N: u32>(digits: [u8; N]) {
    for i in 0..N {
        assert(digits[i] <= 9, "P1 public date must contain decimal digits");
    }
}

fn date_less(
    first: [u8; 6],
    second: [u8; 6],
) -> bool {
    // This is the same lexicographic YY/MM/DD predicate as Self's
    // `DateIsLess`, after its ASCII-to-digit conversion.
    let first_year = first[0] * 10 + first[1];
    let second_year = second[0] * 10 + second[1];
    let first_month = first[2] * 10 + first[3];
    let second_month = second[2] * 10 + second[3];
    let first_day = first[4] * 10 + first[5];
    let second_day = second[4] * 10 + second[5];
    (first_year < second_year)
        | ((first_year == second_year) & (first_month < second_month))
        | ((first_year == second_year) & (first_month == second_month) & (first_day < second_day))
}

fn ascii_yymmdd(input: [u8; 6]) -> [u8; 6] {
    let mut result = [0; 6];
    for i in 0..6 {
        assert(input[i] >= 48, "DG1 YYMMDD digit is below ASCII 0");
        assert(input[i] <= 57, "DG1 YYMMDD digit is above ASCII 9");
        result[i] = input[i] - 48;
    }
    result
}

fn assert_valid_and_old_enough(dg1: [u8; DG1_LEN], current_date: [u8; 6], minimum_age_ascii: [u8; 2]) {
    assert_decimal_digits(current_date);
    assert(minimum_age_ascii[0] >= 48 & minimum_age_ascii[0] <= 57, "minimum age tens must be ASCII decimal");
    assert(minimum_age_ascii[1] >= 48 & minimum_age_ascii[1] <= 57, "minimum age units must be ASCII decimal");

    let mut dob_ascii = [0; 6];
    let mut expiry_ascii = [0; 6];
    for i in 0..6 {
        dob_ascii[i] = dg1[62 + i];
        expiry_ascii[i] = dg1[70 + i];
    }
    let dob = ascii_yymmdd(dob_ascii);
    let expiry = ascii_yymmdd(expiry_ascii);

    // Self uses a strict comparison: a passport dated today is not valid.
    assert(date_less(current_date, expiry), "passport is expired at the public date");

    let age = (minimum_age_ascii[0] - 48) * 10 + (minimum_age_ascii[1] - 48);
    let current_year = current_date[0] * 10 + current_date[1];
    let normalized_current_year = if current_year < dob[0] * 10 + dob[1] {
        current_year + 100
    } else {
        current_year
    };
    let qualifying_birth = [
        dob[0] * 10 + dob[1] + age,
        dob[2],
        dob[3],
        dob[4],
        dob[5],
        0,
    ];
    let qualifying_current = [
        normalized_current_year,
        current_date[2],
        current_date[3],
        current_date[4],
        current_date[5],
        0,
    ];
    // Convert the two three-part dates back to six digits to keep the source
    // visibly equivalent to Self's `DateIsLess` call.
    let birth_plus_age = [
        qualifying_birth[0] / 10,
        qualifying_birth[0] % 10,
        qualifying_birth[1],
        qualifying_birth[2],
        qualifying_birth[3],
        qualifying_birth[4],
    ];
    let today = [
        qualifying_current[0] / 10,
        qualifying_current[0] % 10,
        qualifying_current[1],
        qualifying_current[2],
        qualifying_current[3],
        qualifying_current[4],
    ];
    assert(date_less(birth_plus_age, today), "holder is not older than the public minimum age");
}

fn pack_bytes_le<let N: u32, let CHUNKS: u32>(bytes: [u8; N]) -> [Field; CHUNKS] {
    let mut packed = [0; CHUNKS];
    for i in 0..CHUNKS {
        let mut value: Field = 0;
        let mut multiplier: Field = 1;
        for j in 0..PACK_BYTES {
            let index = i * PACK_BYTES + j;
            if index < N {
                value += (bytes[index] as Field) * multiplier;
            }
            multiplier *= 256;
        }
        packed[i] = value;
    }
    packed
}

fn self_custom_hash_3(bytes: [u8; DG1_LEN]) -> Field {
    // DG1_LEN / 31 = 3, so Self's CustomHasher takes the direct Poseidon(3)
    // branch after little-endian byte packing.
    hash_3(pack_bytes_le::<DG1_LEN, 3>(bytes))
}

fn self_custom_hash_58(bytes: [u8; RAW_DSC_LEN]) -> Field {
    // 1792 bytes produce 58 field chunks.  Self hashes four 16-wide chunks,
    // zero-pads the final ten inputs, then hashes those four outputs.
    let packed = pack_bytes_le::<RAW_DSC_LEN, 58>(bytes);
    let h0 = hash_16([
        packed[0], packed[1], packed[2], packed[3], packed[4], packed[5], packed[6], packed[7],
        packed[8], packed[9], packed[10], packed[11], packed[12], packed[13], packed[14], packed[15],
    ]);
    let h1 = hash_16([
        packed[16], packed[17], packed[18], packed[19], packed[20], packed[21], packed[22], packed[23],
        packed[24], packed[25], packed[26], packed[27], packed[28], packed[29], packed[30], packed[31],
    ]);
    let h2 = hash_16([
        packed[32], packed[33], packed[34], packed[35], packed[36], packed[37], packed[38], packed[39],
        packed[40], packed[41], packed[42], packed[43], packed[44], packed[45], packed[46], packed[47],
    ]);
    let h3 = hash_16([
        packed[48], packed[49], packed[50], packed[51], packed[52], packed[53], packed[54], packed[55],
        packed[56], packed[57], 0, 0, 0, 0, 0, 0,
    ]);
    hash_4([h0, h1, h2, h3])
}

fn self_registry_root(
    raw_dsc: [u8; RAW_DSC_LEN],
    raw_dsc_actual_length: u32,
    csca_tree_leaf: Field,
    leaf_depth: u32,
    path: [u1; TREE_DEPTH],
    siblings: [Field; TREE_DEPTH],
) -> Field {
    assert(raw_dsc_actual_length <= RAW_DSC_LEN, "raw DSC length is out of range");
    assert(leaf_depth <= TREE_DEPTH, "Self registry depth is out of range");
    let dsc_hash = self_custom_hash_58(raw_dsc);
    let mut current = hash_2([hash_2([dsc_hash, raw_dsc_actual_length as Field]), csca_tree_leaf]);
    for i in 0..TREE_DEPTH {
        let next = if path[i] == 0 {
            hash_2([current, siblings[i]])
        } else {
            hash_2([siblings[i], current])
        };
        if i < leaf_depth {
            current = next;
        }
    }
    current
}

fn sha256_padded_block<let N: u32>(bytes: [u8; N], start: u32) -> [u32; 16] {
    let mut block = [0; 16];
    for i in 0..16 {
        let mut word: u32 = 0;
        for j in 0..4 {
            word = (word << 8) + bytes[start + i * 4 + j] as u32;
        }
        block[i] = word;
    }
    block
}

fn sha256_padded<let N: u32>(bytes: [u8; N], padded_length: u32) -> [u8; 32] {
    // Self supplies SHA-pre-padded messages.  Hashing them with sha256_var
    // would add a second padding block and change the signed digest.
    assert(padded_length <= N, "SHA padded length is out of range");
    assert(padded_length % 64 == 0, "SHA padded length is not block aligned");
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    for i in 0..(N / 64) {
        if i * 64 < padded_length {
            state = std::hash::sha256_compression(sha256_padded_block(bytes, i * 64), state);
        }
    }
    let mut digest = [0; 32];
    for i in 0..8 {
        digest[i * 4] = ((state[i] >> 24) & 0xff) as u8;
        digest[i * 4 + 1] = ((state[i] >> 16) & 0xff) as u8;
        digest[i * 4 + 2] = ((state[i] >> 8) & 0xff) as u8;
        digest[i * 4 + 3] = (state[i] & 0xff) as u8;
    }
    digest
}

fn assert_self_rsa_4096_pubkey_prefix(raw_dsc: [u8; RAW_DSC_LEN], dsc_pubkey_offset: u32) {
    // CheckPubkeyPosition takes the 33 bytes immediately before the modulus.
    // P1 fixes the modulus to 4096 bits, so only Self's RSA prefix entries
    // 4, 5, and 6 may match (the last is its Estonia compatibility form).
    assert(dsc_pubkey_offset >= DSC_PUBKEY_PREFIX_LEN, "DSC key offset is before its DER prefix");
    let prefix_65537 = [
        0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02,
        0x0f, 0x00, 0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00,
    ];
    let prefix_e3 = [
        0x30, 0x82, 0x02, 0x20, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02,
        0x0d, 0x00, 0x30, 0x82, 0x02, 0x08, 0x02, 0x82, 0x02, 0x01, 0x00,
    ];
    let prefix_estonia = [
        0x69, 0x61, 0x30, 0x82, 0x02, 0x20, 0x30, 0x0b, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x03, 0x82, 0x02,
        0x0f, 0x00, 0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00,
    ];
    let mut matches_65537 = true;
    let mut matches_e3 = true;
    let mut matches_estonia = true;
    for i in 0..DSC_PUBKEY_PREFIX_LEN {
        let actual = raw_dsc[dsc_pubkey_offset - DSC_PUBKEY_PREFIX_LEN + i];
        matches_65537 = matches_65537 & (actual == prefix_65537[i]);
        matches_e3 = matches_e3 & (actual == prefix_e3[i]);
        matches_estonia = matches_estonia & (actual == prefix_estonia[i]);
    }
    assert(
        matches_65537 | matches_e3 | matches_estonia,
        "DSC key does not have a Self-compatible RSA-4096 DER prefix",
    );
}

fn verify_self_rsa_4096(
    pubkey_bytes: [u8; DSC_KEY_LEN],
    signature: [u8; DSC_KEY_LEN],
    redc_param_bytes: [u8; DSC_REDC_LEN],
    digest: [u8; 32],
) -> bool {
    let modulus = utils::pack_be_bytes_into_u128s::<DSC_KEY_LEN, 35, 15>(pubkey_bytes);
    let redc_param = utils::pack_be_bytes_into_u128s::<DSC_REDC_LEN, 35, 15>(redc_param_bytes);
    let params: BigNumParams<35, 4096> = BigNumParams::new(false, modulus, redc_param);
    let signature_number: RuntimeBigNum<35, 4096> = RuntimeBigNum::from_be_bytes(params, signature);
    verify_sha256_pkcs1v15::<35, 4096>(digest, signature_number, 65537)
}

fn check_integrity(
    dg1: [u8; DG1_LEN],
    dg1_hash_offset: u32,
    econtent: [u8; ECONTENT_LEN],
    econtent_padded_length: u32,
    signed_attr: [u8; SIGNED_ATTR_LEN],
    signed_attr_padded_length: u32,
    signed_attr_econtent_hash_offset: u32,
) {
    assert(econtent_padded_length <= ECONTENT_LEN, "eContent length is out of range");
    assert(signed_attr_padded_length <= SIGNED_ATTR_LEN, "signed-attributes length is out of range");
    assert(dg1_hash_offset + 32 <= econtent_padded_length, "DG1 digest offset is out of range");
    assert(signed_attr_econtent_hash_offset + 32 <= signed_attr_padded_length, "eContent digest offset is out of range");
    check_zero_padding(econtent, econtent_padded_length);
    check_zero_padding(signed_attr, signed_attr_padded_length);
    let dg1_digest = sha256_var(dg1, DG1_LEN);
    let econtent_digest = sha256_padded(econtent, econtent_padded_length);
    for i in 0..32 {
        assert(dg1_digest[i] == econtent[dg1_hash_offset + i], "DG1 SHA-256 is not bound into eContent");
        assert(econtent_digest[i] == signed_attr[signed_attr_econtent_hash_offset + i], "eContent SHA-256 is not bound into signed attributes");
    }
}

fn main(
    raw_dsc: [u8; RAW_DSC_LEN],
    raw_dsc_actual_length: u32,
    dsc_pubkey_offset: u32,
    dsc_pubkey_actual_size: u32,
    dg1: [u8; DG1_LEN],
    dg1_hash_offset: u32,
    econtent: [u8; ECONTENT_LEN],
    econtent_padded_length: u32,
    signed_attr: [u8; SIGNED_ATTR_LEN],
    signed_attr_padded_length: u32,
    signed_attr_econtent_hash_offset: u32,
    signature_passport: [u8; DSC_KEY_LEN],
    dsc_barrett_mu: [u8; DSC_REDC_LEN],
    merkle_root: pub Field,
    leaf_depth: u32,
    path: [u1; TREE_DEPTH],
    siblings: [Field; TREE_DEPTH],
    csca_tree_leaf: Field,
    current_date: pub [u8; 6],
    minimum_age: pub [u8; 2],
) -> pub Field {
    assert(dsc_pubkey_actual_size == DSC_KEY_LEN, "P1 requires a 4096-bit DSC modulus");
    assert_self_rsa_4096_pubkey_prefix(raw_dsc, dsc_pubkey_offset);
    assert(dsc_pubkey_offset + DSC_KEY_LEN <= raw_dsc_actual_length, "DSC key lies outside the raw DSC");
    let mut dsc_pubkey = [0; DSC_KEY_LEN];
    for i in 0..DSC_KEY_LEN {
        dsc_pubkey[i] = raw_dsc[dsc_pubkey_offset + i];
    }

    check_integrity(
        dg1,
        dg1_hash_offset,
        econtent,
        econtent_padded_length,
        signed_attr,
        signed_attr_padded_length,
        signed_attr_econtent_hash_offset,
    );
    assert(
        verify_self_rsa_4096(
            dsc_pubkey,
            signature_passport,
            dsc_barrett_mu,
            sha256_padded(signed_attr, signed_attr_padded_length),
        ),
        "DSC RSA-4096 PKCS#1 v1.5 signature is invalid",
    );
    assert(
        self_registry_root(raw_dsc, raw_dsc_actual_length, csca_tree_leaf, leaf_depth, path, siblings)
            == merkle_root,
        "Self DSC registry path does not reach the public root",
    );
    assert_valid_and_old_enough(dg1, current_date, minimum_age);
    self_custom_hash_3(dg1)
}
