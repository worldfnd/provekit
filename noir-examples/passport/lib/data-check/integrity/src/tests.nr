use super::{
    check_dg1_sha1, check_dg1_sha224, check_dg1_sha256, check_dg1_sha384, check_dg1_sha512,
    check_signed_attributes_sha1, check_signed_attributes_sha224, check_signed_attributes_sha256,
    check_signed_attributes_sha384, check_signed_attributes_sha512, DG2_HASH_DER_IDENTIFIER,
    get_dg1_size, get_dg2_hash_from_econtent,
};
use sha1::sha1::sha1_var;
use sha256::{sha224_var, sha256_var};
use sha512::{sha384::sha384_var, sha512::sha512_var};
use utils::constants::{
    ECONTENT_LENGTH, ID_CARD_DG1_LENGTH, ID_CARD_SAMPLE_DG1, PASSPORT_DG1_LENGTH, SAMPLE_DG1,
    SIGNED_ATTRS_LENGTH,
};

#[test]
fn test_get_dg1_size_passport() {
    let dg1_size = get_dg1_size(SAMPLE_DG1);
    assert_eq(dg1_size, PASSPORT_DG1_LENGTH);
}

#[test]
fn test_get_dg1_size_id_card() {
    let dg1_size = get_dg1_size(ID_CARD_SAMPLE_DG1);
    assert_eq(dg1_size, ID_CARD_DG1_LENGTH);
}

#[test]
fn test_get_dg2_hash_from_econtent() {
    // Create a sample dg2 full of 1s
    let dg2 = [1 as u8; 100];
    let mut e_content = [0; ECONTENT_LENGTH];

    // Hash dg2
    let dg2_hash = sha256_var(dg2, 100);

    // Add the 0x30 sequence preceding the DER sequence
    e_content[100 - DG2_HASH_DER_IDENTIFIER.len() - 3] = 0x30;
    // Add the size of the DER sequence just after the 0x30 sequence
    e_content[100 - DG2_HASH_DER_IDENTIFIER.len() - 2] = 5 + dg2_hash.len() as u8;
    // Add the expected DER sequence preceding the hash of DG2
    for i in 0..DG2_HASH_DER_IDENTIFIER.len() {
        e_content[i + 100 - DG2_HASH_DER_IDENTIFIER.len() - 1] = DG2_HASH_DER_IDENTIFIER[i];
    }
    // Add the size of the hash of DG2 just after the DER sequence
    e_content[100 - 1] = dg2_hash.len() as u8;
    // Finally add the hash of DG2 just after the size of the hash
    for i in 0..dg2_hash.len() {
        e_content[i + 100] = dg2_hash[i];
    }
    let e_content_size = 200;
    // Get the hash of DG2 from eContent
    let dg2_hash_from_econtent = get_dg2_hash_from_econtent(e_content, e_content_size);
    // Assert that the hash retrieved from eContent is the same as the hash of dg2
    assert_eq(dg2_hash, dg2_hash_from_econtent);
}

#[test]
fn test_check_dg1_sha1() {
    let dg1 = SAMPLE_DG1;
    let mut e_content = [0; ECONTENT_LENGTH];
    let dg1_hash = sha1_var(BoundedVec::from_parts(dg1, PASSPORT_DG1_LENGTH));
    for i in 0..dg1_hash.len() {
        e_content[i + 100] = dg1_hash[i];
    }
    let e_content_size = 200;
    check_dg1_sha1(dg1, e_content, e_content_size);
}

#[test(should_fail_with = "Hash of dg1 not found in eContent")]
fn test_check_dg1_sha1_fail() {
    let dg1 = SAMPLE_DG1;
    let mut e_content = [0; ECONTENT_LENGTH];
    let dg1_hash = sha1_var(BoundedVec::from_parts(dg1, PASSPORT_DG1_LENGTH));
    for i in 0..dg1_hash.len() {
        e_content[i + 100] = dg1_hash[i];
    }
    // Corrupt a few bytes of the hash
    e_content[101] = 0;
    e_content[102] = 0;
    e_content[103] = 0;
    let e_content_size = 200;
    check_dg1_sha1(dg1, e_content, e_content_size);
}

#[test]
fn test_check_dg1_sha224() {
    let dg1 = SAMPLE_DG1;
    let mut e_content = [0; ECONTENT_LENGTH];
    let dg1_hash = sha224_var(dg1, PASSPORT_DG1_LENGTH as u64);
    for i in 0..dg1_hash.len() {
        e_content[i + 100] = dg1_hash[i];
    }
    let e_content_size = 200;
    check_dg1_sha224(dg1, e_content, e_content_size);
}

#[test(should_fail_with = "Hash of dg1 not found in eContent")]
fn test_check_dg1_sha224_fail() {
    let dg1 = SAMPLE_DG1;
    let mut e_content = [0; ECONTENT_LENGTH];
    let dg1_hash = sha224_var(dg1, PASSPORT_DG1_LENGTH as u64);
    for i in 0..dg1_hash.len() {
        e_content[i + 100] = dg1_hash[i];
    }
    let e_content_size = 200;
    // Corrupt a few bytes of the hash
    e_content[101] = 0;
    e_content[102] = 0;
    e_content[103] = 0;
    check_dg1_sha224(dg1, e_content, e_content_size);
}

#[test]
fn test_check_dg1_sha256() {
    let dg1 = SAMPLE_DG1;
    let mut e_content = [0; ECONTENT_LENGTH];
    let dg1_hash = sha256_var(dg1, PASSPORT_DG1_LENGTH as u64);
    for i in 0..dg1_hash.len() {
        e_content[i + 100] = dg1_hash[i];
    }
    let e_content_size = 200;
    check_dg1_sha256(dg1, e_content, e_content_size);
}

#[test(should_fail_with = "Hash of dg1 not found in eContent")]
fn test_check_dg1_sha256_fail() {
    let dg1 = SAMPLE_DG1;
    let mut e_content = [0; ECONTENT_LENGTH];
    let dg1_hash = sha256_var(dg1, PASSPORT_DG1_LENGTH as u64);
    for i in 0..dg1_hash.len() {
        e_content[i + 100] = dg1_hash[i];
    }
    let e_content_size = 200;
    // Corrupt a few bytes of the hash
    e_content[101] = 0;
    e_content[102] = 0;
    e_content[103] = 0;
    check_dg1_sha256(dg1, e_content, e_content_size);
}

#[test]
fn test_check_dg1_sha384() {
    let dg1 = SAMPLE_DG1;
    let mut e_content = [0; ECONTENT_LENGTH];
    let dg1_hash = sha384_var(BoundedVec::from_parts(dg1, PASSPORT_DG1_LENGTH));
    for i in 0..dg1_hash.len() {
        e_content[i + 100] = dg1_hash[i];
    }
    let e_content_size = 200;
    check_dg1_sha384(dg1, e_content, e_content_size);
}

#[test(should_fail_with = "Hash of dg1 not found in eContent")]
fn test_check_dg1_sha384_fail() {
    let dg1 = SAMPLE_DG1;
    let mut e_content = [0; ECONTENT_LENGTH];
    let dg1_hash = sha384_var(BoundedVec::from_parts(dg1, PASSPORT_DG1_LENGTH));
    for i in 0..dg1_hash.len() {
        e_content[i + 100] = dg1_hash[i];
    }
    let e_content_size = 200;
    // Corrupt a few bytes of the hash
    e_content[101] = 0;
    e_content[102] = 0;
    e_content[103] = 0;
    check_dg1_sha384(dg1, e_content, e_content_size);
}

#[test]
fn test_check_dg1_sha512() {
    let dg1 = SAMPLE_DG1;
    let mut e_content = [0; ECONTENT_LENGTH];
    let dg1_hash = sha512_var(BoundedVec::from_parts(dg1, PASSPORT_DG1_LENGTH));
    for i in 0..dg1_hash.len() {
        e_content[i + 100] = dg1_hash[i];
    }
    let e_content_size = 200;
    check_dg1_sha512(dg1, e_content, e_content_size);
}

#[test(should_fail_with = "Hash of dg1 not found in eContent")]
fn test_check_dg1_sha512_fail() {
    let dg1 = SAMPLE_DG1;
    let mut e_content = [0; ECONTENT_LENGTH];
    let dg1_hash = sha512_var(BoundedVec::from_parts(dg1, PASSPORT_DG1_LENGTH));
    for i in 0..dg1_hash.len() {
        e_content[i + 100] = dg1_hash[i];
    }
    let e_content_size = 200;
    // Corrupt a few bytes of the hash
    e_content[101] = 0;
    e_content[102] = 0;
    e_content[103] = 0;
    check_dg1_sha512(dg1, e_content, e_content_size);
}

#[test]
fn test_check_signed_attributes_sha1() {
    let mut signed_attributes = [0; SIGNED_ATTRS_LENGTH];
    let e_content = [0; ECONTENT_LENGTH];
    let e_content_size = 200;
    let e_content_hash = sha1_var(BoundedVec::from_parts(e_content, e_content_size));
    for i in 0..e_content_hash.len() {
        signed_attributes[i] = e_content_hash[i];
    }
    check_signed_attributes_sha1(signed_attributes, e_content, e_content_size);
}

#[test(should_fail_with = "Computed final hash not found in signed attributes")]
fn test_check_signed_attributes_sha1_fail() {
    let mut signed_attributes = [0; SIGNED_ATTRS_LENGTH];
    let e_content = [0; ECONTENT_LENGTH];
    let e_content_size = 200;
    let e_content_hash = sha1_var(BoundedVec::from_parts(e_content, e_content_size));
    for i in 0..e_content_hash.len() {
        signed_attributes[i] = e_content_hash[i];
    }
    // Corrupt a few bytes of the hash
    signed_attributes[0] = 0;
    signed_attributes[1] = 0;
    signed_attributes[2] = 0;
    check_signed_attributes_sha1(signed_attributes, e_content, e_content_size);
}

#[test]
fn test_check_signed_attributes_sha224() {
    let mut signed_attributes = [0; SIGNED_ATTRS_LENGTH];
    let e_content = [0; ECONTENT_LENGTH];
    let e_content_size = 200;
    let e_content_hash = sha224_var(e_content, e_content_size as u64);
    for i in 0..e_content_hash.len() {
        signed_attributes[i] = e_content_hash[i];
    }
    check_signed_attributes_sha224(signed_attributes, e_content, e_content_size);
}

#[test(should_fail_with = "Computed final hash not found in signed attributes")]
fn test_check_signed_attributes_sha224_fail() {
    let mut signed_attributes = [0; SIGNED_ATTRS_LENGTH];
    let e_content = [0; ECONTENT_LENGTH];
    let e_content_size = 200;
    let e_content_hash = sha224_var(e_content, e_content_size as u64);
    for i in 0..e_content_hash.len() {
        signed_attributes[i] = e_content_hash[i];
    }
    // Corrupt a few bytes of the hash
    signed_attributes[0] = 0;
    signed_attributes[1] = 0;
    signed_attributes[2] = 0;
    check_signed_attributes_sha224(signed_attributes, e_content, e_content_size);
}

#[test]
fn test_check_signed_attributes_sha256() {
    let mut signed_attributes = [0; SIGNED_ATTRS_LENGTH];
    let e_content = [0; ECONTENT_LENGTH];
    let e_content_size = 200;
    let e_content_hash = sha256_var(e_content, e_content_size as u64);
    for i in 0..e_content_hash.len() {
        signed_attributes[i] = e_content_hash[i];
    }
    check_signed_attributes_sha256(signed_attributes, e_content, e_content_size);
}

#[test(should_fail_with = "Computed final hash not found in signed attributes")]
fn test_check_signed_attributes_sha256_fail() {
    let mut signed_attributes = [0; SIGNED_ATTRS_LENGTH];
    let e_content = [0; ECONTENT_LENGTH];
    let e_content_size = 200;
    let e_content_hash = sha256_var(e_content, e_content_size as u64);
    for i in 0..e_content_hash.len() {
        signed_attributes[i] = e_content_hash[i];
    }
    // Corrupt a few bytes of the hash
    signed_attributes[0] = 0;
    signed_attributes[1] = 0;
    signed_attributes[2] = 0;
    check_signed_attributes_sha256(signed_attributes, e_content, e_content_size);
}

#[test]
fn test_check_signed_attributes_sha384() {
    let mut signed_attributes = [0; SIGNED_ATTRS_LENGTH];
    let e_content = [0; ECONTENT_LENGTH];
    let e_content_size = 200;
    let e_content_hash = sha384_var(BoundedVec::from_parts(e_content, e_content_size));
    for i in 0..e_content_hash.len() {
        signed_attributes[i] = e_content_hash[i];
    }
    check_signed_attributes_sha384(signed_attributes, e_content, e_content_size);
}

#[test(should_fail_with = "Computed final hash not found in signed attributes")]
fn test_check_signed_attributes_sha384_fail() {
    let mut signed_attributes = [0; SIGNED_ATTRS_LENGTH];
    let e_content = [0; ECONTENT_LENGTH];
    let e_content_size = 200;
    let e_content_hash = sha384_var(BoundedVec::from_parts(e_content, e_content_size));
    for i in 0..e_content_hash.len() {
        signed_attributes[i] = e_content_hash[i];
    }
    // Corrupt a few bytes of the hash
    signed_attributes[0] = 0;
    signed_attributes[1] = 0;
    signed_attributes[2] = 0;
    check_signed_attributes_sha384(signed_attributes, e_content, e_content_size);
}

#[test]
fn test_check_signed_attributes_sha512() {
    let mut signed_attributes = [0; SIGNED_ATTRS_LENGTH];
    let e_content = [0; ECONTENT_LENGTH];
    let e_content_size = 200;
    let e_content_hash = sha512_var(BoundedVec::from_parts(e_content, e_content_size));
    for i in 0..e_content_hash.len() {
        signed_attributes[i] = e_content_hash[i];
    }
    check_signed_attributes_sha512(signed_attributes, e_content, e_content_size);
}

#[test(should_fail_with = "Computed final hash not found in signed attributes")]
fn test_check_signed_attributes_sha512_fail() {
    let mut signed_attributes = [0; SIGNED_ATTRS_LENGTH];
    let e_content = [0; ECONTENT_LENGTH];
    let e_content_size = 200;
    let e_content_hash = sha512_var(BoundedVec::from_parts(e_content, e_content_size));
    for i in 0..e_content_hash.len() {
        signed_attributes[i] = e_content_hash[i];
    }
    // Corrupt a few bytes of the hash
    signed_attributes[0] = 0;
    signed_attributes[1] = 0;
    signed_attributes[2] = 0;
    check_signed_attributes_sha512(signed_attributes, e_content, e_content_size);
}
