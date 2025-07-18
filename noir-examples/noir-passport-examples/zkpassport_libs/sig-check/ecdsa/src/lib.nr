use bigcurve::curves::brainpoolP256r1::{
    BrainpoolP256r1_Params, BrainpoolP256r1Fq, BrainpoolP256r1Fr,
};
use bigcurve::curves::brainpoolP256t1::{
    BrainpoolP256t1_Params, BrainpoolP256t1Fq, BrainpoolP256t1Fr,
};
use bigcurve::curves::brainpoolP384r1::{
    BrainpoolP384r1_Params, BrainpoolP384r1Fq, BrainpoolP384r1Fr,
};
use bigcurve::curves::brainpoolP384t1::{
    BrainpoolP384t1_Params, BrainpoolP384t1Fq, BrainpoolP384t1Fr,
};
use bigcurve::curves::brainpoolP512r1::{
    BrainpoolP512r1_Params, BrainpoolP512r1Fq, BrainpoolP512r1Fr,
};
use bigcurve::curves::brainpoolP512t1::{
    BrainpoolP512t1_Params, BrainpoolP512t1Fq, BrainpoolP512t1Fr,
};
use bigcurve::curves::secp256r1::{Secp256r1_Params, Secp256r1Fq, Secp256r1Fr};
use bigcurve::curves::secp384r1::{Secp384r1_Params, Secp384r1Fq, Secp384r1Fr};
use bigcurve::curves::secp521r1::{Secp521r1_Params, Secp521r1Fq, Secp521r1Fr};
use bignum::bignum::BigNum;
use bignum::bignum::BigNumTrait;
use ecdsa::ecdsa::{
    verify_brainpoolp256r1_ecdsa, verify_brainpoolp256t1_ecdsa, verify_brainpoolp384r1_ecdsa,
    verify_brainpoolp384t1_ecdsa, verify_brainpoolp512r1_ecdsa, verify_brainpoolp512t1_ecdsa,
    verify_secp256r1_ecdsa, verify_secp384r1_ecdsa, verify_secp521r1_ecdsa,
};
use std::ecdsa_secp256r1;
use utils::{
    check_zero_padding, concat_array, ECDSA_CURVE_BRAINPOOL_B256R1, ECDSA_CURVE_BRAINPOOL_B256T1,
    ECDSA_CURVE_BRAINPOOL_B384R1, ECDSA_CURVE_BRAINPOOL_B384T1, ECDSA_CURVE_BRAINPOOL_B512R1,
    ECDSA_CURVE_BRAINPOOL_B512T1, ECDSA_CURVE_P384, ECDSA_CURVE_P521,
};

pub fn verify_nist_p256_blackbox<let DATA_TO_SIGN_LEN: u32, let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let signature = concat_array(signature_r, signature_s);
    ecdsa_secp256r1::verify_signature(pubkey_x, pubkey_y, signature, msg_hash)
}

pub fn verify_nist_p256<let DATA_TO_SIGN_LEN: u32, let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: Secp256r1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: Secp256r1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: Secp256r1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: Secp256r1Fr = BigNum::from_be_bytes(signature_s);
    verify_secp256r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_nist_p384<let DATA_TO_SIGN_LEN: u32, let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 48],
    pubkey_y: [u8; 48],
    signature_r: [u8; 48],
    signature_s: [u8; 48],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: Secp384r1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: Secp384r1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: Secp384r1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: Secp384r1Fr = BigNum::from_be_bytes(signature_s);
    verify_secp384r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_nist_p521<let DATA_TO_SIGN_LEN: u32, let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 66],
    pubkey_y: [u8; 66],
    signature_r: [u8; 66],
    signature_s: [u8; 66],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: Secp521r1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: Secp521r1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: Secp521r1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: Secp521r1Fr = BigNum::from_be_bytes(signature_s);
    verify_secp521r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_256r1<let DATA_TO_SIGN_LEN: u32, let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: BrainpoolP256r1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP256r1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP256r1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP256r1Fr = BigNum::from_be_bytes(signature_s);
    verify_brainpoolp256r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_256t1<let DATA_TO_SIGN_LEN: u32, let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: BrainpoolP256t1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP256t1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP256t1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP256t1Fr = BigNum::from_be_bytes(signature_s);
    verify_brainpoolp256t1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_384r1<let DATA_TO_SIGN_LEN: u32, let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 48],
    pubkey_y: [u8; 48],
    signature_r: [u8; 48],
    signature_s: [u8; 48],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: BrainpoolP384r1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP384r1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP384r1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP384r1Fr = BigNum::from_be_bytes(signature_s);
    verify_brainpoolp384r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_384t1<let DATA_TO_SIGN_LEN: u32, let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 48],
    pubkey_y: [u8; 48],
    signature_r: [u8; 48],
    signature_s: [u8; 48],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: BrainpoolP384t1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP384t1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP384t1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP384t1Fr = BigNum::from_be_bytes(signature_s);
    verify_brainpoolp384t1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_512r1<let DATA_TO_SIGN_LEN: u32, let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 64],
    pubkey_y: [u8; 64],
    signature_r: [u8; 64],
    signature_s: [u8; 64],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: BrainpoolP512r1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP512r1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP512r1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP512r1Fr = BigNum::from_be_bytes(signature_s);
    verify_brainpoolp512r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_512t1<let DATA_TO_SIGN_LEN: u32, let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 64],
    pubkey_y: [u8; 64],
    signature_r: [u8; 64],
    signature_s: [u8; 64],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: BrainpoolP512t1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP512t1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP512t1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP512t1Fr = BigNum::from_be_bytes(signature_s);
    verify_brainpoolp512t1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

// Doesn't compile
/**
Arithmetic generics simplification failed: `((8: numeric u32) - (((NBytes : u32)'53600 -> (66: numeric u32) * (8: numeric u32)) - (MOD_BITS : u32)'53599 -> (384: numeric u32)))` != `((8: numeric u32) - (((NBytes : u32)'53600 -> (66: numeric u32) * (8: numeric u32)) - (MOD_BITS : u32)'53599 -> (384: numeric u32)))`
 most_significant_byte.assert_max_bit_size::<8 - (NBytes * 8 - MOD_BITS)>();
*/
pub fn verify_signature<let DATA_TO_SIGN_LEN: u32, let CURVE: u32, let PUBKEY_BYTE_LEN: u32, let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; PUBKEY_BYTE_LEN],
    pubkey_y: [u8; PUBKEY_BYTE_LEN],
    signature_r: [u8; PUBKEY_BYTE_LEN],
    signature_s: [u8; PUBKEY_BYTE_LEN],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    if CURVE == ECDSA_CURVE_P384 {
        let pubkey_x_bignum: Secp384r1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: Secp384r1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: Secp384r1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: Secp384r1Fr = BigNum::from_be_bytes(signature_s);
        verify_secp384r1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else if CURVE == ECDSA_CURVE_P521 {
        let pubkey_x_bignum: Secp521r1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: Secp521r1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: Secp521r1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: Secp521r1Fr = BigNum::from_be_bytes(signature_s);
        verify_secp521r1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else if CURVE == ECDSA_CURVE_BRAINPOOL_B256R1 {
        let pubkey_x_bignum: BrainpoolP256r1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: BrainpoolP256r1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: BrainpoolP256r1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: BrainpoolP256r1Fr = BigNum::from_be_bytes(signature_s);
        verify_brainpoolp256r1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else if CURVE == ECDSA_CURVE_BRAINPOOL_B384R1 {
        let pubkey_x_bignum: BrainpoolP384r1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: BrainpoolP384r1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: BrainpoolP384r1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: BrainpoolP384r1Fr = BigNum::from_be_bytes(signature_s);
        verify_brainpoolp384r1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else if CURVE == ECDSA_CURVE_BRAINPOOL_B512R1 {
        let pubkey_x_bignum: BrainpoolP512r1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: BrainpoolP512r1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: BrainpoolP512r1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: BrainpoolP512r1Fr = BigNum::from_be_bytes(signature_s);
        verify_brainpoolp512r1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else if CURVE == ECDSA_CURVE_BRAINPOOL_B256T1 {
        let pubkey_x_bignum: BrainpoolP256t1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: BrainpoolP256t1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: BrainpoolP256t1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: BrainpoolP256t1Fr = BigNum::from_be_bytes(signature_s);
        verify_brainpoolp256t1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else if CURVE == ECDSA_CURVE_BRAINPOOL_B384T1 {
        let pubkey_x_bignum: BrainpoolP384t1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: BrainpoolP384t1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: BrainpoolP384t1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: BrainpoolP384t1Fr = BigNum::from_be_bytes(signature_s);
        verify_brainpoolp384t1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else if CURVE == ECDSA_CURVE_BRAINPOOL_B512T1 {
        let pubkey_x_bignum: BrainpoolP512t1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: BrainpoolP512t1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: BrainpoolP512t1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: BrainpoolP512t1Fr = BigNum::from_be_bytes(signature_s);
        verify_brainpoolp512t1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else {
        false
    }
}
