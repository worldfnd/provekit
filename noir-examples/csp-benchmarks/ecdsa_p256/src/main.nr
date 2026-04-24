use bignum::BigNum;
use bigcurve::curves::secp256r1::{Secp256r1_Fq, Secp256r1_Fr};
use noir_ecdsa::ecdsa::verify_secp256r1_ecdsa;

fn main(hashed_message: [u8; 32], pub_key_x: [u8; 32], pub_key_y: [u8; 32], signature: [u8; 64]) {
    let public_key_x = Secp256r1_Fq::from_be_bytes(pub_key_x);
    let public_key_y = Secp256r1_Fq::from_be_bytes(pub_key_y);
    let r = signature_scalar(signature, 0);
    let s = signature_scalar(signature, 32);

    assert(verify_secp256r1_ecdsa(public_key_x, public_key_y, hashed_message, (r, s)));
}

fn signature_scalar(signature: [u8; 64], offset: u32) -> Secp256r1_Fr {
    let mut bytes = [0; 32];
    for i in 0..32 {
        bytes[i] = signature[offset + i];
    }
    Secp256r1_Fr::from_be_bytes(bytes)
}
