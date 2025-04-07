use bignum::{BigNum, BigNumTrait};
use bigcurve::{BigCurveTrait, curves::secp256r1::{Secp256r1, Secp256r1Fq, Secp256r1Fr, Secp256r1Scalar}, scalar_field::ScalarFieldTrait};

fn main(
    hashed_message : [u8;32], 
    pub_key_x : [u8;32], 
    pub_key_y : [u8;32], 
    signature : [u8;64]
) {
    let gen = Secp256r1::one();
    let public = Secp256r1 {
        x: BigNum::from_be_bytes(pub_key_x),
        y: BigNum::from_be_bytes(pub_key_y),
        is_infinity: false,
    };
    public.validate_on_curve();
    let message = Secp256r1Fr::from_be_bytes(hashed_message);
    
    // Somehow Noir makes it harder than necessary to get the signature components.
    let mut r: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    let mut s: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    for i in 0..32 {
        r[i] = signature[i];
        s[i] = signature[i + 32];
    }
    let r_x = Secp256r1Fq::from_be_bytes(r);
    let r = Secp256r1Fr::from_be_bytes(r);
    let s = Secp256r1Fr::from_be_bytes(s);

    let s_g = Secp256r1Scalar::from_bignum(message / s);
    let s_p = Secp256r1Scalar::from_bignum(r / s);
    let r_point = Secp256r1::msm([gen, public], [s_g, s_p]);

    assert(r_point.x == rx);
}
