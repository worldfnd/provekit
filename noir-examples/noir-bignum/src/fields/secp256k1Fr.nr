use crate::bignum::BigNum;
use crate::bignum::derive_bignum;
use crate::params::BigNumParams;

pub global Secp256k1_Fr_PARAMS: BigNumParams<3, 256> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0xaedce6af48a03bbfd25e8cd0364141, 0xfffffffffffffffffffffffffffeba, 0xffff],
    double_modulus: [
        0x015db9cd5e9140777fa4bd19a06c8282,
        0x01fffffffffffffffffffffffffffd74,
        0x01fffe,
    ],
    redc_param: [0x1231950b75fc4402da1732fc9bec09, 0x1455, 0x100000],
};

#[derive_bignum(3, 256, quote {Secp256k1_Fr_PARAMS})]
pub struct Secp256k1_Fr {
    limbs: [u128; 3],
}
