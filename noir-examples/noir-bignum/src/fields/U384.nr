use crate::bignum::BigNum;
use crate::params::BigNumParams;
use crate::params::BigNumParamsGetter;

pub struct U384Params {}

pub type U384 = BigNum<4, 385, U384Params>;

impl BigNumParamsGetter<4, 385> for U384Params {
    fn get_params() -> BigNumParams<4, 385> {
        U384_PARAMS
    }
}

pub global U384_PARAMS: BigNumParams<4, 385> = BigNumParams {
    has_multiplicative_inverse: false,
    modulus: [0x00, 0x00, 0x00, 0x01000000],
    double_modulus: [
        0x01000000000000000000000000000000,
        0xffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffff,
        0x01ffffff,
    ],
    redc_param: [0x00, 0x00, 0x00, 0x40000000],
};
