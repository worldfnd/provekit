use crate::bignum::BigNum;
use crate::params::BigNumParams;
use crate::params::BigNumParamsGetter;

pub struct U1024Params {}

pub type U1024 = BigNum<9, 1025, U1024Params>;

impl BigNumParamsGetter<9, 1025> for U1024Params {
    fn get_params() -> BigNumParams<9, 1025> {
        U1024_PARAMS
    }
}

pub global U1024_PARAMS: BigNumParams<9, 1025> = BigNumParams {
    has_multiplicative_inverse: false,
    modulus: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x010000000000000000],
    double_modulus: [
        0x01000000000000000000000000000000,
        0xffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffff,
        0x01ffffffffffffffff,
    ],
    redc_param: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x400000000000000000],
};
