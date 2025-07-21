use crate::bignum::BigNum;
use crate::params::BigNumParams;
use crate::params::BigNumParamsGetter;

pub struct U512Params {}

pub type U512 = BigNum<5, 513, U512Params>;

impl BigNumParamsGetter<5, 513> for U512Params {
    fn get_params() -> BigNumParams<5, 513> {
        U512_PARAMS
    }
}

pub global U512_PARAMS: BigNumParams<5, 513> = BigNumParams {
    has_multiplicative_inverse: false,
    modulus: [0x00, 0x00, 0x00, 0x00, 0x0100000000],
    double_modulus: [
        0x01000000000000000000000000000000,
        0xffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffff,
        0x01ffffffff,
    ],
    redc_param: [0x00, 0x00, 0x00, 0x00, 0x4000000000],
};
