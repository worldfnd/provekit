use crate::bignum::BigNum;
use crate::params::BigNumParams;
use crate::params::BigNumParamsGetter;

pub struct Secp384r1_Fq_Params {}

pub type Secp384r1_Fq = BigNum<4, 384, Secp384r1_Fq_Params>;

impl BigNumParamsGetter<4, 384> for Secp384r1_Fq_Params {
    fn get_params() -> BigNumParams<4, 384> {
        Secp384r1_Fq_PARAMS
    }
}

pub global Secp384r1_Fq_PARAMS: BigNumParams<4, 384> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [
        0xffffff0000000000000000ffffffff,
        0xfffffffffffffffffffffffffffeff,
        0xffffffffffffffffffffffffffffff,
        0xffffff,
    ],
    double_modulus: [
        0x01fffffe0000000000000001fffffffe,
        0x01fffffffffffffffffffffffffffdfe,
        0x01fffffffffffffffffffffffffffffe,
        0x01fffffe,
    ],
    redc_param: [0x0ffffffffffffffff000000010, 0x1000, 0x00, 0x10000000],
};
