use crate::bignum::BigNum;
use crate::params::BigNumParams;
use crate::params::BigNumParamsGetter;

pub struct ED25519_Fq_Params {}

pub type ED25519_Fq = BigNum<3, 255, ED25519_Fq_Params>;

impl BigNumParamsGetter<3, 255> for ED25519_Fq_Params {
    fn get_params() -> BigNumParams<3, 255> {
        ED25519_Fq_PARAMS
    }
}

pub global ED25519_Fq_PARAMS: BigNumParams<3, 255> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0xffffffffffffffffffffffffffffed, 0xffffffffffffffffffffffffffffff, 0x7fff],
    double_modulus: [
        0x01ffffffffffffffffffffffffffffda,
        0x01fffffffffffffffffffffffffffffe,
        0xfffe,
    ],
    redc_param: [0x0130, 0x00, 0x080000],
};
