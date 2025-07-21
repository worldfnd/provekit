use crate::bignum::BigNum;
use crate::params::BigNumParams;
use crate::params::BigNumParamsGetter;

pub struct Secp256r1_Fq_Params {}

pub type Secp256r1_Fq = BigNum<3, 256, Secp256r1_Fq_Params>;

impl BigNumParamsGetter<3, 256> for Secp256r1_Fq_Params {
    fn get_params() -> BigNumParams<3, 256> {
        Secp256r1_Fq_PARAMS
    }
}

pub global Secp256r1_Fq_PARAMS: BigNumParams<3, 256> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0xffffffffffffffffffffffff, 0xffff00000001000000000000000000, 0xffff],
    double_modulus: [
        0x01000001fffffffffffffffffffffffe,
        0x01fffe00000001ffffffffffffffffff,
        0x01fffe,
    ],
    redc_param: [0xffffeffffffff00000000000000030, 0x0fffffffffffffffefffffffefff, 0x100000],
};
