use crate::bignum::BigNum;
use crate::params::BigNumParams;
use crate::params::BigNumParamsGetter;

pub struct ED25519_Fr_Params {}

pub type ED25519_Fr = BigNum<3, 255, ED25519_Fr_Params>;

impl BigNumParamsGetter<3, 255> for ED25519_Fr_Params {
    fn get_params() -> BigNumParams<3, 255> {
        ED25519_Fr_PARAMS
    }
}

pub global ED25519_Fr_PARAMS: BigNumParams<3, 255> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0xdef9dea2f79cd65812631a5cf5d3ed, 0x14, 0x1000],
    double_modulus: [
        0x01bdf3bd45ef39acb024c634b9eba7da,
        0x01000000000000000000000000000028,
        0x1fff,
    ],
    redc_param: [0x4188574218ca69fb673968c28b04c6, 0xfffffffffffffffffffffffffffac8, 0x03ffff],
};
