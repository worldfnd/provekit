use crate::bignum::BigNum;
use crate::bignum::derive_bignum;
use crate::params::BigNumParams;

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

#[derive_bignum(3, 255, quote {ED25519_Fr_PARAMS})]
pub struct ED25519_Fr {
    limbs: [u128; 3],
}
