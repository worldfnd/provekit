use crate::bignum::BigNum;
use crate::bignum::derive_bignum;
use crate::params::BigNumParams;

pub global Secp256r1_Fr_PARAMS: BigNumParams<3, 256> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0xe6faada7179e84f3b9cac2fc632551, 0xffff00000000ffffffffffffffffbc, 0xffff],
    double_modulus: [
        0x01cdf55b4e2f3d09e7739585f8c64aa2,
        0x01fffe00000001ffffffffffffffff78,
        0x01fffe,
    ],
    redc_param: [0x90552df1a6c21012ffd85eedf9bfe6, 0x0fffffffffffffffeffffffff431, 0x100000],
};

#[derive_bignum(3, 256, quote {Secp256r1_Fr_PARAMS})]
pub struct Secp256r1_Fr {
    limbs: [u128; 3],
}
