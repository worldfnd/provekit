use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;

pub type Params1024 = BigNumParams<9, 1024>;
pub type Params1025 = BigNumParams<9, 1025>;
pub type Params1964 = BigNumParams<17, 1946>;
pub type Params2048 = BigNumParams<18, 2048>;
pub type Params4096 = BigNumParams<35, 4096>;

pub type RBN1024 = RuntimeBigNum<9, 1024>;
pub type RBN1025 = RuntimeBigNum<9, 1025>;
pub type RBN1964 = RuntimeBigNum<17, 1946>;
pub type RBN2048 = RuntimeBigNum<18, 2048>;
pub type RBN4096 = RuntimeBigNum<35, 4096>;
