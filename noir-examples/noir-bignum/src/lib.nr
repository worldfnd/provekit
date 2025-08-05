mod bignum;
mod runtime_bignum;
// mod tests;
// mod benchmarks;
pub mod constants;

// Pre-defined fields and bignums for people to use:
// pub mod fields;

// Structs enabling people to define their own bignum params
pub mod params;

// Free functions and other utils, called by the BigNum and RuntimeBigNum structs
pub(crate) mod fns;
pub(crate) mod utils;

// Re-export the main structs so that users don't have to specify the paths
pub use bignum::{BigNum, BigNumTrait};
pub use runtime_bignum::RuntimeBigNum;

// // Re-export the pre-defined bignum types, for easier access:
// pub use fields::bls12_377Fq::BLS12_377_Fq;
// pub use fields::bls12_377Fr::BLS12_377_Fr;
// pub use fields::bls12_381Fq::BLS12_381_Fq;
// pub use fields::bls12_381Fr::BLS12_381_Fr;
// pub use fields::bn254Fq::BN254_Fq;
// pub use fields::ed25519Fq::ED25519_Fq;
// pub use fields::ed25519Fr::ED25519_Fr;
// pub use fields::mnt4_753Fq::MNT4_753_Fq;
// pub use fields::mnt4_753Fr::MNT4_753_Fr;
// pub use fields::mnt6_753Fq::MNT6_753_Fq;
// pub use fields::mnt6_753Fr::MNT6_753_Fr;
// pub use fields::pallasFq::Pallas_Fq;
// pub use fields::pallasFr::Pallas_Fr;
// pub use fields::secp256k1Fq::Secp256k1_Fq;
// pub use fields::secp256k1Fr::Secp256k1_Fr;
// pub use fields::secp256r1Fq::Secp256r1_Fq;
// pub use fields::secp256r1Fr::Secp256r1_Fr;
// pub use fields::secp384r1Fq::Secp384r1_Fq;
// pub use fields::secp384r1Fr::Secp384r1_Fr;
// pub use fields::U1024::U1024;
// pub use fields::U2048::U2048;
// pub use fields::U256::U256;
// pub use fields::U384::U384;
// pub use fields::U4096::U4096;
// pub use fields::U512::U512;
// pub use fields::U768::U768;
// pub use fields::U8192::U8192;
// pub use fields::vestaFq::Vesta_Fq;
// pub use fields::vestaFr::Vesta_Fr;
