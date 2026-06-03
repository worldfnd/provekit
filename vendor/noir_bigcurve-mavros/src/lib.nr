mod bigcurve;
mod scalar_field;

// Pre-defined curves and `BigCurve`s for people to use:
pub mod curves;

mod tests;
mod benchmarks;
mod data;

// Free functions and other utils, called by the BigCurve structs
pub(crate) mod utils;
pub(crate) mod ops;
pub(crate) mod curve_jac;

// Internal functions required by derive macros for external crates
// Exported through the `internal` submodule to make it clear they are not
// intended for direct use by end users
pub mod internal {
    pub use dep::bignum::bignum::evaluate_quadratic_expression;

    pub use crate::ops::msm::evaluate_linear_expression;
    pub use crate::ops::msm::get_mul_transcript;
    pub use crate::ops::msm::mul_with_hint;

    pub use crate::ops::affine::add_with_hint;
    pub use crate::ops::affine::sub_with_hint;
}

// Re-export the main structs so that users on't have to specify the paths
pub use bigcurve::BigCurve;
pub use bigcurve::BigCurveParams;
pub use bigcurve::derive_curve_impl;
pub use scalar_field::ScalarField;

// Re-export the pre-defied bigcurve types, for easier access:
pub use curves::bls12_377::BLS12_377;
pub use curves::bls12_381::BLS12_381;
pub use curves::bn254::BN254;
pub use curves::mnt4_753::MNT4_753;
pub use curves::mnt6_753::MNT6_753;
pub use curves::pallas::Pallas;
pub use curves::secp256k1::Secp256k1;
pub use curves::secp256r1::Secp256r1;
pub use curves::secp384r1::Secp384r1;
pub use curves::vesta::Vesta;
