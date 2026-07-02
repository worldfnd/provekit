//! Zinc+ type instantiation for full-width (254-bit) BN254 witness values.
//!
//! ProveKit witnesses are canonical BN254 scalar-field representatives in
//! $[0, p)$ with $p < 2^{254}$, so the committed `int` column carries 256-bit
//! signed integers. RAA linear codes are used for the Zip+ PCS because their
//! encoding is repetition/permutation/accumulation only — codeword growth is
//! additive in $2\log_2(\text{codeword len})$ bits, so 256-bit evaluations fit
//! comfortably in 320-bit codeword entries (good for row lengths up to
//! $2^{29}$ per the width assertion in `zip_plus::code::raa`).

use {
    crypto_bigint::U64,
    crypto_primitives::{
        crypto_bigint_int::Int, crypto_bigint_monty::MontyField, crypto_bigint_uint::Uint,
    },
    zinc_poly::univariate::{
        binary::{BinaryPoly, BinaryPolyInnerProduct},
        dense::{DensePolyInnerProduct, DensePolynomial},
    },
    zinc_primality::MillerRabin,
    zinc_protocol::{fold::NoopFoldTrace, ZincTypes},
    zinc_utils::inner_product::{MBSInnerProduct, ScalarProduct},
    zip_plus::{
        code::raa::{RaaCode, RaaConfig},
        pcs::structs::ZipTypes,
    },
};

/// 256-bit limb count (4 × 64-bit words): holds canonical BN254-Fr
/// representatives in $[0, p)$, $p < 2^{254}$.
pub const LIMBS_256: usize = U64::LIMBS * 4;
/// 320-bit limb count: RAA codeword entries (256-bit evaluations plus
/// $2\log_2(\text{row len} \cdot \text{REP})$ bits of accumulation growth).
const LIMBS_320: usize = U64::LIMBS * 5;
/// 512-bit limb count: random-linear-combination accumulators
/// (evaluation + challenge + summation growth stays well under 511 bits).
const LIMBS_512: usize = U64::LIMBS * 8;

/// Committed columns are scalar-valued: polynomial degree bound $D = 1$.
pub const FW_D: usize = 1;
/// No binary-column folding ([`NoopFoldTrace`]), so the folded degree bound
/// equals `FW_D`.
pub const FW_FD: usize = 1;
/// RAA repetition factor (code rate 1/8).
const REP: usize = 8;

/// The fixed R1CS working field: BN254 scalar field as a runtime-configured
/// Montgomery field.
pub type F = MontyField<LIMBS_256>;
/// Committed witness integers: 256-bit signed, canonical Fr representatives.
pub type ZincInt = Int<LIMBS_256>;
type FwCw = Int<LIMBS_320>;
type FwCombR = Int<LIMBS_512>;
type FwFmod = Uint<LIMBS_256>;
type FwChal = i128;

/// RAA code configuration: precomputed permutations and overflow-checked
/// accumulation (the width headroom above is analytic; checked adds turn any
/// miscalculation into a clean encoding error instead of silent wraparound).
#[derive(Copy, Clone, Debug)]
pub struct FullWidthRaaConfig;

impl RaaConfig for FullWidthRaaConfig {
    const CHECK_FOR_OVERFLOWS: bool = true;
    const PERMUTE_IN_PLACE: bool = false;
}

/// Zip+ types for the `int` column group — the only group R1CS actually
/// commits (the witness vector is a single scalar `int` column).
#[derive(Debug, Clone)]
pub struct FullWidthIntZipTypes;

impl ZipTypes for FullWidthIntZipTypes {
    type ArrCombRDotChal = MBSInnerProduct;
    type Chal = FwChal;
    type Comb = Self::CombR;
    type CombDotChal = ScalarProduct;
    type CombR = FwCombR;
    type Cw = FwCw;
    type Eval = ZincInt;
    type EvalDotChal = ScalarProduct;
    type Fmod = FwFmod;
    type Pt = i128;
    type PrimeTest = MillerRabin;

    const NUM_COLUMN_OPENINGS: usize = 100;
}

/// Zip+ types for the `binary_poly` column group. R1CS commits no binary
/// columns, so this exists only to satisfy the [`ZincTypes`] shape.
#[derive(Debug, Clone)]
pub struct FullWidthBinZipTypes;

impl ZipTypes for FullWidthBinZipTypes {
    type ArrCombRDotChal = MBSInnerProduct;
    type Chal = FwChal;
    type Comb = DensePolynomial<Self::CombR, FW_FD>;
    type CombDotChal =
        DensePolyInnerProduct<Self::CombR, FwChal, Self::CombR, MBSInnerProduct, FW_FD>;
    type CombR = FwCombR;
    type Cw = DensePolynomial<i64, FW_FD>;
    type Eval = BinaryPoly<FW_FD>;
    type EvalDotChal = BinaryPolyInnerProduct<FwChal, FW_FD>;
    type Fmod = FwFmod;
    type Pt = i128;
    type PrimeTest = MillerRabin;

    const NUM_COLUMN_OPENINGS: usize = 100;
}

/// Zip+ types for the `arbitrary_poly` column group. R1CS commits no
/// polynomial columns, so this exists only to satisfy the [`ZincTypes`] shape.
#[derive(Debug, Clone)]
pub struct FullWidthArbZipTypes;

impl ZipTypes for FullWidthArbZipTypes {
    type ArrCombRDotChal = MBSInnerProduct;
    type Chal = FwChal;
    type Comb = DensePolynomial<Self::CombR, FW_D>;
    type CombDotChal =
        DensePolyInnerProduct<Self::CombR, FwChal, Self::CombR, MBSInnerProduct, FW_D>;
    type CombR = FwCombR;
    type Cw = DensePolynomial<FwCw, FW_D>;
    type Eval = DensePolynomial<ZincInt, FW_D>;
    type EvalDotChal = DensePolyInnerProduct<ZincInt, FwChal, FwCombR, MBSInnerProduct, FW_D>;
    type Fmod = FwFmod;
    type Pt = i128;
    type PrimeTest = MillerRabin;

    const NUM_COLUMN_OPENINGS: usize = 100;
}

/// The full-width RAA [`ZincTypes`] instantiation used for ProveKit R1CS:
/// 256-bit `int`-column evaluations, RAA codes for all three groups, and no
/// binary folding.
#[derive(Clone, Debug)]
pub struct FullWidthZincTypesRaa;

impl ZincTypes<FW_D, FW_FD> for FullWidthZincTypesRaa {
    type ArbitraryLc = RaaCode<Self::ArbitraryZt, FullWidthRaaConfig, REP>;
    type ArbitraryZt = FullWidthArbZipTypes;
    type BinaryFold = NoopFoldTrace;
    type BinaryLc = RaaCode<Self::BinaryZt, FullWidthRaaConfig, REP>;
    type BinaryZt = FullWidthBinZipTypes;
    type Chal = FwChal;
    type CombR = FwCombR;
    type Fmod = FwFmod;
    type Int = ZincInt;
    type IntLc = RaaCode<Self::IntZt, FullWidthRaaConfig, REP>;
    type IntZt = FullWidthIntZipTypes;
    type PrimeTest = MillerRabin;
    type Pt = i128;
}
