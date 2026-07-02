//! Conversions between ProveKit types (arkworks BN254) and Zinc+ types
//! (crypto-primitives `MontyField`/`Int`), plus power-of-two padding.

use {
    crate::zinc_types::{ZincInt, F, LIMBS_256},
    anyhow::{ensure, Result},
    ark_ff::PrimeField as ArkPrimeField,
    crypto_primitives::{
        crypto_bigint_uint::Uint, FromWithConfig, HasPrimeFieldConfig, PrimeField,
    },
    provekit_common::{sparse_matrix::HydratedSparseMatrix, FieldElement, R1CS},
    std::sync::LazyLock,
    zinc_protocol::{r1cs_frontend::R1csInstance, r1cs_sparse_matrix::SparseMatrix},
};

/// BN254 scalar field modulus, big-endian hex (matches `ark_bn254::Fr`).
const BN254_FR_MODULUS_HEX: &str =
    "30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001";

/// Field configuration type of the fixed Zinc+ working field.
pub(crate) type FieldCfg = <F as HasPrimeFieldConfig>::Config;

/// The fixed BN254 scalar-field configuration, built once.
pub(crate) static BN254_CFG: LazyLock<FieldCfg> = LazyLock::new(|| {
    let modulus = Uint::<LIMBS_256>::new(crypto_bigint::Uint::from_be_hex(BN254_FR_MODULUS_HEX));
    F::make_cfg(&modulus).expect("BN254 scalar modulus is odd")
});

/// Minimum number of MLE variables for the committed witness column. Tiny
/// instances are zero-padded up to this size so the RAA codeword has more
/// columns than `NUM_COLUMN_OPENINGS` (soundness-neutral: padding slots are
/// zero and touched by no constraint).
const MIN_NUM_VARS: usize = 10;

/// Padded dimensions shared by prover and verifier, derived deterministically
/// from the (public) R1CS index — nothing extra is persisted.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PaddedDims {
    /// log2 of the padded witness length (the variable axis).
    pub num_vars:    usize,
    /// Padded witness length / matrix column count (`1 << num_vars`).
    pub padded_cols: usize,
    /// Padded constraint count (power of two, ≥ 2).
    pub padded_rows: usize,
}

pub(crate) fn padded_dims(r1cs: &R1CS) -> Result<PaddedDims> {
    ensure!(r1cs.num_witnesses() > 0, "R1CS has no witnesses");
    ensure!(r1cs.num_constraints() > 0, "R1CS has no constraints");
    let num_vars =
        r1cs.num_witnesses()
            .next_power_of_two()
            .ilog2()
            .max(u32::try_from(MIN_NUM_VARS).expect("MIN_NUM_VARS fits u32")) as usize;
    let padded_cols = 1usize << num_vars;
    let padded_rows = r1cs.num_constraints().next_power_of_two().max(2);
    Ok(PaddedDims {
        num_vars,
        padded_cols,
        padded_rows,
    })
}

/// Convert an arkworks BN254 scalar to the Zinc+ working field.
///
/// `into_bigint()` yields the canonical (non-Montgomery) representative as
/// little-endian `u64` limbs; the value is `< p`, so the modular reduction in
/// `from_with_cfg` is the identity.
pub(crate) fn fe_to_field(x: &FieldElement, cfg: &FieldCfg) -> F {
    let limbs: [u64; 4] = x.into_bigint().0;
    let value = Uint::<LIMBS_256>::new(crypto_bigint::Uint::from_words(limbs));
    F::from_with_cfg(&value, cfg)
}

/// Convert an arkworks BN254 scalar to a committed 256-bit integer.
///
/// Canonical representatives are in `[0, p)` with `p < 2^{254}`, so the top
/// two bits are clear and the two's-complement reinterpretation is the same
/// non-negative value.
pub(crate) fn fe_to_int(x: &FieldElement) -> ZincInt {
    ZincInt::from_words(x.into_bigint().0)
}

/// Convert the ProveKit R1CS index (interned, delta-encoded sparse matrices
/// over arkworks BN254) into the Zinc+ R1CS instance (variable-density CSR
/// over the fixed working field), padded to `PaddedDims`.
pub(crate) fn r1cs_to_zinc(r1cs: &R1CS, dims: &PaddedDims, cfg: &FieldCfg) -> R1csInstance<F> {
    let convert = |m: HydratedSparseMatrix<'_>| -> SparseMatrix<F> {
        let mut rows: Vec<Vec<(usize, F)>> = vec![Vec::new(); dims.padded_rows];
        for ((row, col), value) in m.iter() {
            rows[row].push((col, fe_to_field(&value, cfg)));
        }
        SparseMatrix::from_rows(dims.padded_cols, rows)
    };
    R1csInstance {
        a:                 convert(r1cs.a()),
        b:                 convert(r1cs.b()),
        c:                 convert(r1cs.c()),
        num_public_inputs: r1cs.num_public_inputs,
    }
}

/// Build the committed witness column: the full witness vector `z = [1,
/// public..., private...]` as 256-bit integers, zero-padded to the padded
/// length, with the public prefix `0..=num_public_inputs` zeroed (the Zinc+
/// R1CS frontend re-adds the public prefix inside the argument).
pub(crate) fn witness_to_int_column(
    witness: &[FieldElement],
    num_public_inputs: usize,
    padded_cols: usize,
) -> Vec<ZincInt> {
    let mut z = vec![ZincInt::default(); padded_cols];
    for (slot, value) in z.iter_mut().zip(witness).skip(num_public_inputs + 1) {
        *slot = fe_to_int(value);
    }
    z
}
