//! Zinc+ proving backend for ProveKit R1CS.
//!
//! Bridges ProveKit's BN254 R1CS (arkworks) to the Zinc+ SNARK
//! (`zinc-protocol`'s Spartan-style `R1csFrontend` over a fixed working field
//! plus the Zip+ PCS with RAA codes). The witness is committed as a single
//! full-width (256-bit) `int` column; see [`zinc_types`] for the type
//! instantiation.

mod convert;
pub mod zinc_types;

use {
    crate::{
        convert::{
            fe_to_field, padded_dims, r1cs_to_zinc, witness_to_int_column, FieldCfg, PaddedDims,
            BN254_CFG,
        },
        zinc_types::{FullWidthZincTypesRaa, ZincInt, F, FW_D, FW_FD},
    },
    anyhow::{ensure, Context, Result},
    provekit_common::{FieldElement, R1CS},
    std::borrow::Cow,
    tracing::instrument,
    zinc_poly::mle::DenseMultilinearExtension,
    zinc_protocol::{
        r1cs_frontend::{R1csConstraintProof, R1csFrontend},
        Proof, ZincPlusPiop, ZincTypes,
    },
    zinc_transcript::traits::{GenTranscribable, Transcribable},
    zinc_uair::{ideal::DegreeOneIdeal, ideal_collector::IdealOrZero, UairTrace},
    zinc_utils::CHECKED,
    zip_plus::{
        code::raa::RaaCode,
        pcs::structs::{ZipPlus, ZipPlusParams},
    },
};

type Zt = FullWidthZincTypesRaa;
type Piop = ZincPlusPiop<Zt, R1csFrontend<F>, F, FW_D, FW_FD>;
type ZincProof = Proof<F, R1csConstraintProof<F>>;
type Ideal = IdealOrZero<DegreeOneIdeal<F>>;
type PublicParams = (
    ZipPlusParams<
        <Zt as ZincTypes<FW_D, FW_FD>>::BinaryZt,
        <Zt as ZincTypes<FW_D, FW_FD>>::BinaryLc,
    >,
    ZipPlusParams<
        <Zt as ZincTypes<FW_D, FW_FD>>::ArbitraryZt,
        <Zt as ZincTypes<FW_D, FW_FD>>::ArbitraryLc,
    >,
    ZipPlusParams<<Zt as ZincTypes<FW_D, FW_FD>>::IntZt, <Zt as ZincTypes<FW_D, FW_FD>>::IntLc>,
);

/// An empty column trace (used for the substrate-public trace, which is
/// always empty for R1CS: public inputs are bound inside the argument, not
/// via substrate public columns).
fn empty_trace() -> UairTrace<'static, ZincInt, ZincInt, FW_D, FW_D> {
    UairTrace {
        binary_poly:    Cow::Owned(vec![]),
        arbitrary_poly: Cow::Owned(vec![]),
        int:            Cow::Owned(vec![]),
    }
}

/// Zip+ public parameters for the padded witness length. Deterministic (RAA
/// permutation seeds are fixed), so prover and verifier derive identical
/// parameters independently.
fn setup_params(dims: &PaddedDims) -> PublicParams {
    // Arrange the committed column as a near-square matrix; the RAA codeword
    // then has `row_len * REP` columns, comfortably above NUM_COLUMN_OPENINGS
    // thanks to the MIN_NUM_VARS floor in `padded_dims`.
    let row_len = 1usize << (dims.num_vars / 2);
    let poly_size = dims.padded_cols;
    (
        ZipPlus::setup(poly_size, RaaCode::new(row_len)),
        ZipPlus::setup(poly_size, RaaCode::new(row_len)),
        ZipPlus::setup(poly_size, RaaCode::new(row_len)),
    )
}

/// Build the Zinc+ statement (frontend) shared by prover and verifier.
fn build_frontend(
    r1cs: &R1CS,
    public_values: &[FieldElement],
    dims: &PaddedDims,
    cfg: &FieldCfg,
) -> Result<R1csFrontend<F>> {
    ensure!(
        public_values.len() == r1cs.num_public_inputs,
        "expected {} public inputs, got {}",
        r1cs.num_public_inputs,
        public_values.len()
    );
    let instance = r1cs_to_zinc(r1cs, dims, cfg);
    let public_values = public_values
        .iter()
        .map(|v| fe_to_field(v, cfg))
        .collect::<Vec<_>>();
    Ok(R1csFrontend::new(instance, public_values, *cfg))
}

/// Prove a ProveKit R1CS instance with Zinc+.
///
/// `witness` is the full solved witness vector `z = [1, public...,
/// private...]` of length `r1cs.num_witnesses()`; `public_values` are the
/// `r1cs.num_public_inputs` public inputs (excluding the constant one).
/// Returns the serialized Zinc+ proof.
#[instrument(skip_all)]
pub fn zinc_prove(
    r1cs: &R1CS,
    public_values: &[FieldElement],
    witness: &[FieldElement],
) -> Result<Vec<u8>> {
    ensure!(
        witness.len() == r1cs.num_witnesses(),
        "expected {} witnesses, got {}",
        r1cs.num_witnesses(),
        witness.len()
    );
    let cfg = &*BN254_CFG;
    let dims = padded_dims(r1cs)?;
    let frontend = build_frontend(r1cs, public_values, &dims, cfg)?;
    let pp = setup_params(&dims);

    let z_wit = witness_to_int_column(witness, r1cs.num_public_inputs, dims.padded_cols);
    let witness_col =
        DenseMultilinearExtension::from_evaluations_vec(dims.num_vars, z_wit, ZincInt::default());
    let trace: UairTrace<'static, ZincInt, ZincInt, FW_D, FW_D> = UairTrace {
        binary_poly:    Cow::Owned(vec![]),
        arbitrary_poly: Cow::Owned(vec![]),
        int:            Cow::Owned(vec![witness_col]),
    };

    let proof = Piop::prove::<false, CHECKED>(&pp, &trace, dims.num_vars, &frontend)
        .map_err(|e| anyhow::anyhow!("Zinc+ prove failed: {e:?}"))?;

    let mut bytes = vec![0u8; proof.get_num_bytes()];
    proof.write_transcription_bytes_exact(&mut bytes);
    Ok(bytes)
}

/// Verify a Zinc+ proof for a ProveKit R1CS instance against the given
/// public inputs.
#[instrument(skip_all)]
pub fn zinc_verify(r1cs: &R1CS, public_values: &[FieldElement], proof_bytes: &[u8]) -> Result<()> {
    let cfg = &*BN254_CFG;
    let dims = padded_dims(r1cs)?;
    let frontend = build_frontend(r1cs, public_values, &dims, cfg)?;
    let pp = setup_params(&dims);

    // Proof deserialization asserts on malformed input; treat a panic as a
    // malformed proof rather than crashing the verifier.
    let proof: ZincProof =
        std::panic::catch_unwind(|| ZincProof::read_transcription_bytes_exact(proof_bytes))
            .map_err(|_| anyhow::anyhow!("Malformed Zinc+ proof"))?;

    let public_trace = empty_trace();
    Piop::verify::<Ideal, CHECKED>(
        &pp,
        proof,
        &public_trace,
        dims.num_vars,
        &frontend,
        |_, _| unreachable!("R1CS: no psi_a scalar projection"),
        |_, _| unreachable!("R1CS: no ideal projection"),
        |_, _| unreachable!("R1CS: no fq-ideal projection"),
    )
    .map_err(|e| anyhow::anyhow!("Zinc+ verification failed: {e:?}"))
    .context("While verifying Zinc+ proof")
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ark_ff::{Field as ArkField, One, PrimeField as ArkPrimeField, Zero},
        crypto_primitives::Field as CpField,
        provekit_common::FieldElement,
    };

    /// `fe_to_field` maps 0, 1, p-1 and a full-width value to the expected
    /// canonical representatives.
    #[test]
    fn field_conversion_roundtrip() {
        let cfg = &*BN254_CFG;
        for fe in [
            FieldElement::zero(),
            FieldElement::one(),
            -FieldElement::one(),
            FieldElement::from(123456789u64).pow([5]),
        ] {
            let converted = fe_to_field(&fe, cfg);
            let expected: [u64; 4] = fe.into_bigint().0;
            let lifted = converted.lift_to_integer();
            assert_eq!(
                lifted.inner().to_words(),
                expected,
                "canonical representative mismatch for {fe}"
            );
        }
    }

    /// Hand-built R1CS `x * x = w` with a genuinely full-width witness
    /// (`x = p - 3`, so `x` does not fit in an `i64`), one public input, no
    /// Noir involved. Covers prove/verify roundtrip and tamper rejection for
    /// the `D = FD = 1` + `NoopFoldTrace` + 256-bit-int instantiation.
    #[test]
    fn full_width_prove_verify_tamper() {
        let x = -FieldElement::from(3u64); // p - 3: full 254-bit value
        let w = x * x;

        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(3); // [1, x, w]
        r1cs.num_public_inputs = 1; // x at z[1] is public
        let one = FieldElement::one();
        r1cs.add_constraint(&[(one, 1)], &[(one, 1)], &[(one, 2)]);

        let witness = vec![FieldElement::one(), x, w];
        let public_values = vec![x];

        let proof = zinc_prove(&r1cs, &public_values, &witness).expect("prove");

        zinc_verify(&r1cs, &public_values, &proof).expect("verify");

        // Tampered public input must be rejected.
        let bad_public = vec![x + FieldElement::one()];
        assert!(
            zinc_verify(&r1cs, &bad_public, &proof).is_err(),
            "tampered public input must be rejected"
        );

        // Tampered proof bytes must be rejected (either a verification
        // failure or a malformed-proof error).
        let mut bad_proof = proof.clone();
        let mid = bad_proof.len() / 2;
        bad_proof[mid] ^= 0x01;
        assert!(
            zinc_verify(&r1cs, &public_values, &bad_proof).is_err(),
            "tampered proof must be rejected"
        );
    }

    /// An unsatisfied instance must fail to produce a valid proof (the prover
    /// either errors or the resulting proof is rejected).
    #[test]
    fn unsatisfied_instance_rejected() {
        let x = FieldElement::from(3u64);
        let w = FieldElement::from(10u64); // wrong: 3 * 3 != 10

        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(3);
        r1cs.num_public_inputs = 0;
        let one = FieldElement::one();
        r1cs.add_constraint(&[(one, 1)], &[(one, 1)], &[(one, 2)]);

        let witness = vec![FieldElement::one(), x, w];

        match zinc_prove(&r1cs, &[], &witness) {
            Err(_) => {}
            Ok(proof) => assert!(
                zinc_verify(&r1cs, &[], &proof).is_err(),
                "proof of an unsatisfied instance must be rejected"
            ),
        }
    }
}
