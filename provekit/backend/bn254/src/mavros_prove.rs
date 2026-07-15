//! Mavros WHIR proving for bn254. The Mavros VM's automatic-differentiation
//! pass returns `ark_bn254::Fr`, so this proving path is bn254-specific; it
//! composes the generic proving primitives from `provekit-prover`
//! (`run_zk_sumcheck_prover`, `prove_from_alphas`).
//!
//! TODO: make field-generic and fold into `WhirR1CSProver<P>` when the Mavros
//! VM is field-agnostic.

use {
    crate::{Bn254Field, FieldElement, TranscriptSponge},
    anyhow::{ensure, Result},
    mavros_artifacts::{ConstraintsLayout, WitnessLayout},
    mavros_vm::interpreter::{run_ad, WitgenResult},
    provekit_common::{
        prefix_covector::expand_powers,
        utils::sumcheck::calculate_evaluations_over_boolean_hypercube_for_eq, PublicInputs,
        WhirR1CSProof, WhirR1CSScheme,
    },
    provekit_prover::{
        prove_from_alphas_ctx, run_zk_sumcheck_prover, ProveFromAlphasCtx, SparkQueryData,
        WhirR1CSCommitment,
    },
    tracing::instrument,
    whir::{algebra::embedding::Identity, transcript::ProverState},
};

pub trait MavrosR1CSProver {
    #[allow(clippy::too_many_arguments)]
    fn prove_mavros(
        &self,
        merlin: ProverState<TranscriptSponge>,
        witgen: WitgenResult,
        commitments: Vec<WhirR1CSCommitment<Bn254Field>>,
        public_inputs: &PublicInputs<FieldElement>,
        witness_layout: WitnessLayout,
        constraints_layout: ConstraintsLayout,
        binary: &[u64],
    ) -> Result<WhirR1CSProof>;

    /// Like [`Self::prove_mavros`], but also produces the SPARK query data as
    /// a side output (the transcript is identical either way).
    #[allow(clippy::too_many_arguments)]
    fn prove_mavros_with_spark(
        &self,
        merlin: ProverState<TranscriptSponge>,
        witgen: WitgenResult,
        commitments: Vec<WhirR1CSCommitment<Bn254Field>>,
        public_inputs: &PublicInputs<FieldElement>,
        witness_layout: WitnessLayout,
        constraints_layout: ConstraintsLayout,
        binary: &[u64],
    ) -> Result<(WhirR1CSProof, SparkQueryData<Bn254Field>)>;
}

impl MavrosR1CSProver for WhirR1CSScheme<Bn254Field> {
    #[instrument(skip_all)]
    fn prove_mavros(
        &self,
        merlin: ProverState<TranscriptSponge>,
        witgen: WitgenResult,
        commitments: Vec<WhirR1CSCommitment<Bn254Field>>,
        public_inputs: &PublicInputs<FieldElement>,
        witness_layout: WitnessLayout,
        constraints_layout: ConstraintsLayout,
        binary: &[u64],
    ) -> Result<WhirR1CSProof> {
        let (proof, _) = prove_mavros_inner(
            self,
            merlin,
            witgen,
            commitments,
            public_inputs,
            witness_layout,
            constraints_layout,
            binary,
            false,
        )?;
        Ok(proof)
    }

    #[instrument(skip_all)]
    fn prove_mavros_with_spark(
        &self,
        merlin: ProverState<TranscriptSponge>,
        witgen: WitgenResult,
        commitments: Vec<WhirR1CSCommitment<Bn254Field>>,
        public_inputs: &PublicInputs<FieldElement>,
        witness_layout: WitnessLayout,
        constraints_layout: ConstraintsLayout,
        binary: &[u64],
    ) -> Result<(WhirR1CSProof, SparkQueryData<Bn254Field>)> {
        let (proof, queries) = prove_mavros_inner(
            self,
            merlin,
            witgen,
            commitments,
            public_inputs,
            witness_layout,
            constraints_layout,
            binary,
            true,
        )?;
        let queries = queries
            .ok_or_else(|| anyhow::anyhow!("SPARK query data must be produced when requested"))?;
        Ok((proof, queries))
    }
}

#[instrument(skip_all)]
#[allow(clippy::too_many_arguments)]
fn prove_mavros_inner(
    scheme: &WhirR1CSScheme<Bn254Field>,
    mut merlin: ProverState<TranscriptSponge>,
    witgen: WitgenResult,
    commitments: Vec<WhirR1CSCommitment<Bn254Field>>,
    public_inputs: &PublicInputs<FieldElement>,
    witness_layout: WitnessLayout,
    constraints_layout: ConstraintsLayout,
    binary: &[u64],
    produce_spark_query: bool,
) -> Result<(WhirR1CSProof, Option<SparkQueryData<Bn254Field>>)> {
    ensure!(!commitments.is_empty(), "Need at least one commitment");

    let blinding = commitments[0]
        .blinding
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("c1 must carry blinding state"))?;

    // `g` is committed separately in the extension field; open `blinding_eval`
    // against the blinding vector (g flattened at offset 0).
    let (alpha, blinding_eval) = run_zk_sumcheck_prover(
        &Identity::new(),
        [witgen.out_a, witgen.out_b, witgen.out_c],
        &mut merlin,
        scheme.m_0,
        &blinding.polynomial,
        &blinding.vector,
    );

    let eq_alpha = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha, 1 << alpha.len());
    let (ad_a, ad_b, ad_c, _) = run_ad(
        binary,
        &eq_alpha[..constraints_layout.size()],
        witness_layout,
        constraints_layout,
    )?;
    let alphas = [ad_a, ad_b, ad_c];

    let blinding_weights = expand_powers::<4, _>(&alpha);

    prove_from_alphas_ctx(
        scheme,
        merlin,
        ProveFromAlphasCtx {
            alphas,
            blinding_eval,
            blinding_weights,
            commitments,
            spark_row: produce_spark_query.then_some(alpha),
        },
        public_inputs,
    )
}
