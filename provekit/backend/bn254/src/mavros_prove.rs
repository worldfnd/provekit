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
    provekit_prover::{prove_from_alphas, run_zk_sumcheck_prover, WhirR1CSCommitment},
    tracing::instrument,
    whir::{algebra::embedding::Identity, transcript::ProverState},
};

pub trait MavrosR1CSProver {
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
}

impl MavrosR1CSProver for WhirR1CSScheme<Bn254Field> {
    #[instrument(skip_all)]
    fn prove_mavros(
        &self,
        mut merlin: ProverState<TranscriptSponge>,
        witgen: WitgenResult,
        commitments: Vec<WhirR1CSCommitment<Bn254Field>>,
        public_inputs: &PublicInputs<FieldElement>,
        witness_layout: WitnessLayout,
        constraints_layout: ConstraintsLayout,
        binary: &[u64],
    ) -> Result<WhirR1CSProof> {
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
            self.m_0,
            &blinding.polynomial,
            &blinding.vector,
        );

        let eq_alpha =
            calculate_evaluations_over_boolean_hypercube_for_eq(&alpha, 1 << alpha.len());
        let (ad_a, ad_b, ad_c, _) = run_ad(
            binary,
            &eq_alpha[..constraints_layout.size()],
            witness_layout,
            constraints_layout,
        )?;
        let alphas = [ad_a, ad_b, ad_c];

        let blinding_weights = expand_powers::<4, _>(&alpha);

        prove_from_alphas(
            self,
            merlin,
            alphas,
            blinding_eval,
            blinding_weights,
            commitments,
            public_inputs,
        )
    }
}
