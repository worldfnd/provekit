use {
    anyhow::{ensure, Context, Result},
    ark_std::{One, Zero},
    provekit_common::{
        skyscraper::SkyscraperSponge,
        utils::sumcheck::{calculate_eq, eval_cubic_poly},
        FieldElement, WhirConfig, WhirR1CSProof, WhirR1CSScheme,
    },
    spongefish::{
        codecs::arkworks_algebra::{FieldToUnitDeserialize, UnitToField},
        VerifierState,
    },
    tracing::instrument,
    whir::{
        poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint},
        whir::{
            committer::{reader::ParsedCommitment, CommitmentReader},
            statement::{Statement, Weights},
            utils::HintDeserialize,
            verifier::Verifier,
        },
    },
};

pub struct DataFromSumcheckVerifier {
    r:                 Vec<FieldElement>,
    alpha:             Vec<FieldElement>,
    last_sumcheck_val: FieldElement,
}

pub trait WhirR1CSVerifier {
    fn verify(&self, proof: &WhirR1CSProof) -> Result<()>;
}

impl WhirR1CSVerifier for WhirR1CSScheme {
    #[instrument(skip_all)]
    #[allow(unused)] // TODO: Fix implementation
    fn verify(&self, proof: &WhirR1CSProof) -> Result<()> {
        // Set up transcript
        let io = self.create_io_pattern();
        let mut arthur = io.to_verifier_state(&proof.transcript);

        let commitment_reader = CommitmentReader::new(&self.whir_witness);
        let parsed_commitment = commitment_reader.parse_commitment(&mut arthur).unwrap();

        let data_from_sumcheck_verifier = run_sumcheck_verifier(
            &mut arthur,
            self.m_0,
            &self.whir_for_hiding_spartan,
            // proof.whir_spartan_blinding_values,
        )
        .context("while verifying sumcheck")?;

        let whir_query_answer_sum_vectors: (Vec<FieldElement>, Vec<FieldElement>) =
            arthur.hint().unwrap();

        let whir_query_answer_sums = (
            whir_query_answer_sum_vectors.0.try_into().unwrap(),
            whir_query_answer_sum_vectors.1.try_into().unwrap(),
        );

        let statement_verifier = prepare_statement_for_witness_verifier::<3>(
            self.m,
            &parsed_commitment,
            &whir_query_answer_sums,
        );

        let (folding_randomness, deferred) = run_whir_pcs_verifier(
            &mut arthur,
            &parsed_commitment,
            &self.whir_witness,
            &statement_verifier,
        )
        .context("while verifying WHIR proof")?;

        // Check the Spartan sumcheck relation.
        ensure!(
            data_from_sumcheck_verifier.last_sumcheck_val
                == (whir_query_answer_sums.0[0] * whir_query_answer_sums.0[1]
                    - whir_query_answer_sums.0[2])
                    * calculate_eq(
                        &data_from_sumcheck_verifier.r,
                        &data_from_sumcheck_verifier.alpha
                    ),
            "last sumcheck value does not match"
        );

        Ok(())
    }
}

fn prepare_statement_for_witness_verifier<const N: usize>(
    m: usize,
    parsed_commitment: &ParsedCommitment<FieldElement, FieldElement>,
    whir_query_answer_sums: &([FieldElement; N], [FieldElement; N]),
) -> Statement<FieldElement> {
    let mut statement_verifier = Statement::<FieldElement>::new(m);
    for i in 0..whir_query_answer_sums.0.len() {
        let claimed_sum = whir_query_answer_sums.0[i]
            + whir_query_answer_sums.1[i] * parsed_commitment.batching_randomness;
        statement_verifier.add_constraint(
            Weights::linear(EvaluationsList::new(vec![FieldElement::zero(); 1 << m])),
            claimed_sum,
        );
    }
    statement_verifier
}

#[instrument(skip_all)]
pub fn run_sumcheck_verifier(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    m_0: usize,
    whir_for_spartan_blinding_config: &WhirConfig,
) -> Result<DataFromSumcheckVerifier> {
    // r is the combination randomness from the 2nd item of the interaction phase
    let mut r = vec![FieldElement::zero(); m_0];
    let _ = arthur.fill_challenge_scalars(&mut r);

    let commitment_reader = CommitmentReader::new(whir_for_spartan_blinding_config);
    let parsed_commitment = commitment_reader.parse_commitment(arthur).unwrap();

    let mut sum_g_buf = [FieldElement::zero()];
    arthur.fill_next_scalars(&mut sum_g_buf)?;

    let mut rho_buf = [FieldElement::zero()];
    arthur.fill_challenge_scalars(&mut rho_buf)?;
    let rho = rho_buf[0];

    let mut saved_val_for_sumcheck_equality_assertion = rho * sum_g_buf[0];

    let mut alpha = vec![FieldElement::zero(); m_0];

    for item in alpha.iter_mut().take(m_0) {
        let mut hhat_i = [FieldElement::zero(); 4];
        let mut alpha_i = [FieldElement::zero(); 1];
        let _ = arthur.fill_next_scalars(&mut hhat_i);
        let _ = arthur.fill_challenge_scalars(&mut alpha_i);
        *item = alpha_i[0];
        let hhat_i_at_zero = eval_cubic_poly(hhat_i, FieldElement::zero());
        let hhat_i_at_one = eval_cubic_poly(hhat_i, FieldElement::one());
        ensure!(
            saved_val_for_sumcheck_equality_assertion == hhat_i_at_zero + hhat_i_at_one,
            "Sumcheck equality assertion failed"
        );
        saved_val_for_sumcheck_equality_assertion = eval_cubic_poly(hhat_i, alpha_i[0]);
    }
    let mut values_of_polynomial_sums = [FieldElement::zero(); 2];
    let _ = arthur.fill_next_scalars(&mut values_of_polynomial_sums);

    let statement_verifier = prepare_statement_for_witness_verifier::<1>(
        whir_for_spartan_blinding_config.mv_parameters.num_variables,
        &parsed_commitment,
        &([values_of_polynomial_sums[0]], [
            values_of_polynomial_sums[1]
        ]),
    );
    run_whir_pcs_verifier(
        arthur,
        &parsed_commitment,
        whir_for_spartan_blinding_config,
        &statement_verifier,
    )
    .context("while verifying WHIR")?;

    let f_at_alpha = saved_val_for_sumcheck_equality_assertion - rho * values_of_polynomial_sums[0];

    Ok(DataFromSumcheckVerifier {
        r,
        alpha,
        last_sumcheck_val: f_at_alpha,
    })
}

#[instrument(skip_all)]
pub fn run_whir_pcs_verifier(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    parsed_commitment: &ParsedCommitment<FieldElement, FieldElement>,
    params: &WhirConfig,
    statement_verifier: &Statement<FieldElement>,
) -> Result<(MultilinearPoint<FieldElement>, Vec<FieldElement>)> {
    let verifier = Verifier::new(params);

    let (folding_randomness, deferred) = verifier
        .verify(arthur, parsed_commitment, statement_verifier)
        .context("while verifying WHIR")?;

    Ok((folding_randomness, deferred))
}
