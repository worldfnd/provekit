use {
    crate::{
        gpa::gpa_sumcheck_verifier4, memory::{verify_colwise, verify_rowwise}, sumcheck::run_sumcheck_verifier_spark, types::{MatrixDimensions, SPARKProof, SPARKWHIRConfigs}
    },
    anyhow::{ensure, Context, Result},
    provekit_common::{
        skyscraper::SkyscraperSponge, spark::SparkStatement, utils::next_power_of_two,
        FieldElement, IOPattern,
    },
    spongefish::codecs::arkworks_algebra::{FieldToUnitDeserialize, UnitToField},
    whir::{
        poly_utils::multilinear::MultilinearPoint,
        whir::{
            committer::CommitmentReader,
            statement::{Statement, Weights},
            utils::HintDeserialize,
            verifier::Verifier,
        },
    },
};

/// SPARK verification interface.
pub trait SPARKVerifier {
    /// Verifies a SPARK proof against the given request.
    fn verify(&self, proof: &SPARKProof, request: &SparkStatement) -> Result<()>;
}

/// SPARK verification scheme with configuration extracted from proof.
pub struct SPARKScheme {
    pub whir_configs:      SPARKWHIRConfigs,
    pub io_pattern:        IOPattern,
    pub matrix_dimensions: MatrixDimensions,
}

impl SPARKScheme {
    /// Constructs verifier scheme from proof metadata.
    pub fn from_proof(proof: &SPARKProof) -> Self {
        Self {
            whir_configs:      proof.whir_params.clone(),
            io_pattern:        IOPattern::from_string(proof.io_pattern.clone()),
            matrix_dimensions: proof.matrix_dimensions.clone(),
        }
    }
}

impl SPARKVerifier for SPARKScheme {
    fn verify(&self, proof: &SPARKProof, request: &SparkStatement) -> Result<()> {
        let io = IOPattern::from_string(proof.io_pattern.clone());
        let mut arthur = io.to_verifier_state(&proof.transcript);

        let _point_row: Vec<FieldElement> = arthur.hint()?;
        let _point_col: Vec<FieldElement> = arthur.hint()?;

        let mut claimed_values = [FieldElement::from(0); 3];
        arthur.fill_next_scalars(&mut claimed_values)?;

        let mut matrix_batching_randomness = [FieldElement::from(0); 1];
        arthur.fill_challenge_scalars(&mut matrix_batching_randomness)?;
        let matrix_batching_randomness = matrix_batching_randomness[0];

        let claimed_value = claimed_values[0]
            + claimed_values[1] * matrix_batching_randomness
            + claimed_values[2] * matrix_batching_randomness * matrix_batching_randomness;

        verify_spark_single_matrix(
            &matrix_batching_randomness,
            &proof.whir_params,
            proof.matrix_dimensions.clone(),
            &mut arthur,
            request,
            &claimed_value,
        )
    }
}

/// Core SPARK verification: sumcheck + row/col memory checks.
fn verify_spark_single_matrix(
    matrix_batching_randomness: &FieldElement,
    whir_params: &SPARKWHIRConfigs,
    matrix_dimensions: MatrixDimensions,
    arthur: &mut spongefish::VerifierState<SkyscraperSponge, FieldElement>,
    request: &SparkStatement,
    claimed_value: &FieldElement,
) -> Result<()> {
    let commitment_reader_row = CommitmentReader::new(&whir_params.row);
    let commitment_reader_col = CommitmentReader::new(&whir_params.col);
    let commitment_reader_batched2 = CommitmentReader::new(&whir_params.num_terms_2batched);
    let commitment_reader_batched3 = CommitmentReader::new(&whir_params.num_terms_3batched);
    let commitment_reader_batched4 = CommitmentReader::new(&whir_params.num_terms_4batched);

    let val_commitment = commitment_reader_batched3.parse_commitment(arthur)?;
    let rsws_commitment = commitment_reader_batched4.parse_commitment(arthur)?;
    let a_row_finalts_commitment = commitment_reader_row.parse_commitment(arthur)?;
    let a_col_finalts_commitment = commitment_reader_col.parse_commitment(arthur)?;
    
    let evalues_commitment = commitment_reader_batched2.parse_commitment(arthur)?;

    let (randomness, a_last_sumcheck_value) = run_sumcheck_verifier_spark(
        arthur,
        next_power_of_two(matrix_dimensions.nonzero_terms),
        *claimed_value,
    )
    .context("While verifying SPARK sumcheck")?;

    let sumcheck_hints: Vec<FieldElement> = arthur.hint()?;

    let claimed_val = 
          sumcheck_hints[0]
        + sumcheck_hints[1] * matrix_batching_randomness
        + sumcheck_hints[2] * matrix_batching_randomness * matrix_batching_randomness;
    ensure!(a_last_sumcheck_value == claimed_val * sumcheck_hints[3] * sumcheck_hints[4]);

    let mut sumcheck_evalues_statement =
        Statement::<FieldElement>::new(next_power_of_two(matrix_dimensions.nonzero_terms));

    sumcheck_evalues_statement.add_constraint(
        Weights::evaluation(MultilinearPoint(randomness.clone())),
        sumcheck_hints[3] + 
            sumcheck_hints[4] * evalues_commitment.batching_randomness
    );

    let sumcheck_evalues_verifier = Verifier::new(&whir_params.num_terms_2batched);
    sumcheck_evalues_verifier.verify(
        arthur,
        &evalues_commitment,
        &sumcheck_evalues_statement,
    )?;

    let mut spark_sumcheck_val_statement_verifier =
        Statement::<FieldElement>::new(next_power_of_two(matrix_dimensions.nonzero_terms));

    spark_sumcheck_val_statement_verifier.add_constraint(
        Weights::evaluation(MultilinearPoint(randomness.clone())),
        sumcheck_hints[0] + 
            sumcheck_hints[1] * val_commitment.batching_randomness + 
            sumcheck_hints[2] * val_commitment.batching_randomness * val_commitment.batching_randomness
    );

    let spark_sumcheck_val_verifier = Verifier::new(&whir_params.num_terms_3batched);
    spark_sumcheck_val_verifier.verify(
        arthur,
        &val_commitment,
        &spark_sumcheck_val_statement_verifier,
    )?;

    let mut tau_and_gamma = [FieldElement::from(0); 2];
    arthur.fill_challenge_scalars(&mut tau_and_gamma)?;
    let tau = tau_and_gamma[0];
    let gamma = tau_and_gamma[1];

    let gpa_result = gpa_sumcheck_verifier4(
        arthur,
        provekit_common::utils::next_power_of_two(matrix_dimensions.nonzero_terms) + 3,
    )?;

    let (combination_randomness, evaluation_randomness) = gpa_result.randomness.split_at(2);
    
    let claimed_row_rs = gpa_result.claimed_values[0];
    let claimed_row_ws = gpa_result.claimed_values[1];
    let claimed_col_rs = gpa_result.claimed_values[2];
    let claimed_col_ws = gpa_result.claimed_values[3];

    let row_adr: FieldElement = arthur.hint()?;
    let row_timestamp: FieldElement = arthur.hint()?;
    let col_adr: FieldElement = arthur.hint()?;
    let col_timestamp: FieldElement = arthur.hint()?;

    let mut rsws_statement = Statement::<FieldElement>::new(provekit_common::utils::next_power_of_two(
        matrix_dimensions.nonzero_terms,
    ));
    rsws_statement.add_constraint(
        Weights::evaluation(MultilinearPoint(evaluation_randomness.to_vec())),
        row_adr + 
            row_timestamp * rsws_commitment.batching_randomness +
            col_adr * rsws_commitment.batching_randomness * rsws_commitment.batching_randomness +
            col_timestamp * rsws_commitment.batching_randomness * rsws_commitment.batching_randomness * rsws_commitment.batching_randomness
    );
    let rsws_verifier = Verifier::new(&whir_params.num_terms_4batched);
    rsws_verifier.verify(arthur, &rsws_commitment, &rsws_statement)?;

    let row_mem: FieldElement = arthur.hint()?;
    let col_mem: FieldElement = arthur.hint()?;

    let mut evalues_statement = Statement::<FieldElement>::new(provekit_common::utils::next_power_of_two(
        matrix_dimensions.nonzero_terms,
    ));
    evalues_statement.add_constraint(
        Weights::evaluation(MultilinearPoint(evaluation_randomness.to_vec())),
        row_mem + 
            col_mem * evalues_commitment.batching_randomness
    );
    let evalues_verifier = Verifier::new(&whir_params.num_terms_2batched);
    evalues_verifier.verify(arthur, &evalues_commitment, &evalues_statement)?;

    let row_rs_opening = row_adr * gamma * gamma + row_mem * gamma + row_timestamp - tau;
    let row_ws_opening = row_adr * gamma * gamma + row_mem * gamma + row_timestamp + FieldElement::from(1) - tau;
    let col_rs_opening = col_adr * gamma * gamma + col_mem * gamma + col_timestamp - tau;
    let col_ws_opening = col_adr * gamma * gamma + col_mem * gamma + col_timestamp + FieldElement::from(1) - tau;
    
    let evaluated_value =
        row_rs_opening * (FieldElement::from(1) - combination_randomness[0]) * (FieldElement::from(1) - combination_randomness[1]) +
        row_ws_opening * (FieldElement::from(1) - combination_randomness[0]) * combination_randomness[1] +
        col_rs_opening * combination_randomness[0] * (FieldElement::from(1) - combination_randomness[1]) +
        col_ws_opening * combination_randomness[0] * combination_randomness[1]; 

    ensure!(evaluated_value == gpa_result.a_last_sumcheck_value);

    verify_rowwise(
        arthur,
        matrix_dimensions.num_rows,
        whir_params,
        request,
        a_row_finalts_commitment,
        &tau,
        &gamma,
        &claimed_row_rs,
        &claimed_row_ws,
    )?;

    verify_colwise(
        arthur,
        matrix_dimensions.num_cols,
        whir_params,
        request,
        a_col_finalts_commitment,
        &tau,
        &gamma,
        &claimed_col_rs,
        &claimed_col_ws,
    )?;

    Ok(())
}
