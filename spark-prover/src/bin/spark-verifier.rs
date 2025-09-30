use {
    anyhow::{ensure, Context, Result},
    ark_std::{One, Zero},
    provekit_common::{
        skyscraper::SkyscraperSponge, spark::SPARKRequest, utils::{
            next_power_of_two,
            sumcheck::{calculate_eq, eval_cubic_poly},
        }, FieldElement, IOPattern, WhirConfig
    },
    spark_prover::utilities::SPARKProof,
    spongefish::{
        codecs::arkworks_algebra::{FieldToUnitDeserialize, UnitToField},
        VerifierState,
    },
    std::fs::{self, File},
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

fn main() -> Result<()> {
    let spark_proof_json_str = fs::read_to_string("spark-prover/spark_proof.json")
        .context("Error: Failed to open the r1cs.json file")?;
    let spark_proof: SPARKProof = serde_json::from_str(&spark_proof_json_str)
        .context("Error: Failed to deserialize JSON to R1CS")?;

    let request_json_str = fs::read_to_string("spark-prover/request.json")
        .context("Error: Failed to open the r1cs.json file")?;
    let request: SPARKRequest = serde_json::from_str(&request_json_str)
        .context("Error: Failed to deserialize JSON to R1CS")?;

    let io = IOPattern::from_string(spark_proof.io_pattern.clone());
    let mut arthur = io.to_verifier_state(&spark_proof.transcript);

    let claimed_a: FieldElement = arthur.hint()?;
    let claimed_b: FieldElement = arthur.hint()?;
    let claimed_c: FieldElement = arthur.hint()?;
    let point_row: Vec<FieldElement> = arthur.hint()?;
    let point_col: Vec<FieldElement> = arthur.hint()?;

    verify_spark_single_matrix(
        &spark_proof.whir_params.row, 
        &spark_proof.whir_params.col, 
        &spark_proof.whir_params.a_3batched, 
        spark_proof.matrix_dimensions.num_rows,
        spark_proof.matrix_dimensions.num_cols,
        spark_proof.matrix_dimensions.a_nonzero_terms,
        &mut arthur, 
        &request,
        &request.claimed_values.a,
    )?;

    verify_spark_single_matrix(
        &spark_proof.whir_params.row, 
        &spark_proof.whir_params.col, 
        &spark_proof.whir_params.b_3batched, 
        spark_proof.matrix_dimensions.num_rows,
        spark_proof.matrix_dimensions.num_cols,
        spark_proof.matrix_dimensions.b_nonzero_terms,
        &mut arthur, 
        &request,
        &request.claimed_values.b,
    )?;

    verify_spark_single_matrix(
        &spark_proof.whir_params.row, 
        &spark_proof.whir_params.col, 
        &spark_proof.whir_params.c_3batched, 
        spark_proof.matrix_dimensions.num_rows,
        spark_proof.matrix_dimensions.num_cols,
        spark_proof.matrix_dimensions.c_nonzero_terms,
        &mut arthur, 
        &request,
        &request.claimed_values.c,
    )?;    

    Ok(())
}

pub fn verify_spark_single_matrix(
    row_config: &WhirConfig,
    col_config: &WhirConfig,
    num_nonzero_term_batched3_config: &WhirConfig,
    num_rows: usize,
    num_cols: usize,
    num_nonzero_terms: usize,
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    request: &SPARKRequest,
    claimed_value: &FieldElement,
) -> Result<()> {
    let commitment_reader_row = CommitmentReader::new(row_config);
    let commitment_reader_col = CommitmentReader::new(col_config);
    
    // Matrix A

    let a_3batched_commitment_reader = CommitmentReader::new(num_nonzero_term_batched3_config);

    let a_sumcheck_commitment = a_3batched_commitment_reader.parse_commitment(arthur)?;
    let a_rowwise_commitment = a_3batched_commitment_reader.parse_commitment(arthur)?;
    let a_colwise_commitment = a_3batched_commitment_reader.parse_commitment(arthur)?;
    
    let a_row_finalts_commitment = commitment_reader_row.parse_commitment(arthur).unwrap();
    let a_col_finalts_commitment = commitment_reader_col.parse_commitment(arthur).unwrap();

    // Matrix A - Sumcheck 

    let (randomness, a_last_sumcheck_value) = run_sumcheck_verifier_spark(
        arthur,
        next_power_of_two(num_nonzero_terms),
        *claimed_value,
    )
    .context("While verifying SPARK sumcheck")?;

    let final_folds: Vec<FieldElement> = arthur.hint()?;

    assert!(a_last_sumcheck_value == final_folds[0] * final_folds[1] * final_folds[2]);

    let mut a_spark_sumcheck_statement_verifier = Statement::<FieldElement>::new(next_power_of_two(
        num_nonzero_terms,
    ));

    a_spark_sumcheck_statement_verifier.add_constraint(
        Weights::evaluation(MultilinearPoint(randomness.clone())),
        final_folds[0] + 
            final_folds[1] * a_sumcheck_commitment.batching_randomness +
            final_folds[2] * a_sumcheck_commitment.batching_randomness * a_sumcheck_commitment.batching_randomness,
    );

    let a_spark_sumcheck_verifier = Verifier::new(num_nonzero_term_batched3_config);
    a_spark_sumcheck_verifier.verify(arthur, &a_sumcheck_commitment, &a_spark_sumcheck_statement_verifier)?;

    // Matrix A - Rowwise 

    let mut tau_and_gamma = [FieldElement::from(0); 2];
    arthur.fill_challenge_scalars(&mut tau_and_gamma)?;
    let tau = tau_and_gamma[0];
    let gamma = tau_and_gamma[1];

    let gpa_result = gpa_sumcheck_verifier(
        arthur,
        next_power_of_two(num_rows) + 2,
    )?;

    let claimed_init = gpa_result.claimed_values[0];
    let claimed_final = gpa_result.claimed_values[1];

    let (last_randomness, evaluation_randomness) = gpa_result.randomness.split_at(1);

    let init_adr = calculate_adr(&evaluation_randomness.to_vec());
    let init_mem = calculate_eq(
        &request.point_to_evaluate.row,
        &evaluation_randomness.to_vec(),
    );
    let init_cntr = FieldElement::from(0);

    let init_opening = init_adr * gamma * gamma + init_mem * gamma + init_cntr - tau;
    let final_cntr: FieldElement = arthur.hint()?;

    let mut final_cntr_statement =
        Statement::<FieldElement>::new(next_power_of_two(num_rows));
    final_cntr_statement.add_constraint(
        Weights::evaluation(MultilinearPoint(evaluation_randomness.to_vec().clone())),
        final_cntr,
    );

    let final_cntr_verifier = Verifier::new(row_config);
    final_cntr_verifier
        .verify(arthur, &a_row_finalts_commitment, &final_cntr_statement)
        .context("while verifying WHIR")?;

    let final_adr = calculate_adr(&evaluation_randomness.to_vec());
    let final_mem = calculate_eq(
        &request.point_to_evaluate.row,
        &evaluation_randomness.to_vec(),
    );

    let final_opening = final_adr * gamma * gamma + final_mem * gamma + final_cntr - tau;

    let evaluated_value = init_opening * (FieldElement::one() - last_randomness[0])
        + final_opening * last_randomness[0];

    ensure!(evaluated_value == gpa_result.a_last_sumcheck_value);

    let gpa_result = gpa_sumcheck_verifier(
        arthur,
        next_power_of_two(num_nonzero_terms) + 2,
    )?;

    let (last_randomness, evaluation_randomness) = gpa_result.randomness.split_at(1);

    let claimed_rs = gpa_result.claimed_values[0];
    let claimed_ws = gpa_result.claimed_values[1];

    let rs_adr: FieldElement = arthur.hint()?;
    let rs_mem: FieldElement = arthur.hint()?;
    let rs_timestamp: FieldElement = arthur.hint()?;

    let rs_opening = rs_adr * gamma * gamma + rs_mem * gamma + rs_timestamp - tau;
    let ws_opening = rs_adr * gamma * gamma + rs_mem * gamma + rs_timestamp + FieldElement::from(1) - tau;
    
    let evaluated_value = rs_opening * (FieldElement::one() - last_randomness[0])
        + ws_opening * last_randomness[0];

    ensure!(evaluated_value == gpa_result.a_last_sumcheck_value);

    let mut a_spark_rowwise_statement_verifier = Statement::<FieldElement>::new(next_power_of_two(
        num_nonzero_terms,
    ));

    a_spark_rowwise_statement_verifier.add_constraint(
        Weights::evaluation(MultilinearPoint(evaluation_randomness.to_vec().clone())),
        rs_adr + 
            rs_mem * a_rowwise_commitment.batching_randomness +
            rs_timestamp * a_rowwise_commitment.batching_randomness * a_rowwise_commitment.batching_randomness,
    );

    a_spark_sumcheck_verifier.verify(arthur, &a_rowwise_commitment, &a_spark_rowwise_statement_verifier)?;

    ensure!(claimed_init * claimed_ws == claimed_rs * claimed_final);

    // Matrix A - Colwise

    let mut tau_and_gamma = [FieldElement::from(0); 2];
    arthur.fill_challenge_scalars(&mut tau_and_gamma)?;
    let tau = tau_and_gamma[0];
    let gamma = tau_and_gamma[1];

    // Colwise Init Final GPA

    let gpa_result = gpa_sumcheck_verifier(
        arthur,
        next_power_of_two(num_cols) + 2,
    )?;

    let claimed_init = gpa_result.claimed_values[0];
    let claimed_final = gpa_result.claimed_values[1];

    let (last_randomness, evaluation_randomness) = gpa_result.randomness.split_at(1);

    let init_adr = calculate_adr(&evaluation_randomness.to_vec());
    let init_mem = calculate_eq(
        &request.point_to_evaluate.col[1..],
        &evaluation_randomness.to_vec(),
    ) * (FieldElement::from(1) - request.point_to_evaluate.col[0]);
    let init_cntr = FieldElement::from(0);

    let init_opening = init_adr * gamma * gamma + init_mem * gamma + init_cntr - tau;

    let final_cntr: FieldElement = arthur.hint()?;

    let mut final_cntr_statement =
        Statement::<FieldElement>::new(next_power_of_two(num_cols));
    final_cntr_statement.add_constraint(
        Weights::evaluation(MultilinearPoint(evaluation_randomness.to_vec().clone())),
        final_cntr,
    );

    let final_cntr_verifier = Verifier::new(col_config);
    final_cntr_verifier
        .verify(arthur, &a_col_finalts_commitment, &final_cntr_statement)
        .context("while verifying WHIR")?;

    let final_adr = calculate_adr(&evaluation_randomness.to_vec());
    let final_mem = calculate_eq(
        &request.point_to_evaluate.col[1..],
        &evaluation_randomness.to_vec(),
    ) * (FieldElement::from(1) - request.point_to_evaluate.col[0]);

    let final_opening = final_adr * gamma * gamma + final_mem * gamma + final_cntr - tau;

    let evaluated_value = init_opening * (FieldElement::one() - last_randomness[0])
        + final_opening * last_randomness[0];

    ensure!(evaluated_value == gpa_result.a_last_sumcheck_value);

    // Colwise RS WS GPA

    let gpa_result = gpa_sumcheck_verifier(
        arthur,
        next_power_of_two(num_nonzero_terms) + 2,
    )?;

    let (last_randomness, evaluation_randomness) = gpa_result.randomness.split_at(1);

    let claimed_rs = gpa_result.claimed_values[0];
    let claimed_ws = gpa_result.claimed_values[1];

    let rs_adr: FieldElement = arthur.hint()?;
    let rs_mem: FieldElement = arthur.hint()?;
    let rs_timestamp: FieldElement = arthur.hint()?;

    let rs_opening = rs_adr * gamma * gamma + rs_mem * gamma + rs_timestamp - tau;
    let ws_opening = rs_adr * gamma * gamma + rs_mem * gamma + rs_timestamp + FieldElement::from(1) - tau;
    
    let evaluated_value = rs_opening * (FieldElement::one() - last_randomness[0])
        + ws_opening * last_randomness[0];

    ensure!(evaluated_value == gpa_result.a_last_sumcheck_value);

    let mut a_spark_colwise_statement_verifier = Statement::<FieldElement>::new(next_power_of_two(
        num_nonzero_terms,
    ));

    a_spark_colwise_statement_verifier.add_constraint(
        Weights::evaluation(MultilinearPoint(evaluation_randomness.to_vec().clone())),
        rs_adr + 
            rs_mem * a_colwise_commitment.batching_randomness +
            rs_timestamp * a_colwise_commitment.batching_randomness * a_colwise_commitment.batching_randomness,
    );

    a_spark_sumcheck_verifier.verify(arthur, &a_colwise_commitment, &a_spark_colwise_statement_verifier)?;

    ensure!(claimed_init * claimed_ws == claimed_rs * claimed_final);

    Ok(())
}

pub fn run_sumcheck_verifier_spark(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    variable_count: usize,
    initial_sumcheck_val: FieldElement,
) -> Result<(Vec<FieldElement>, FieldElement)> {
    let mut saved_val_for_sumcheck_equality_assertion = initial_sumcheck_val;

    let mut alpha = vec![FieldElement::zero(); variable_count];

    for i in 0..variable_count {
        let mut hhat_i = [FieldElement::zero(); 4];
        let mut alpha_i = [FieldElement::zero(); 1];
        let _ = arthur.fill_next_scalars(&mut hhat_i);
        let _ = arthur.fill_challenge_scalars(&mut alpha_i);
        alpha[i] = alpha_i[0];

        let hhat_i_at_zero = eval_cubic_poly(&hhat_i, &FieldElement::zero());
        let hhat_i_at_one = eval_cubic_poly(&hhat_i, &FieldElement::one());
        ensure!(
            saved_val_for_sumcheck_equality_assertion == hhat_i_at_zero + hhat_i_at_one,
            "Sumcheck equality assertion failed"
        );
        saved_val_for_sumcheck_equality_assertion = eval_cubic_poly(&hhat_i, &alpha_i[0]);
    }

    Ok((alpha, saved_val_for_sumcheck_equality_assertion))
}

pub fn gpa_sumcheck_verifier(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    height_of_binary_tree: usize,
) -> Result<GPASumcheckResult> {
    let mut prev_rand = Vec::<FieldElement>::new();
    let mut rand = Vec::<FieldElement>::new();
    let mut claimed_values = [FieldElement::from(0); 2];
    let mut l = [FieldElement::from(0); 2];
    let mut r = [FieldElement::from(0); 1];
    let mut h = [FieldElement::from(0); 4];
    let mut alpha = [FieldElement::from(0); 1];

    arthur
        .fill_next_scalars(&mut claimed_values)
        .expect("Failed to fill next scalars");
    arthur
        .fill_challenge_scalars(&mut r)
        .expect("Failed to fill next scalars");
    let mut a_last_sumcheck_value = eval_linear_poly(&claimed_values, &r[0]);
    rand.push(r[0]);
    prev_rand = rand;
    rand = Vec::<FieldElement>::new();

    for i in 1..(height_of_binary_tree - 1) {
        for _ in 0..i {
            arthur
                .fill_next_scalars(&mut h)
                .expect("Failed to fill next scalars");
            arthur
                .fill_challenge_scalars(&mut alpha)
                .expect("Failed to fill next scalars");
            assert_eq!(
                eval_cubic_poly(&h, &FieldElement::from(0))
                    + eval_cubic_poly(&h, &FieldElement::from(1)),
                a_last_sumcheck_value
            );
            rand.push(alpha[0]);
            a_last_sumcheck_value = eval_cubic_poly(&h, &alpha[0]);
        }
        arthur
            .fill_next_scalars(&mut l)
            .expect("Failed to fill next scalars");
        arthur
            .fill_challenge_scalars(&mut r)
            .expect("Failed to fill next scalars");
        let claimed_last_sch = calculate_eq(&prev_rand, &rand)
            * eval_linear_poly(&l, &FieldElement::from(0))
            * eval_linear_poly(&l, &FieldElement::from(1));
        assert_eq!(claimed_last_sch, a_last_sumcheck_value);
        rand.push(r[0]);
        prev_rand = rand;
        rand = Vec::<FieldElement>::new();
        a_last_sumcheck_value = eval_linear_poly(&l, &r[0]);
    }

    Ok(GPASumcheckResult {
        claimed_values: claimed_values.to_vec(),
        a_last_sumcheck_value,
        randomness: prev_rand,
    })
}

pub struct GPASumcheckResult {
    pub claimed_values:      Vec<FieldElement>,
    pub a_last_sumcheck_value: FieldElement,
    pub randomness:          Vec<FieldElement>,
}

pub fn eval_linear_poly(poly: &[FieldElement], point: &FieldElement) -> FieldElement {
    poly[0] + *point * poly[1]
}

pub fn calculate_adr(alpha: &Vec<FieldElement>) -> FieldElement {
    let mut ans = FieldElement::from(0);
    let mut mult = FieldElement::from(1);
    for a in alpha.iter().rev() {
        ans = ans + *a * mult;
        mult = mult * FieldElement::from(2);
    }
    ans
}
