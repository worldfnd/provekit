use {
    anyhow::{ensure, Context, Result},
    ark_std::{One, Zero},
    provekit_common::{
        skyscraper::SkyscraperSponge,
        utils::{
            next_power_of_two,
            sumcheck::{calculate_eq, eval_cubic_poly},
        },
        FieldElement, IOPattern,
    },
    spark_prover::utilities::{SPARKProof, SPARKRequest},
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

    let io = IOPattern::from_string(spark_proof.io_pattern);
    let mut arthur = io.to_verifier_state(&spark_proof.transcript);

    let commitment_reader = CommitmentReader::new(&spark_proof.whir_params.a);
    let commitment_reader_row = CommitmentReader::new(&spark_proof.whir_params.row);

    let val_commitment = commitment_reader.parse_commitment(&mut arthur).unwrap();
    let e_rx_commitment = commitment_reader.parse_commitment(&mut arthur).unwrap();
    let e_ry_commitment = commitment_reader.parse_commitment(&mut arthur).unwrap();
    let final_row_commitment = commitment_reader_row.parse_commitment(&mut arthur).unwrap();
    let row_commitment = commitment_reader.parse_commitment(&mut arthur).unwrap();
    let read_ts_commitment = commitment_reader.parse_commitment(&mut arthur).unwrap();

    let (randomness, last_sumcheck_value) = run_sumcheck_verifier_spark(
        &mut arthur,
        next_power_of_two(spark_proof.matrix_dimensions.a_nonzero_terms),
        request.claimed_values.a,
    )
    .context("While verifying SPARK sumcheck")?;

    let final_folds: Vec<FieldElement> = arthur.hint()?;

    let mut val_statement_verifier = Statement::<FieldElement>::new(next_power_of_two(
        spark_proof.matrix_dimensions.a_nonzero_terms,
    ));
    val_statement_verifier.add_constraint(
        Weights::evaluation(MultilinearPoint(randomness.clone())),
        final_folds[0],
    );
    let val_verifier = Verifier::new(&spark_proof.whir_params.a);
    val_verifier
        .verify(&mut arthur, &val_commitment, &val_statement_verifier)
        .context("while verifying WHIR")?;

    let mut e_rx_statement_verifier = Statement::<FieldElement>::new(next_power_of_two(
        spark_proof.matrix_dimensions.a_nonzero_terms,
    ));
    e_rx_statement_verifier.add_constraint(
        Weights::evaluation(MultilinearPoint(randomness.clone())),
        final_folds[1],
    );
    let e_rx_verifier = Verifier::new(&spark_proof.whir_params.a);
    e_rx_verifier
        .verify(&mut arthur, &e_rx_commitment, &e_rx_statement_verifier)
        .context("while verifying WHIR")?;

    let mut e_ry_statement_verifier = Statement::<FieldElement>::new(next_power_of_two(
        spark_proof.matrix_dimensions.a_nonzero_terms,
    ));
    e_ry_statement_verifier.add_constraint(
        Weights::evaluation(MultilinearPoint(randomness.clone())),
        final_folds[2],
    );
    let e_ry_verifier = Verifier::new(&spark_proof.whir_params.a);
    e_ry_verifier
        .verify(&mut arthur, &e_ry_commitment, &e_ry_statement_verifier)
        .context("while verifying WHIR")?;

    let mut tau_and_gamma = [FieldElement::from(0); 2];
    arthur.fill_challenge_scalars(&mut tau_and_gamma)?;
    let tau = tau_and_gamma[0];
    let gamma = tau_and_gamma[1];

    let gpa_result = gpa_sumcheck_verifier(
        &mut arthur,
        next_power_of_two(spark_proof.matrix_dimensions.num_rows) + 2,
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

    let mut final_cntr: FieldElement = arthur.hint()?;

    let mut final_cntr_statement =
        Statement::<FieldElement>::new(next_power_of_two(spark_proof.matrix_dimensions.num_rows));
    final_cntr_statement.add_constraint(
        Weights::evaluation(MultilinearPoint(evaluation_randomness.to_vec().clone())),
        final_cntr,
    );

    let final_cntr_verifier = Verifier::new(&spark_proof.whir_params.row);
    final_cntr_verifier
        .verify(&mut arthur, &final_row_commitment, &final_cntr_statement)
        .context("while verifying WHIR")?;

    let final_adr = calculate_adr(&evaluation_randomness.to_vec());
    let final_mem = calculate_eq(
        &request.point_to_evaluate.row,
        &evaluation_randomness.to_vec(),
    );

    let final_opening = final_adr * gamma * gamma + final_mem * gamma + final_cntr - tau;

    let evaluated_value = init_opening * (FieldElement::one() - last_randomness[0])
        + final_opening * last_randomness[0];

    ensure!(evaluated_value == gpa_result.last_sumcheck_value);

    // let mut rs_address: FieldElement = arthur.hint()?;
    let gpa_result = gpa_sumcheck_verifier(
        &mut arthur,
        next_power_of_two(spark_proof.matrix_dimensions.a_nonzero_terms) + 2,
    )?;

    let claimed_rs = gpa_result.claimed_values[0];
    let claimed_ws = gpa_result.claimed_values[1];

    let (last_randomness, evaluation_randomness) = gpa_result.randomness.split_at(1);

    let rs_adr = arthur.hint()?;

    let mut rs_adr_statement = Statement::<FieldElement>::new(next_power_of_two(
        spark_proof.matrix_dimensions.a_nonzero_terms,
    ));
    rs_adr_statement.add_constraint(
        Weights::evaluation(MultilinearPoint(evaluation_randomness.to_vec().clone())),
        rs_adr,
    );

    let rs_adr_verifier = Verifier::new(&spark_proof.whir_params.a);
    rs_adr_verifier
        .verify(&mut arthur, &row_commitment, &rs_adr_statement)
        .context("while verifying WHIR")?;

    let rs_mem = arthur.hint()?;

    let mut rs_val_statement = Statement::<FieldElement>::new(next_power_of_two(
        spark_proof.matrix_dimensions.a_nonzero_terms,
    ));
    rs_val_statement.add_constraint(
        Weights::evaluation(MultilinearPoint(evaluation_randomness.to_vec().clone())),
        rs_mem,
    );

    let rs_val_verifier = Verifier::new(&spark_proof.whir_params.a);
    rs_val_verifier
        .verify(&mut arthur, &e_rx_commitment, &rs_val_statement)
        .context("while verifying WHIR")?;

    let rs_timestamp = arthur.hint()?;

    let mut rs_timestamp_statement = Statement::<FieldElement>::new(next_power_of_two(
        spark_proof.matrix_dimensions.a_nonzero_terms,
    ));
    rs_timestamp_statement.add_constraint(
        Weights::evaluation(MultilinearPoint(evaluation_randomness.to_vec().clone())),
        rs_timestamp,
    );

    let rs_timestamp_verifier = Verifier::new(&spark_proof.whir_params.a);
    rs_timestamp_verifier
        .verify(&mut arthur, &read_ts_commitment, &rs_timestamp_statement)
        .context("while verifying WHIR")?;

    let rs_opening = rs_adr * gamma * gamma + rs_mem * gamma + rs_timestamp - tau;
    let ws_opening =
        rs_adr * gamma * gamma + rs_mem * gamma + rs_timestamp + FieldElement::from(1) - tau;

    let evaluated_value =
        rs_opening * (FieldElement::one() - last_randomness[0]) + ws_opening * last_randomness[0];

    ensure!(evaluated_value == gpa_result.last_sumcheck_value);

    ensure!(claimed_init * claimed_ws == claimed_final * claimed_rs);

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
    let mut last_sumcheck_value = eval_linear_poly(&claimed_values, &r[0]);

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
                last_sumcheck_value
            );
            rand.push(alpha[0]);
            last_sumcheck_value = eval_cubic_poly(&h, &alpha[0]);
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
        assert_eq!(claimed_last_sch, last_sumcheck_value);
        rand.push(r[0]);
        prev_rand = rand;
        rand = Vec::<FieldElement>::new();
        last_sumcheck_value = eval_linear_poly(&l, &r[0]);
    }

    Ok(GPASumcheckResult {
        claimed_values: claimed_values.to_vec(),
        last_sumcheck_value,
        randomness: prev_rand,
    })
}

pub struct GPASumcheckResult {
    pub claimed_values:      Vec<FieldElement>,
    pub last_sumcheck_value: FieldElement,
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
