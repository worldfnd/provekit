use {
    crate::{
        gpa::{self, run_gpa4},
        memory::{prove_colwise, prove_rowwise},
        preprocessing::MatrixPreprocessor,
        sumcheck::run_spark_sumcheck,
        types::{
            EValuesForMatrix, MatrixDimensions, Memory, SPARKProof, SPARKWHIRConfigs, SparkMatrix,
        },
        utils::{calculate_memory, SPARKDomainSeparator},
    }, anyhow::Result, ark_ff::AdditiveGroup, itertools::izip, provekit_common::{
        skyscraper::{SkyscraperMerkleConfig, SkyscraperSponge},
        spark::SparkStatement,
        utils::{next_power_of_two, sumcheck::SumcheckIOPattern},
        FieldElement, IOPattern, WhirR1CSScheme, R1CS,
    }, provekit_r1cs_compiler::WhirR1CSSchemeBuilder, spongefish::{
        codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
        ProverState,
    }, std::collections::BTreeSet, whir::{
        poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint},
        whir::{
            committer::{CommitmentWriter, Witness},
            domainsep::WhirDomainSeparator,
            prover::Prover,
            statement::{Statement, Weights},
            utils::HintSerialize,
        },
    }
};

/// SPARK proving interface for R1CS constraint systems.
pub trait SPARKProver {
    /// Generates a SPARK proof from R1CS and evaluation request.
    fn prove(&self, r1cs: &R1CS, request: &SparkStatement) -> Result<SPARKProof>;
}

/// SPARK scheme with pre-configured WHIR parameters and IO pattern.
pub struct SPARKScheme {
    pub whir_configs:      SPARKWHIRConfigs,
    pub io_pattern:        IOPattern,
    pub matrix_dimensions: MatrixDimensions,
}

impl SPARKScheme {
    /// Configures SPARK scheme for given R1CS dimensions.
    pub fn new_for_r1cs(r1cs: &R1CS) -> Self {
        let num_rows = r1cs.num_constraints();
        let num_cols = r1cs.num_witnesses();

        let mut coordinates = BTreeSet::new();
        for ((row, col), _) in r1cs.a().iter() {
            coordinates.insert((row, col));
        }
        for ((row, col), _) in r1cs.b().iter() {
            coordinates.insert((row, col));
        }
        for ((row, col), _) in r1cs.c().iter() {
            coordinates.insert((row, col));
        }
        let nonzero_terms = coordinates.len();
        let padded_num_entries = 1 << next_power_of_two(nonzero_terms);

        let row_config = WhirR1CSScheme::new_whir_config_for_size(next_power_of_two(num_rows), 1);
        let col_config = WhirR1CSScheme::new_whir_config_for_size(next_power_of_two(num_cols), 1);
        let num_terms_2batched_config =
        WhirR1CSScheme::new_whir_config_for_size(next_power_of_two(padded_num_entries), 2);
        let num_terms_3batched_config =
            WhirR1CSScheme::new_whir_config_for_size(next_power_of_two(padded_num_entries), 3);
        let num_terms_5batched_config =
            WhirR1CSScheme::new_whir_config_for_size(next_power_of_two(padded_num_entries), 5);

        let whir_configs = SPARKWHIRConfigs {
            row:                row_config.clone(),
            col:                col_config.clone(),
            num_terms_3batched: num_terms_3batched_config.clone(),
            num_terms_5batched: num_terms_5batched_config.clone(),
        };

        let mut io = IOPattern::new("💥");

        io = io
            .hint("point_row")
            .hint("point_col")
            .add_claimed_evaluations();

        io = io
            .commit_statement(&num_terms_5batched_config)
            .commit_statement(&num_terms_3batched_config)
            .commit_statement(&num_terms_3batched_config)
            .commit_statement(&row_config)
            .commit_statement(&col_config)
            .add_sumcheck_polynomials(next_power_of_two(padded_num_entries))
            .hint("sumcheck_last_folds")
            .add_whir_proof(&num_terms_5batched_config);

        io = io.add_tau_and_gamma();

        io = io.add_gpa4_claimed_values();
        for i in 2..=(next_power_of_two(padded_num_entries)+1) {
            io = io.add_sumcheck_polynomials(i).add_line();
        }
        
        io = io
            .hint("row_rs_address_claimed_evaluation")
            .hint("row_rs_value_claimed_evaluation")
            .hint("row_rs_timestamp_claimed_evaluation")
            .add_whir_proof(&num_terms_3batched_config);

        io = io
            .hint("col_rs_address_claimed_evaluation")
            .hint("col_rs_value_claimed_evaluation")
            .hint("col_rs_timestamp_claimed_evaluation")
            .add_whir_proof(&num_terms_3batched_config);

        // for i in 0..=next_power_of_two(num_rows) {
        //     io = io.add_sumcheck_polynomials(i).add_line();
        // }
        // io = io
        //     .hint("row_final_counter_claimed_evaluation")
        //     .add_whir_proof(&row_config);

        // for i in 0..=next_power_of_two(padded_num_entries) {
        //     io = io.add_sumcheck_polynomials(i).add_line();
        // }

        // io = io.add_tau_and_gamma();
        // for i in 0..=next_power_of_two(num_cols) {
        //     io = io.add_sumcheck_polynomials(i).add_line();
        // }
        // io = io
        //     .hint("col_final_counter_claimed_evaluation")
        //     .add_whir_proof(&col_config);

        // for i in 0..=next_power_of_two(padded_num_entries) {
        //     io = io.add_sumcheck_polynomials(i).add_line();
        // }
        

        Self {
            whir_configs,
            io_pattern: io,
            matrix_dimensions: MatrixDimensions {
                num_rows,
                num_cols,
                nonzero_terms,
            },
        }
    }
}

impl SPARKProver for SPARKScheme {
    fn prove(&self, r1cs: &R1CS, request: &SparkStatement) -> Result<SPARKProof> {
        let processed = MatrixPreprocessor::from_r1cs(r1cs)?;
        let memory = calculate_memory(request.point_to_evaluate.clone());
        let e_values = processed.compute_e_values(&memory);

        let mut merlin = self.io_pattern.to_prover_state();

        merlin.hint(&request.point_to_evaluate.row)?;
        merlin.hint(&request.point_to_evaluate.col)?;

        merlin.add_scalars(&[
            request.claimed_values.a,
            request.claimed_values.b,
            request.claimed_values.c,
        ])?;
        let mut matrix_batching_randomness = [FieldElement::ZERO; 1];
        merlin.fill_challenge_scalars(&mut matrix_batching_randomness)?;
        let matrix_batching_randomness = matrix_batching_randomness[0];
        let matrix_batching_randomness_sq = matrix_batching_randomness * matrix_batching_randomness;

        let spark_matrix = processed.into_spark_matrix(r1cs, matrix_batching_randomness);

        let claimed_value = request.claimed_values.a
            + request.claimed_values.b * matrix_batching_randomness
            + request.claimed_values.c * matrix_batching_randomness_sq;

        prove_spark_for_single_matrix(
            &mut merlin,
            spark_matrix,
            &memory,
            e_values,
            claimed_value,
            &self.whir_configs,
        )?;

        Ok(SPARKProof {
            transcript:        merlin.narg_string().to_vec(),
            io_pattern:        String::from_utf8(self.io_pattern.as_bytes().to_vec())?,
            whir_params:       self.whir_configs.clone(),
            matrix_dimensions: self.matrix_dimensions.clone(),
        })
    }
}

/// Core SPARK protocol: sumcheck + row/col memory checking.
fn prove_spark_for_single_matrix(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    matrix: SparkMatrix,
    memory: &Memory,
    e_values: EValuesForMatrix,
    claimed_value: FieldElement,
    whir_configs: &SPARKWHIRConfigs,
) -> Result<()> {
    let row_committer = CommitmentWriter::new(whir_configs.row.clone());
    let col_committer = CommitmentWriter::new(whir_configs.col.clone());
    let batched3_committer = CommitmentWriter::new(whir_configs.num_terms_3batched.clone());
    let batched5_committer = CommitmentWriter::new(whir_configs.num_terms_5batched.clone());

    // Commit to 5 polynomials: val_a, val_b, val_c, eᵣ, eᵧ
    let sumcheck_witness = batched5_committer.commit_batch(merlin, &[
        EvaluationsList::new(matrix.coo.val_a.clone()).to_coeffs(),
        EvaluationsList::new(matrix.coo.val_b.clone()).to_coeffs(),
        EvaluationsList::new(matrix.coo.val_c.clone()).to_coeffs(),
        EvaluationsList::new(e_values.e_rx.clone()).to_coeffs(),
        EvaluationsList::new(e_values.e_ry.clone()).to_coeffs(),
    ])?;

    let rowwise_witness = batched3_committer.commit_batch(merlin, &[
        EvaluationsList::new(matrix.coo.row.clone()).to_coeffs(),
        EvaluationsList::new(e_values.e_rx.clone()).to_coeffs(),
        EvaluationsList::new(matrix.timestamps.read_row.clone()).to_coeffs(),
    ])?;

    let colwise_witness = batched3_committer.commit_batch(merlin, &[
        EvaluationsList::new(matrix.coo.col.clone()).to_coeffs(),
        EvaluationsList::new(e_values.e_ry.clone()).to_coeffs(),
        EvaluationsList::new(matrix.timestamps.read_col.clone()).to_coeffs(),
    ])?;

    let final_row_ts_witness =
        commit_to_vector(&row_committer, merlin, matrix.timestamps.final_row.clone());
    let final_col_ts_witness =
        commit_to_vector(&col_committer, merlin, matrix.timestamps.final_col.clone());

    let mles = [
        matrix.coo.val.clone(),
        e_values.e_rx.clone(),
        e_values.e_ry.clone(),
    ];

    let (sumcheck_final_folds, folding_randomness) =
        run_spark_sumcheck(merlin, mles, claimed_value)?;

    let val_a_eval = EvaluationsList::new(matrix.coo.val_a.clone())
        .evaluate(&MultilinearPoint(folding_randomness.to_vec().clone()));
    let val_b_eval = EvaluationsList::new(matrix.coo.val_b.clone())
        .evaluate(&MultilinearPoint(folding_randomness.to_vec().clone()));
    let val_c_eval = EvaluationsList::new(matrix.coo.val_c.clone())
        .evaluate(&MultilinearPoint(folding_randomness.to_vec().clone()));

    merlin.hint::<Vec<FieldElement>>(
        &[
            val_a_eval,
            val_b_eval,
            val_c_eval,
            sumcheck_final_folds[1],
            sumcheck_final_folds[2],
        ]
        .to_vec(),
    )?;

    // Batching randomness powers: [1, β, β², β³, β⁴]
    let mut batching_randomness = Vec::with_capacity(5);
    let mut cur = FieldElement::from(1);
    for _ in 0..5 {
        batching_randomness.push(cur);
        cur *= sumcheck_witness.batching_randomness;
    }

    let claimed_batched_value = val_a_eval * batching_randomness[0]
        + val_b_eval * batching_randomness[1]
        + val_c_eval * batching_randomness[2]
        + sumcheck_final_folds[1] * batching_randomness[3]
        + sumcheck_final_folds[2] * batching_randomness[4];

    produce_whir_proof(
        merlin,
        MultilinearPoint(folding_randomness.to_vec()),
        claimed_batched_value,
        whir_configs.num_terms_5batched.clone(),
        sumcheck_witness,
    )?;

    
    // RS WS combined

    let mut tau_and_gamma = [FieldElement::from(0); 2];
    merlin.fill_challenge_scalars(&mut tau_and_gamma)?;
    let tau = tau_and_gamma[0];
    let gamma = tau_and_gamma[1];

    let row_rs_vec: Vec<_> = izip!(
        (&matrix.coo.row).iter(),
        (&e_values.e_rx).iter(),
        (&matrix.timestamps.read_row).iter()
    )
    .map(|(&a, &v, &t)| a * gamma * gamma + v * gamma + t - tau)
    .collect();

    let row_ws_vec: Vec<_> = izip!(
        (&matrix.coo.row).iter(),
        (&e_values.e_rx).iter(),
        (&matrix.timestamps.read_row).iter()
    )
    .map(|(&a, &v, &t)| a * gamma * gamma + v * gamma + (t + FieldElement::from(1)) - tau)
    .collect();

    let col_rs_vec: Vec<_> = izip!(
        (&matrix.coo.col).iter(),
        (&e_values.e_ry).iter(),
        (&matrix.timestamps.read_col).iter()
    )
    .map(|(&a, &v, &t)| a * gamma * gamma + v * gamma + t - tau)
    .collect();

    let col_ws_vec: Vec<_> = izip!(
        (&matrix.coo.col).iter(),
        (&e_values.e_ry).iter(),
        (&matrix.timestamps.read_col).iter()
    )
    .map(|(&a, &v, &t)| a * gamma * gamma + v * gamma + (t + FieldElement::from(1)) - tau)
    .collect();

    let gpa_leaves = [row_rs_vec, row_ws_vec, col_rs_vec, col_ws_vec];
    let gpa_leaves_flat = gpa_leaves.iter().flatten().cloned().collect::<Vec<_>>();
    let gpa_randomness = run_gpa4(merlin, gpa_leaves_flat);

    let (_combination_randomness, evaluation_randomness) = gpa_randomness.split_at(2);
    let eval_point = MultilinearPoint(evaluation_randomness.to_vec());

    let row_address_eval = EvaluationsList::new(matrix.coo.row).evaluate(&eval_point);
    merlin.hint(&row_address_eval)?;

    let row_value_eval = EvaluationsList::new(e_values.e_rx).evaluate(&eval_point);
    merlin.hint(&row_value_eval)?;

    let row_timestamp_eval = EvaluationsList::new(matrix.timestamps.read_row.to_vec()).evaluate(&eval_point);
    merlin.hint(&row_timestamp_eval)?;

    let row_br = rowwise_witness.batching_randomness;
    let claimed_eval = row_address_eval + row_value_eval * row_br + row_timestamp_eval * row_br * row_br;

    assert_eq!(
        claimed_eval,
        rowwise_witness.batched_poly().evaluate(&eval_point)
    );

    produce_whir_proof(
        merlin,
        eval_point.clone(),
        claimed_eval,
        whir_configs.num_terms_3batched.clone(),
        rowwise_witness,
    )?;

    let col_address_eval = EvaluationsList::new(matrix.coo.col).evaluate(&eval_point);
    merlin.hint(&col_address_eval)?;

    let col_value_eval = EvaluationsList::new(e_values.e_ry).evaluate(&eval_point);
    merlin.hint(&col_value_eval)?;

    let col_timestamp_eval = EvaluationsList::new(matrix.timestamps.read_col.to_vec()).evaluate(&eval_point);
    merlin.hint(&col_timestamp_eval)?;

    let col_br = colwise_witness.batching_randomness;
    let claimed_eval = col_address_eval + col_value_eval * col_br + col_timestamp_eval * col_br * col_br;

    assert_eq!(
        claimed_eval,
        colwise_witness.batched_poly().evaluate(&eval_point)
    );

    produce_whir_proof(
        merlin,
        eval_point,
        claimed_eval,
        whir_configs.num_terms_3batched.clone(),
        colwise_witness,
    )?;

    // prove_rowwise(
    //     merlin,
    //     &matrix,
    //     memory,
    //     &e_values.e_rx,
    //     whir_configs,
    //     final_row_ts_witness,
    //     rowwise_witness,
    // )?;

    // prove_colwise(
    //     merlin,
    //     &matrix,
    //     memory,
    //     &e_values.e_ry,
    //     whir_configs,
    //     final_col_ts_witness,
    //     colwise_witness,
    // )?;

    Ok(())
}

/// Commits to vector and returns WHIR witness.
fn commit_to_vector(
    committer: &CommitmentWriter<
        FieldElement,
        SkyscraperMerkleConfig,
        provekit_common::skyscraper::SkyscraperPoW,
    >,
    merlin: &mut spongefish::ProverState<SkyscraperSponge, FieldElement>,
    vector: Vec<FieldElement>,
) -> Witness<FieldElement, SkyscraperMerkleConfig> {
    assert!(
        vector.len().is_power_of_two(),
        "Vector length must be power of two"
    );
    let evals = EvaluationsList::new(vector);
    let coeffs = evals.to_coeffs();
    committer
        .commit(merlin, coeffs)
        .expect("WHIR commitment failed")
}

/// Generates WHIR opening proof for polynomial evaluation.
fn produce_whir_proof(
    merlin: &mut spongefish::ProverState<SkyscraperSponge, FieldElement>,
    evaluation_point: MultilinearPoint<FieldElement>,
    evaluated_value: FieldElement,
    config: provekit_common::WhirConfig,
    witness: Witness<FieldElement, SkyscraperMerkleConfig>,
) -> Result<()> {
    let mut statement = Statement::<FieldElement>::new(evaluation_point.num_variables());
    statement.add_constraint(Weights::evaluation(evaluation_point), evaluated_value);
    let prover = Prover::new(config);

    prover.prove(merlin, statement, witness)?;

    Ok(())
}
