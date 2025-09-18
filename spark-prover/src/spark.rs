use {
    crate::{
        gpa::run_gpa,
        memory::{EValuesForMatrix, Memory},
        utilities::matrix::SparkMatrix,
        whir::{commit_to_vector, produce_whir_proof, SPARKWHIRConfigs},
    },
    anyhow::{ensure, Result},
    itertools::izip,
    provekit_common::{
        skyscraper::SkyscraperSponge,
        utils::{
            sumcheck::{eval_cubic_poly, sumcheck_fold_map_reduce},
            HALF,
        },
        FieldElement,
    },
    spongefish::{
        codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
        ProverState,
    },
    whir::{
        poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint},
        whir::{committer::CommitmentWriter, prover::Prover, statement::{Statement, Weights}, utils::HintSerialize},
    },
};

pub fn prove_spark_for_single_matrix(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    matrix: SparkMatrix,
    memory: Memory,
    e_values: EValuesForMatrix,
    claimed_value: FieldElement,
    whir_configs: &SPARKWHIRConfigs,
) -> Result<()> {
    let committer_a = CommitmentWriter::new(whir_configs.a.clone());
    let committer_row = CommitmentWriter::new(whir_configs.row.clone());
    let a_spark_sumcheck_committer = CommitmentWriter::new(whir_configs.a_spark_sumcheck.clone());

    let val_coeff = EvaluationsList::new(matrix.coo.val.clone()).to_coeffs();
    let e_rx_coeff = EvaluationsList::new(e_values.e_rx.clone()).to_coeffs();
    let e_ry_coeff = EvaluationsList::new(e_values.e_ry.clone()).to_coeffs();

    let spark_sumcheck_witness = a_spark_sumcheck_committer.commit_batch(merlin, &[val_coeff, e_rx_coeff, e_ry_coeff])?;

    let row_addr_coeff = EvaluationsList::new(matrix.coo.row.clone()).to_coeffs();
    let row_val_coeff = EvaluationsList::new(e_values.e_rx.clone()).to_coeffs();
    let row_timestamp_coeff = EvaluationsList::new(matrix.timestamps.read_row.clone()).to_coeffs();

    let spark_rowwise_witness = a_spark_sumcheck_committer.commit_batch(merlin, &[row_addr_coeff, row_val_coeff, row_timestamp_coeff])?;

    let final_row_ts_witness = commit_to_vector(&committer_row, merlin, matrix.timestamps.final_row.clone());

    let mles = [
        matrix.coo.val.clone(),
        e_values.e_rx.clone(),
        e_values.e_ry.clone(),
    ];

    let (sumcheck_final_folds, folding_randomness) =
        run_spark_sumcheck(merlin, mles, claimed_value)?;

    let mut spark_sumcheck_statement = Statement::<FieldElement>::new(folding_randomness.len());
    
    let claimed_batched_value = 
        sumcheck_final_folds[0] + 
        sumcheck_final_folds[1] * spark_sumcheck_witness.batching_randomness + 
        sumcheck_final_folds[2] * spark_sumcheck_witness.batching_randomness * spark_sumcheck_witness.batching_randomness;

    spark_sumcheck_statement.add_constraint(
        Weights::evaluation(MultilinearPoint(folding_randomness.clone())), claimed_batched_value);
    
    let sumcheck_prover = Prover(whir_configs.a_spark_sumcheck.clone());
    sumcheck_prover.prove(merlin, spark_sumcheck_statement, spark_sumcheck_witness)?;

    // Rowwise

    let mut tau_and_gamma = [FieldElement::from(0); 2];
    merlin.fill_challenge_scalars(&mut tau_and_gamma)?;
    let tau = tau_and_gamma[0];
    let gamma = tau_and_gamma[1];

    let init_address: Vec<FieldElement> = (0..memory.eq_rx.len() as u64)
        .map(FieldElement::from)
        .collect();
    let init_value = memory.eq_rx.clone();
    let init_timestamp = vec![FieldElement::from(0); memory.eq_rx.len()];

    let init_vec: Vec<FieldElement> = izip!(init_address, init_value, init_timestamp)
        .map(|(a, v, t)| a * gamma * gamma + v * gamma + t - tau)
        .collect();

    let final_address: Vec<FieldElement> = (0..memory.eq_rx.len() as u64)
        .map(FieldElement::from)
        .collect();
    let final_value = memory.eq_rx.clone();
    let final_timestamp = matrix.timestamps.final_row.clone();

    let final_vec: Vec<FieldElement> = izip!(final_address, final_value, final_timestamp)
        .map(|(a, v, t)| a * gamma * gamma + v * gamma + t - tau)
        .collect();

    let gpa_randomness = run_gpa(merlin, &init_vec, &final_vec);

    let (combination_randomness, evaluation_randomness) = gpa_randomness.split_at(1);

    // TODO: Can I avoid evaluating here?
    let final_row_eval = EvaluationsList::new(matrix.timestamps.final_row.clone())
        .evaluate(&MultilinearPoint(evaluation_randomness.to_vec().clone()));
    merlin.hint(&final_row_eval)?;

    produce_whir_proof(
        merlin,
        MultilinearPoint(evaluation_randomness.to_vec()),
        final_row_eval,
        whir_configs.row.clone(),
        final_row_ts_witness,
    )?;

    let rs_address = matrix.coo.row.clone();
    let rs_value = e_values.e_rx.clone();
    let rs_timestamp = matrix.timestamps.read_row.clone();

    let rs_vec: Vec<FieldElement> =
        izip!(rs_address.clone(), rs_value.clone(), rs_timestamp.clone())
            .map(|(a, v, t)| a * gamma * gamma + v * gamma + t - tau)
            .collect();

    let ws_address = matrix.coo.row.clone();
    let ws_value = e_values.e_rx.clone();
    let ws_timestamp: Vec<FieldElement> = matrix
        .timestamps
        .read_row
        .into_iter()
        .map(|a| a + FieldElement::from(1))
        .collect();

    let ws_vec: Vec<FieldElement> =
        izip!(ws_address.clone(), ws_value.clone(), ws_timestamp.clone())
            .map(|(a, v, t)| a * gamma * gamma + v * gamma + t - tau)
            .collect();

    let gpa_randomness = run_gpa(merlin, &rs_vec, &ws_vec);

    let (combination_randomness, evaluation_randomness) = gpa_randomness.split_at(1);

    let rs_address_eval = EvaluationsList::new(rs_address)
        .evaluate(&MultilinearPoint(evaluation_randomness.to_vec().clone()));
    merlin.hint(&rs_address_eval)?;
    
    let rs_value_eval = EvaluationsList::new(rs_value)
        .evaluate(&MultilinearPoint(evaluation_randomness.to_vec().clone()));
    merlin.hint(&rs_value_eval)?;

    let rs_timestamp_eval = EvaluationsList::new(rs_timestamp)
        .evaluate(&MultilinearPoint(evaluation_randomness.to_vec().clone()));
    merlin.hint(&rs_timestamp_eval)?;

    let mut spark_rowwise_statement = Statement::<FieldElement>::new(evaluation_randomness.len());

    let claimed_rowwise_eval = 
        rs_address_eval + 
        rs_value_eval * spark_rowwise_witness.batching_randomness + 
        rs_timestamp_eval * spark_rowwise_witness.batching_randomness * spark_rowwise_witness.batching_randomness;

    assert!(claimed_rowwise_eval == spark_rowwise_witness.batched_poly().evaluate(&MultilinearPoint(evaluation_randomness.to_vec())));

    spark_rowwise_statement.add_constraint(
        Weights::evaluation(MultilinearPoint(evaluation_randomness.to_vec().clone())), claimed_rowwise_eval);
    
    let sumcheck_prover = Prover(whir_configs.a_spark_sumcheck.clone());
    sumcheck_prover.prove(merlin, spark_rowwise_statement, spark_rowwise_witness)?;
    
    // produce_whir_proof(
    //     merlin,
    //     MultilinearPoint(evaluation_randomness.to_vec()),
    //     rs_address_eval,
    //     whir_configs.a.clone(),
    //     row_witness.clone(),
    // )?;

    // produce_whir_proof(
    //     merlin,
    //     MultilinearPoint(evaluation_randomness.to_vec()),
    //     rs_value_eval,
    //     whir_configs.a.clone(),
    //     e_rx_witness.clone(),
    // )?;

    // produce_whir_proof(
    //     merlin,
    //     MultilinearPoint(evaluation_randomness.to_vec()),
    //     rs_timestamp_eval,
    //     whir_configs.a.clone(),
    //     read_ts_witness.clone(),
    // )?;

    Ok(())
}

pub fn run_spark_sumcheck(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    mles: [Vec<FieldElement>; 3],
    mut claimed_value: FieldElement,
) -> Result<([FieldElement; 3], Vec<FieldElement>)> {
    let mut sumcheck_randomness = [FieldElement::from(0)];
    let mut sumcheck_randomness_accumulator = Vec::<FieldElement>::new();
    let mut fold = None;

    let mut m0 = mles[0].clone();
    let mut m1 = mles[1].clone();
    let mut m2 = mles[2].clone();

    loop {
        let [hhat_i_at_0, hhat_i_at_em1, hhat_i_at_inf_over_x_cube] =
            sumcheck_fold_map_reduce([&mut m0, &mut m1, &mut m2], fold, |[m0, m1, m2]| {
                [
                    // Evaluation at 0
                    m0.0 * m1.0 * m2.0,
                    // Evaluation at -1
                    (m0.0 + m0.0 - m0.1) * (m1.0 + m1.0 - m1.1) * (m2.0 + m2.0 - m2.1),
                    // Evaluation at infinity
                    (m0.1 - m0.0) * (m1.1 - m1.0) * (m2.1 - m2.0),
                ]
            });

        if fold.is_some() {
            m0.truncate(m0.len() / 2);
            m1.truncate(m1.len() / 2);
            m2.truncate(m2.len() / 2);
        }

        let mut hhat_i_coeffs = [FieldElement::from(0); 4];

        hhat_i_coeffs[0] = hhat_i_at_0;
        hhat_i_coeffs[2] =
            HALF * (claimed_value + hhat_i_at_em1 - hhat_i_at_0 - hhat_i_at_0 - hhat_i_at_0);
        hhat_i_coeffs[3] = hhat_i_at_inf_over_x_cube;
        hhat_i_coeffs[1] = claimed_value
            - hhat_i_coeffs[0]
            - hhat_i_coeffs[0]
            - hhat_i_coeffs[3]
            - hhat_i_coeffs[2];

        assert_eq!(
            claimed_value,
            hhat_i_coeffs[0]
                + hhat_i_coeffs[0]
                + hhat_i_coeffs[1]
                + hhat_i_coeffs[2]
                + hhat_i_coeffs[3]
        );

        merlin.add_scalars(&hhat_i_coeffs[..])?;
        merlin.fill_challenge_scalars(&mut sumcheck_randomness)?;
        fold = Some(sumcheck_randomness[0]);
        claimed_value = eval_cubic_poly(&hhat_i_coeffs, &sumcheck_randomness[0]);
        sumcheck_randomness_accumulator.push(sumcheck_randomness[0]);
        if m0.len() <= 2 {
            break;
        }
    }

    let folded_v0 = m0[0] + (m0[1] - m0[0]) * sumcheck_randomness[0];
    let folded_v1 = m1[0] + (m1[1] - m1[0]) * sumcheck_randomness[0];
    let folded_v2 = m2[0] + (m2[1] - m2[0]) * sumcheck_randomness[0];

    merlin.hint::<Vec<FieldElement>>(&[folded_v0, folded_v1, folded_v2].to_vec())?;
    Ok((
        [folded_v0, folded_v1, folded_v2],
        sumcheck_randomness_accumulator,
    ))
}
