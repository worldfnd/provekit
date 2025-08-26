use {
    anyhow::{ensure, Context, Result},
    ark_std::{One, Zero},
    noir_r1cs::{
        utils::{next_power_of_two, sumcheck::eval_qubic_poly},
        FieldElement, IOPattern, SkyscraperSponge,
    },
    spark_prover::utilities::{SPARKProof, SPARKRequest},
    spongefish::{
        codecs::arkworks_algebra::{FieldToUnitDeserialize, UnitToField},
        VerifierState,
    },
    std::fs,
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
    let spark_proof_json_str = fs::read_to_string("spark/spark-prover/spark_proof.json")
        .context("Error: Failed to open the r1cs.json file")?;
    let spark_proof: SPARKProof = serde_json::from_str(&spark_proof_json_str)
        .context("Error: Failed to deserialize JSON to R1CS")?;

    let request_json_str = fs::read_to_string("spark/spark-prover/request.json")
        .context("Error: Failed to open the r1cs.json file")?;
    let request: SPARKRequest = serde_json::from_str(&request_json_str)
        .context("Error: Failed to deserialize JSON to R1CS")?;

    let io = IOPattern::from_string(spark_proof.io_pattern);
    let mut arthur = io.to_verifier_state(&spark_proof.transcript);

    let commitment_reader = CommitmentReader::new(&spark_proof.whir_params.a);
    let val_commitment = commitment_reader.parse_commitment(&mut arthur).unwrap();

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

        let hhat_i_at_zero = eval_qubic_poly(&hhat_i, &FieldElement::zero());
        let hhat_i_at_one = eval_qubic_poly(&hhat_i, &FieldElement::one());
        ensure!(
            saved_val_for_sumcheck_equality_assertion == hhat_i_at_zero + hhat_i_at_one,
            "Sumcheck equality assertion failed"
        );
        saved_val_for_sumcheck_equality_assertion = eval_qubic_poly(&hhat_i, &alpha_i[0]);
    }

    Ok((alpha, saved_val_for_sumcheck_equality_assertion))
}
