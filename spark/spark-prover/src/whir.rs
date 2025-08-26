use {
    anyhow::{Context, Result},
    noir_r1cs::{
        new_whir_config_for_size, utils::next_power_of_two, FieldElement, SkyscraperMerkleConfig,
        SkyscraperPoW, SkyscraperSponge, WhirConfig, R1CS,
    },
    serde::{Deserialize, Serialize},
    spongefish::ProverState,
    whir::{
        poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint},
        whir::{
            committer::{CommitmentWriter, Witness},
            prover::Prover,
            statement::{Statement, Weights},
        },
    },
};

pub fn commit_to_vector(
    committer: &CommitmentWriter<FieldElement, SkyscraperMerkleConfig, SkyscraperPoW>,
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    vector: Vec<FieldElement>,
) -> Witness<FieldElement, SkyscraperMerkleConfig> {
    assert!(
        vector.len().is_power_of_two(),
        "Committed vector length must be a power of two"
    );
    let evals = EvaluationsList::new(vector);
    let coeffs = evals.to_coeffs();
    committer
        .commit(merlin, coeffs)
        .expect("WHIR prover failed to commit")
}

#[derive(Serialize, Deserialize)]
pub struct SPARKWHIRConfigs {
    pub row: WhirConfig,
    pub col: WhirConfig,
    pub a:   WhirConfig,
    pub b:   WhirConfig,
    pub c:   WhirConfig,
}

pub fn create_whir_configs(r1cs: &R1CS) -> SPARKWHIRConfigs {
    SPARKWHIRConfigs {
        row: new_whir_config_for_size(next_power_of_two(r1cs.a.num_rows)),
        col: new_whir_config_for_size(next_power_of_two(r1cs.a.num_cols)),
        a:   new_whir_config_for_size(next_power_of_two(r1cs.a.num_entries())),
        b:   new_whir_config_for_size(next_power_of_two(r1cs.b.num_entries())),
        c:   new_whir_config_for_size(next_power_of_two(r1cs.c.num_entries())),
    }
}

pub fn produce_whir_proof(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    evaluation_point: MultilinearPoint<FieldElement>,
    evaluated_value: FieldElement,
    config: WhirConfig,
    witness: Witness<FieldElement, SkyscraperMerkleConfig>,
) -> Result<()> {
    let mut statement = Statement::<FieldElement>::new(evaluation_point.num_variables());
    statement.add_constraint(Weights::evaluation(evaluation_point), evaluated_value);
    let prover = Prover(config);

    prover
        .prove(merlin, statement, witness)
        .context("while generating WHIR proof")?;

    Ok(())
}
