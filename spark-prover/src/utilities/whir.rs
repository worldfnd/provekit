use {
    anyhow::{Context, Result},
    provekit_common::{
        skyscraper::{SkyscraperMerkleConfig, SkyscraperPoW, SkyscraperSponge},
        FieldElement, WhirConfig,
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
    pub row:        WhirConfig,
    pub col:        WhirConfig,
    pub a:          WhirConfig,
    pub b:          WhirConfig,
    pub c:          WhirConfig,
    pub a_3batched: WhirConfig,
    pub b_3batched: WhirConfig,
    pub c_3batched: WhirConfig,
}

#[derive(Serialize, Deserialize)]
pub struct SPARKWHIRConfigsNew {
    pub row:                WhirConfig,
    pub col:                WhirConfig,
    pub num_terms_3batched: WhirConfig,
    pub num_terms_5batched: WhirConfig,
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
    let prover = Prover::new(config);

    prover
        .prove(merlin, statement, witness)
        .context("while generating WHIR proof")?;

    Ok(())
}
