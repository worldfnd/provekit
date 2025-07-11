use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::FftField;
use spongefish::{codecs::arkworks_algebra::FieldDomainSeparator, ByteDomainSeparator, ProverState, VerifierState};
use whir::{poly_utils::evals::EvaluationsList, whir::{
    committer::{reader::ParsedCommitment, CommitmentReader, CommitmentWriter, Witness}, domainsep::{DigestDomainSeparator, WhirDomainSeparator}, parameters::WhirConfig as GenericWhirConfig
}};

use crate::{skyscraper::{SkyscraperMerkleConfig, SkyscraperPoW, SkyscraperSponge}, sparse_matrix::HydratedSparseMatrix, utils::{pad_to_power_of_two, sumcheck::{calculate_evaluations_over_boolean_hypercube_for_eq, SumcheckIOPattern}}, FieldElement};

pub type WhirConfig = GenericWhirConfig<FieldElement, SkyscraperMerkleConfig, SkyscraperPoW>;

pub fn prove_spark (
    matrix: HydratedSparseMatrix,
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    whir_config_num_terms: &WhirConfig,
    row_randomness: &Vec<FieldElement>,
    col_randomness: &Vec<FieldElement>,
) {
    SparkInstance::new(
        &matrix,
        merlin,
        whir_config_num_terms.clone(),
        row_randomness,
        col_randomness,
    );
}


pub struct SparkInstance {
    pub sumcheck: SPARKSumcheckValuesAndWitnesses,
}

impl SparkInstance {
    pub fn new(
        s: &HydratedSparseMatrix,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        whir_config_num_terms: WhirConfig,
        row_randomness: &Vec<FieldElement>,
        col_randomness: &Vec<FieldElement>,
    ) -> Self {
        let (matrix_witnesses, matrix_values) = Self::calculate_matrix_values_and_witnesses(&s, merlin, whir_config_num_terms.clone());
        let (e_witnesses, e_values) = Self::calculate_e_witnesses(&s, merlin, whir_config_num_terms.clone(), row_randomness, col_randomness);
        Self { 
            sumcheck: SPARKSumcheckValuesAndWitnesses {
                values: SPARKSumcheckValues {
                    val: matrix_values.val_values,
                    e_rx: e_values.e_rx_values,
                    e_ry: e_values.e_ry_values,
                },
                witnesses: SPARKSumcheckWitnesses {
                    val: matrix_witnesses.val_witness,
                    e_rx: e_witnesses.e_rx_witness,
                    e_ry: e_witnesses.e_ry_witness,
                },
            },
        }
    }

    pub fn calculate_matrix_values_and_witnesses(
        s: &HydratedSparseMatrix, 
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>, 
        whir_config_a: WhirConfig
    ) -> (MatrixWitnesses, MatrixValues) {
        let mut val_spark = Vec::<FieldElement>::new();

        for ((r, c), value) in s.iter() {
            val_spark.push(value.clone());
        }

        val_spark = pad_to_power_of_two(val_spark);

        let committer = CommitmentWriter::new(whir_config_a);
        
        (MatrixWitnesses {
            val_witness: Self::commit_to_vector(&committer, merlin, val_spark.clone()),
        }, 
        MatrixValues {
            val_values: val_spark,
        })
    }


    pub fn calculate_e_witnesses(
        s: &HydratedSparseMatrix, 
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>, 
        whir_config_num_terms: WhirConfig,
        row_randomness: &Vec<FieldElement>,
        col_randomness: &Vec<FieldElement>,
    ) -> (EWitnesses, EValues) {
        let eq_rx = calculate_evaluations_over_boolean_hypercube_for_eq(row_randomness);
        let eq_ry = calculate_evaluations_over_boolean_hypercube_for_eq(col_randomness);
        let mut e_rx = Vec::<FieldElement>::new();
        let mut e_ry = Vec::<FieldElement>::new();

        for ((r, c), _) in s.iter() {
            e_rx.push(eq_rx[r]);
            e_ry.push(eq_ry[c]);
        }

        e_rx = pad_to_power_of_two(e_rx);
        e_ry = pad_to_power_of_two(e_ry);

        let committer = CommitmentWriter::new(whir_config_num_terms);
        (EWitnesses {
            e_rx_witness: Self::commit_to_vector(&committer, merlin, e_rx.clone()),
            e_ry_witness: Self::commit_to_vector(&committer, merlin, e_ry.clone()),
        }, 
        EValues {
            e_rx_values: e_rx,
            e_ry_values: e_ry, 
        })
    }       

    pub fn commit_to_vector(
        committer: &CommitmentWriter<FieldElement, SkyscraperMerkleConfig, SkyscraperPoW>,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        vector: Vec<FieldElement>,
    ) -> Witness<FieldElement, SkyscraperMerkleConfig> {
        assert!(vector.len().is_power_of_two(), "Committed vector length must be a power of two");
        let evals = EvaluationsList::new(vector);
        let coeffs = evals.to_coeffs();
        committer
            .commit(merlin, coeffs)
            .expect("WHIR prover failed to commit")
    }
}

pub struct SPARKSumcheckValuesAndWitnesses {
    pub values: SPARKSumcheckValues,
    pub witnesses: SPARKSumcheckWitnesses,
}

pub struct SPARKSumcheckValues {
    pub val: Vec<FieldElement>,
    pub e_rx: Vec<FieldElement>,
    pub e_ry: Vec<FieldElement>,
}

pub struct SPARKSumcheckWitnesses {
    pub val: Witness<FieldElement, SkyscraperMerkleConfig>,
    pub e_rx: Witness<FieldElement, SkyscraperMerkleConfig>,
    pub e_ry: Witness<FieldElement, SkyscraperMerkleConfig>,
}

pub struct MatrixValues {
    pub val_values: Vec<FieldElement>,
}

pub struct MatrixWitnesses {
    pub val_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
}

pub struct EValues {
    pub e_rx_values: Vec<FieldElement>,
    pub e_ry_values: Vec<FieldElement>,
}

pub struct EWitnesses {
    pub e_rx_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
    pub e_ry_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
}

pub trait SparkIOPattern<F: FftField, MerkleConfig: Config>{
    fn spark<PowStrategy>(
        self, 
        whir_config_num_terms: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
    ) -> Self;
    fn spark_commit<PowStrategy>(
        self, 
        whir_config_num_terms: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
    ) -> Self;
}

impl<F, MerkleConfig, DomainSeparator> SparkIOPattern<F, MerkleConfig> for DomainSeparator
where
    F: FftField,
    MerkleConfig: Config,
    DomainSeparator:
        ByteDomainSeparator + FieldDomainSeparator<F> + DigestDomainSeparator<MerkleConfig> + WhirDomainSeparator<F, MerkleConfig> + SumcheckIOPattern,

{
    fn spark<PowStrategy> (
        self, 
        whir_config_num_terms: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
    ) -> Self {
        let io = self
            .spark_commit(
                whir_config_num_terms,
            );
        io
    }

    fn spark_commit<PowStrategy> (
        self, 
        whir_config_num_terms: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
    ) -> Self {
        let io = self
            .commit_statement(whir_config_num_terms)
            .commit_statement(whir_config_num_terms)
            .commit_statement(whir_config_num_terms);
        io
    }
}

pub fn verify_spark(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    whir_config_terms: &WhirConfig,
) {
    let spark_commitments = parse_spark_commitments(
        arthur,
        whir_config_terms,
    );
}

pub fn parse_spark_commitments (
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    whir_config_terms: &WhirConfig,
) -> SparkCommitments{
    let commitment_reader_a = CommitmentReader::new(whir_config_terms);
    
    let val_commitment = commitment_reader_a.parse_commitment(arthur).unwrap();
    let e_rx_commitment = commitment_reader_a.parse_commitment(arthur).unwrap();
    let e_ry_commitment = commitment_reader_a.parse_commitment(arthur).unwrap();
    
    SparkCommitments {
        sumcheck: SparkSumcheckCommitments {
            value_commitment: val_commitment,
            e_rx_commitment:  e_rx_commitment,
            e_ry_commitment:  e_ry_commitment,
        },
    }
}

pub struct SparkCommitments {
    sumcheck: SparkSumcheckCommitments,
}

pub struct SparkSumcheckCommitments {
    value_commitment: ParsedCommitment<FieldElement, FieldElement>,
    e_rx_commitment:  ParsedCommitment<FieldElement, FieldElement>,
    e_ry_commitment:  ParsedCommitment<FieldElement, FieldElement>,
}