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
    whir_config_row: &WhirConfig,
    whir_config_col: &WhirConfig,
    row_randomness: &Vec<FieldElement>,
    col_randomness: &Vec<FieldElement>,
) {
    SparkInstance::new(
        &matrix,
        merlin,
        whir_config_num_terms.clone(),
        whir_config_row.clone(),
        whir_config_col.clone(),
        row_randomness,
        col_randomness,
    );
}


pub struct SparkInstance {
    pub sumcheck: SPARKSumcheckValuesAndWitnesses,
    pub rowwise: SPARKValuesAndWitnesses,
    pub colwise: SPARKValuesAndWitnesses,
}

impl SparkInstance {
    pub fn new(
        s: &HydratedSparseMatrix,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        whir_config_num_terms: WhirConfig,
        whir_config_row: WhirConfig,
        whir_config_col: WhirConfig,
        row_randomness: &Vec<FieldElement>,
        col_randomness: &Vec<FieldElement>,
    ) -> Self {
        let (matrix_witnesses, matrix_values) = Self::calculate_matrix_values_and_witnesses(&s, merlin, whir_config_num_terms.clone());
        let (e_witnesses, e_values) = Self::calculate_e_witnesses(&s, merlin, whir_config_num_terms.clone(), row_randomness, col_randomness);
        let (time_stamp_witnesses, time_stamp_values) = Self::calculate_timestamp_witnesses(&s, merlin, whir_config_num_terms.clone(), whir_config_row.clone(), whir_config_col.clone());
        Self { 
            rowwise: SPARKValuesAndWitnesses { 
                values: SPARKValues { 
                    addresses: matrix_values.row_values.clone(), 
                    read_time_stamps: time_stamp_values.read_ts_row_values.clone(),
                    values: e_values.e_rx_values.clone(), 
                    final_counters: time_stamp_values.final_cts_row_values.clone(), 
                    memory: e_values.eq_rx_values.clone(), 
                },
                witnesses: SPARKWitnesses { 
                    addresses: matrix_witnesses.row_witness.clone(), 
                    read_time_stamps: time_stamp_witnesses.read_ts_row_witness.clone(), 
                    values: e_witnesses.e_rx_witness.clone(), 
                    final_counters: time_stamp_witnesses.final_cts_row_witness.clone() 
                },
            },
            colwise: SPARKValuesAndWitnesses { 
                values: SPARKValues { 
                    addresses: matrix_values.col_values.clone(), 
                    read_time_stamps: time_stamp_values.read_ts_col_values.clone(),
                    values: e_values.e_ry_values.clone(), 
                    final_counters: time_stamp_values.final_cts_col_values.clone(), 
                    memory: e_values.eq_ry_values.clone(), 
                },
                witnesses: SPARKWitnesses { 
                    addresses: matrix_witnesses.col_witness.clone(), 
                    read_time_stamps: time_stamp_witnesses.read_ts_col_witness.clone(), 
                    values: e_witnesses.e_ry_witness.clone(), 
                    final_counters: time_stamp_witnesses.final_cts_col_witness.clone() 
                },
            },
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
        let mut row_spark   = Vec::<FieldElement>::new();
        let mut col_spark = Vec::<FieldElement>::new();
        let mut val_spark = Vec::<FieldElement>::new();

        for ((r, c), value) in s.iter() {
            row_spark.push(FieldElement::from(r as u64));
            col_spark.push(FieldElement::from(c as u64));
            val_spark.push(value.clone());
        }

        row_spark = pad_to_power_of_two(row_spark);
        col_spark = pad_to_power_of_two(col_spark);
        val_spark = pad_to_power_of_two(val_spark);

        let committer = CommitmentWriter::new(whir_config_a);
        
        (MatrixWitnesses {
            row_witness: Self::commit_to_vector(&committer, merlin, row_spark.clone()),
            col_witness: Self::commit_to_vector(&committer, merlin, col_spark.clone()),
            val_witness: Self::commit_to_vector(&committer, merlin, val_spark.clone()),
        }, 
        MatrixValues {
            row_values: row_spark,
            col_values: col_spark,
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
            eq_rx_values: eq_rx,
            eq_ry_values: eq_ry,
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

    pub fn calculate_timestamp_witnesses(
        s: &HydratedSparseMatrix, 
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>, 
        whir_config_a: WhirConfig,
        whir_config_row: WhirConfig,
        whir_config_col: WhirConfig,
    ) -> (TimeStampWitnesses, TimeStampValues) {
        let mut read_ts_row_counters = vec![0; s.matrix.num_rows];
        let mut read_ts_row = Vec::<FieldElement>::new();

        let mut read_ts_col_counters = vec![0; s.matrix.num_cols];
        let mut read_ts_col = Vec::<FieldElement>::new();

        // Note: Possible optimization: this can be done once when the matrix is created.
        for ((r, c), _) in s.iter() {
            read_ts_row.push(FieldElement::from(read_ts_row_counters[r] as u64));
            read_ts_row_counters[r] += 1;
            read_ts_col.push(FieldElement::from(read_ts_col_counters[c] as u64));
            read_ts_col_counters[c] += 1;
        }
        read_ts_row = pad_to_power_of_two(read_ts_row);
        read_ts_col = pad_to_power_of_two(read_ts_col);
        
        let final_cts_row = read_ts_row_counters
            .iter()
            .map(|&x| FieldElement::from(x as u64))
            .collect::<Vec<_>>();
        let final_cts_row = pad_to_power_of_two(final_cts_row);

        let final_cts_col = read_ts_col_counters
            .iter()
            .map(|&x| FieldElement::from(x as u64))
            .collect::<Vec<_>>();
        let final_cts_col = pad_to_power_of_two(final_cts_col);

        let committer = CommitmentWriter::new(whir_config_a);
        let committer_row = CommitmentWriter::new(whir_config_row);
        let committer_col = CommitmentWriter::new(whir_config_col);

        (TimeStampWitnesses {
            read_ts_row_witness: Self::commit_to_vector(&committer, merlin, read_ts_row.clone()),
            read_ts_col_witness: Self::commit_to_vector(&committer, merlin, read_ts_col.clone()),
            final_cts_row_witness: Self::commit_to_vector(&committer_row, merlin, final_cts_row.clone()),
            final_cts_col_witness: Self::commit_to_vector(&committer_col, merlin, final_cts_col.clone()),
        }, 
        TimeStampValues {
            read_ts_row_values: read_ts_row,
            read_ts_col_values: read_ts_col,
            final_cts_row_values: final_cts_row,
            final_cts_col_values: final_cts_col,
        })
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
    pub row_values: Vec<FieldElement>,
    pub col_values: Vec<FieldElement>,
    pub val_values: Vec<FieldElement>,
}

pub struct MatrixWitnesses {
    pub row_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
    pub col_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
    pub val_witness: Witness<FieldElement, SkyscraperMerkleConfig>
}

pub struct EValues {
    pub e_rx_values: Vec<FieldElement>,
    pub e_ry_values: Vec<FieldElement>,
    pub eq_rx_values: Vec<FieldElement>,
    pub eq_ry_values: Vec<FieldElement>,
}

pub struct EWitnesses {
    pub e_rx_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
    pub e_ry_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
}

pub trait SparkIOPattern<F: FftField, MerkleConfig: Config>{
    fn spark<PowStrategy>(
        self, 
        whir_config_num_terms: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
        whir_config_row: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
        whir_config_col: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
    ) -> Self;
    fn spark_commit<PowStrategy>(
        self, 
        whir_config_num_terms: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
        whir_config_row: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
        whir_config_col: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
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
        whir_config_row: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
        whir_config_col: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
    ) -> Self {
        let io = self
            .spark_commit(
                whir_config_num_terms,
                whir_config_row,
                whir_config_col,
            );
        io
    }

    fn spark_commit<PowStrategy> (
        self, 
        whir_config_num_terms: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
        whir_config_row: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
        whir_config_col: &GenericWhirConfig<F, MerkleConfig, PowStrategy>,
    ) -> Self {
        let io = self
            .commit_statement(whir_config_num_terms)
            .commit_statement(whir_config_num_terms)
            .commit_statement(whir_config_num_terms)
            .commit_statement(whir_config_num_terms)
            .commit_statement(whir_config_num_terms)
            .commit_statement(whir_config_num_terms)
            .commit_statement(whir_config_num_terms)
            .commit_statement(whir_config_row)
            .commit_statement(whir_config_col);
        io
    }
}

pub fn verify_spark(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    whir_config_terms: &WhirConfig,
    whir_config_row: &WhirConfig,
    whir_config_col: &WhirConfig,
) {
    let spark_commitments = parse_spark_commitments(
        arthur,
        whir_config_row,
        whir_config_col,
        whir_config_terms,
    );
}

pub fn parse_spark_commitments (
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    whir_config_row: &WhirConfig,
    whir_config_col: &WhirConfig,
    whir_config_terms: &WhirConfig,
) -> SparkCommitments{
    let commitment_reader_row = CommitmentReader::new(whir_config_row);
    let commitment_reader_col = CommitmentReader::new(whir_config_col);
    let commitment_reader_a = CommitmentReader::new(whir_config_terms);
    
    let row_commitment = commitment_reader_a.parse_commitment(arthur).unwrap();
    let col_commitment = commitment_reader_a.parse_commitment(arthur).unwrap();
    let val_commitment = commitment_reader_a.parse_commitment(arthur).unwrap();
    let e_rx_commitment = commitment_reader_a.parse_commitment(arthur).unwrap();
    let e_ry_commitment = commitment_reader_a.parse_commitment(arthur).unwrap();
    let read_ts_row_commitment = commitment_reader_a.parse_commitment(arthur).unwrap();
    let read_ts_col_commitment = commitment_reader_a.parse_commitment(arthur).unwrap();
    let final_cts_row_commitment = commitment_reader_row.parse_commitment(arthur).unwrap();
    let final_cts_col_commitment = commitment_reader_col.parse_commitment(arthur).unwrap();
    
    SparkCommitments {
        rowwise: MemoryCheckCommitments {
            rs_ws: SparkWhirRSWSCommitments {
                addr_commitment:    row_commitment.clone(),
                value_commitment:      e_rx_commitment.clone(),
                time_stamp_commitment: read_ts_row_commitment.clone(),
            },
            final_cts: final_cts_row_commitment,
        },

        colwise: MemoryCheckCommitments {
            rs_ws: SparkWhirRSWSCommitments {
                addr_commitment:    col_commitment.clone(),
                value_commitment:      e_ry_commitment.clone(),
                time_stamp_commitment: read_ts_col_commitment.clone(),
            },
            final_cts: final_cts_col_commitment,
        },

        sumcheck: SparkSumcheckCommitments {
            value_commitment: val_commitment,
            e_rx_commitment:  e_rx_commitment,
            e_ry_commitment:  e_ry_commitment,
        },
    }
}

pub struct SparkCommitments {
    sumcheck: SparkSumcheckCommitments,
    rowwise: MemoryCheckCommitments,
    colwise: MemoryCheckCommitments,
}

pub struct MemoryCheckCommitments {
    rs_ws: SparkWhirRSWSCommitments,
    final_cts: ParsedCommitment<FieldElement, FieldElement>,
}

pub struct SparkWhirRSWSCommitments {
    addr_commitment:    ParsedCommitment<FieldElement, FieldElement>,
    value_commitment:  ParsedCommitment<FieldElement, FieldElement>,
    time_stamp_commitment: ParsedCommitment<FieldElement, FieldElement>,
}

pub struct SparkSumcheckCommitments {
    value_commitment: ParsedCommitment<FieldElement, FieldElement>,
    e_rx_commitment:  ParsedCommitment<FieldElement, FieldElement>,
    e_ry_commitment:  ParsedCommitment<FieldElement, FieldElement>,
}

pub struct TimeStampWitnesses {
    pub read_ts_row_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
    pub read_ts_col_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
    pub final_cts_row_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
    pub final_cts_col_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
}

pub struct TimeStampValues {
    pub read_ts_row_values: Vec<FieldElement>,
    pub read_ts_col_values: Vec<FieldElement>,
    pub final_cts_row_values: Vec<FieldElement>,
    pub final_cts_col_values: Vec<FieldElement>,
}

pub struct SPARKValuesAndWitnesses {
    pub values: SPARKValues,
    pub witnesses: SPARKWitnesses,
}

#[derive(Clone)]
pub struct SPARKValues {
    pub addresses: Vec<FieldElement>,
    pub read_time_stamps: Vec<FieldElement>,
    pub values: Vec<FieldElement>,
    pub final_counters: Vec<FieldElement>,
    pub memory: Vec<FieldElement>,
}

#[derive(Clone)]
pub struct SPARKWitnesses {
    pub addresses: Witness<FieldElement, SkyscraperMerkleConfig>,
    pub read_time_stamps: Witness<FieldElement, SkyscraperMerkleConfig>,
    pub values: Witness<FieldElement, SkyscraperMerkleConfig>,
    pub final_counters: Witness<FieldElement, SkyscraperMerkleConfig>,
}