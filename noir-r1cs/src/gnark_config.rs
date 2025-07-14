use {
    crate::{
        whir_r1cs::{IOPattern, WhirConfig},
        FieldElement,
    },
    ark_poly::EvaluationDomain,
    serde::{Deserialize, Serialize},
    std::{fs::File, io::Write as _},
    tracing::instrument,
};

#[derive(Debug, Serialize, Deserialize)]
/// Configuration for Gnark
pub struct GnarkConfig {
    /// WHIR parameters for column
    pub whir_config_col:            WHIRConfigGnark,
    /// WHIR parameters for number of terms in the matrix A
    pub whir_config_a_num_terms:    WHIRConfigGnark,
    /// log of number of constraints in R1CS
    pub log_num_constraints:    usize,
    /// nimue input output pattern
    pub io_pattern:             String,
    /// transcript in byte form
    pub transcript:             Vec<u8>,
    /// length of the transcript
    pub transcript_len:         usize,
    /// statement evaluations
    pub statement_evaluations:  Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]

pub struct WHIRConfigGnark {
    /// number of rounds
    pub n_rounds:               usize,
    /// rate
    pub rate:                   usize,
    /// number of variables
    pub n_vars:                 usize,
    /// folding factor
    pub folding_factor:         Vec<usize>,
    /// out of domain samples
    pub ood_samples:            Vec<usize>,
    /// number of queries
    pub num_queries:            Vec<usize>,
    /// proof of work bits
    pub pow_bits:               Vec<i32>,
    /// final queries
    pub final_queries:          usize,
    /// final proof of work bits
    pub final_pow_bits:         i32,
    /// final folding proof of work bits
    pub final_folding_pow_bits: i32,
    /// domain generator string
    pub domain_generator:       String,
}

impl WHIRConfigGnark {
    pub fn new (whir_params: &WhirConfig) -> Self {
        WHIRConfigGnark {
            n_rounds:               whir_params.folding_factor.compute_number_of_rounds(whir_params.mv_parameters.num_variables).0,
            rate:                   whir_params.starting_log_inv_rate,
            n_vars:                 whir_params.mv_parameters.num_variables,
            folding_factor:         (0..(whir_params.folding_factor.compute_number_of_rounds(whir_params.mv_parameters.num_variables).0))
            .map(|round| whir_params.folding_factor.at_round(round))
            .collect(),
            ood_samples:            whir_params
            .round_parameters
            .iter()
            .map(|x| x.ood_samples)
            .collect(),
            num_queries:            whir_params
            .round_parameters
            .iter()
            .map(|x| x.num_queries)
            .collect(),
            pow_bits:               whir_params
            .round_parameters
            .iter()
            .map(|x| x.pow_bits as i32)
            .collect(),
            final_queries:          whir_params.final_queries,
            final_pow_bits:         whir_params.final_pow_bits as i32,
            final_folding_pow_bits: whir_params.final_folding_pow_bits as i32,
            domain_generator:       format!(
                "{}",
                whir_params.starting_domain.backing_domain.group_gen()
            ),
        }
    }
}


/// Writes config used for Gnark circuit to a file
#[instrument(skip_all)]
pub fn gnark_parameters(
    whir_params_col: &WhirConfig,
    whir_params_a_num_terms: &WhirConfig,
    transcript: &[u8],
    io: &IOPattern,
    sums: [FieldElement; 3],
    m_0: usize,
    m: usize,
) -> GnarkConfig {
    GnarkConfig {
        whir_config_col: WHIRConfigGnark::new(whir_params_col),
        whir_config_a_num_terms: WHIRConfigGnark::new(whir_params_a_num_terms),
        log_num_constraints: m_0,
        io_pattern:             String::from_utf8(io.as_bytes().to_vec()).unwrap(),
        transcript:             transcript.to_vec(),
        transcript_len:         transcript.to_vec().len(),
        statement_evaluations:  vec![
            sums[0].to_string(),
            sums[1].to_string(),
            sums[2].to_string(),
        ],
    }
}

/// Writes config used for Gnark circuit to a file
#[instrument(skip_all)]
pub fn write_gnark_parameters_to_file(
    whir_params_col: &WhirConfig,
    whir_params_a_num_terms: &WhirConfig,
    transcript: &[u8],
    io: &IOPattern,
    sums: [FieldElement; 3],
    m_0: usize,
    m: usize,
    file_path: &str,
) {
    let gnark_config = gnark_parameters(whir_params_col, whir_params_a_num_terms, transcript, io, sums, m_0, m);
    println!("round config {:?}", whir_params_col.round_parameters);
    let mut file_params = File::create(file_path).unwrap();
    file_params
        .write_all(serde_json::to_string(&gnark_config).unwrap().as_bytes())
        .expect("Writing gnark parameters to a file failed");
}
