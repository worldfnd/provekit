use serde::{Deserialize, Serialize};
use crate::WhirConfig;
use ark_poly::EvaluationDomain;

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
    /// batch size
    pub batch_size:             usize,
}

impl WHIRConfigGnark {
    pub fn new(whir_params: &WhirConfig) -> Self {
        WHIRConfigGnark {
            n_rounds:               whir_params
                .folding_factor
                .compute_number_of_rounds(whir_params.mv_parameters.num_variables)
                .0,
            rate:                   whir_params.starting_log_inv_rate,
            n_vars:                 whir_params.mv_parameters.num_variables,
            folding_factor:         (0..(whir_params
                .folding_factor
                .compute_number_of_rounds(whir_params.mv_parameters.num_variables)
                .0))
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
            batch_size:             whir_params.batch_size,
        }
    }
}