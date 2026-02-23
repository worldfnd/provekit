use {
    ark_poly::{EvaluationDomain, GeneralEvaluationDomain},
    provekit_common::{FieldElement, PublicInputs, WhirConfig, WhirR1CSProof},
    serde::{Deserialize, Serialize},
    std::{fs::File, io::Write},
    tracing::instrument,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct GnarkConfig {
    pub whir_config_witness: WHIRConfigGnark,
    pub log_num_constraints: usize,
    pub log_num_variables:   usize,
    pub log_a_num_terms:     usize,
    pub narg_string:         Vec<u8>,
    pub narg_string_len:     usize,
    pub hints:               Vec<u8>,
    pub hints_len:           usize,
    pub num_challenges:      usize,
    pub w1_size:             usize,
    pub public_inputs:       PublicInputs,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WHIRConfigGnark {
    /// Number of WHIR rounds.
    pub n_rounds:               usize,
    /// Reed-Solomon rate (log₂ of inverse rate).
    pub rate:                   usize,
    /// Number of variables in the multilinear polynomial.
    pub n_vars:                 usize,
    /// Folding factor per round.
    pub folding_factor:         Vec<usize>,
    /// Out-of-domain samples per round.
    pub ood_samples:            Vec<usize>,
    /// Number of queries per round.
    pub num_queries:            Vec<usize>,
    /// Proof-of-work bits per round.
    pub pow_bits:               Vec<i32>,
    /// Final round query count.
    pub final_queries:          usize,
    /// Final round proof-of-work bits.
    pub final_pow_bits:         i32,
    /// Final folding proof-of-work bits.
    pub final_folding_pow_bits: i32,
    /// Domain generator as a string.
    pub domain_generator:       String,
    /// Batch size (number of polynomials committed together).
    pub batch_size:             usize,
}

impl WHIRConfigGnark {
    pub fn new(whir_params: &WhirConfig) -> Self {
        let n_rounds = whir_params.n_rounds();
        let n_vars = whir_params.initial_num_variables();
        let rate = whir_params.initial_committer.expansion.ilog2() as usize;

        // Folding factor: initial round uses initial_sumcheck.num_rounds,
        // subsequent rounds use round_configs[i].sumcheck.num_rounds
        let mut folding_factor = Vec::with_capacity(n_rounds + 1);
        folding_factor.push(whir_params.initial_sumcheck.num_rounds);
        for rc in &whir_params.round_configs {
            folding_factor.push(rc.sumcheck.num_rounds);
        }

        let ood_samples: Vec<usize> = whir_params
            .round_configs
            .iter()
            .map(|rc| rc.irs_committer.out_domain_samples)
            .collect();

        let num_queries: Vec<usize> = whir_params
            .round_configs
            .iter()
            .map(|rc| rc.irs_committer.in_domain_samples)
            .collect();

        let pow_bits: Vec<i32> = whir_params
            .round_configs
            .iter()
            .map(|rc| {
                f64::from(whir::protocols::proof_of_work::difficulty(rc.pow.threshold)) as i32
            })
            .collect();

        let final_queries = whir_params.final_in_domain_samples();
        let final_pow_bits = f64::from(whir::protocols::proof_of_work::difficulty(
            whir_params.final_pow.threshold,
        )) as i32;
        let final_folding_pow_bits = f64::from(whir::protocols::proof_of_work::difficulty(
            whir_params.final_sumcheck.round_pow.threshold,
        )) as i32;

        // Reconstruct the starting domain to get its generator
        let domain = GeneralEvaluationDomain::<FieldElement>::new((1 << n_vars) << rate)
            .expect("Should have found an appropriate domain");
        let domain_generator = format!("{}", domain.group_gen());

        let batch_size = whir_params.initial_committer.num_vectors;

        WHIRConfigGnark {
            n_rounds,
            rate,
            n_vars,
            folding_factor,
            ood_samples,
            num_queries,
            pow_bits,
            final_queries,
            final_pow_bits,
            final_folding_pow_bits,
            domain_generator,
            batch_size,
        }
    }
}

#[instrument(skip_all)]
pub fn gnark_parameters(
    whir_params_witness: &WhirConfig,
    proof: &WhirR1CSProof,
    m_0: usize,
    m: usize,
    a_num_terms: usize,
    num_challenges: usize,
    w1_size: usize,
    public_inputs: &PublicInputs,
) -> GnarkConfig {
    GnarkConfig {
        whir_config_witness: WHIRConfigGnark::new(whir_params_witness),
        log_num_constraints: m_0,
        log_num_variables: m,
        log_a_num_terms: a_num_terms,
        narg_string: proof.narg_string.clone(),
        narg_string_len: proof.narg_string.len(),
        hints: proof.hints.clone(),
        hints_len: proof.hints.len(),
        num_challenges,
        w1_size,
        public_inputs: public_inputs.clone(),
    }
}

#[instrument(skip_all)]
pub fn write_gnark_parameters_to_file(
    whir_params_witness: &WhirConfig,
    proof: &WhirR1CSProof,
    m_0: usize,
    m: usize,
    a_num_terms: usize,
    num_challenges: usize,
    w1_size: usize,
    public_inputs: &PublicInputs,
    file_path: &str,
) {
    let gnark_config = gnark_parameters(
        whir_params_witness,
        proof,
        m_0,
        m,
        a_num_terms,
        num_challenges,
        w1_size,
        public_inputs,
    );
    let mut file_params = File::create(file_path).unwrap();
    file_params
        .write_all(serde_json::to_string(&gnark_config).unwrap().as_bytes())
        .expect("Writing gnark parameters to a file failed");
}
