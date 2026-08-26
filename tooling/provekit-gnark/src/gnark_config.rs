use {
    ark_poly::{EvaluationDomain, GeneralEvaluationDomain},
    provekit_backend_bn254::{Bn254Field, FieldElement, WhirConfig},
    provekit_common::{PublicInputs, WhirR1CSProof, WhirR1CSScheme},
    serde::{Deserialize, Serialize},
    std::{fs::File, io::Write},
    tracing::{instrument, warn},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct GnarkConfig {
    /// WHIR config for the non-hiding witness commitment. `blinded_` is the
    /// historical (format-1.x zkWHIR) wire name, kept for Go compatibility.
    pub blinded_commitment_whir_config: WHIRConfigGnark,
    /// WHIR config for the Spartan blinding polynomial `g` commitment.
    pub blinding_commitment_whir_config: WHIRConfigGnark,
    pub log_num_constraints: usize,
    pub log_num_variables: usize,
    pub log_a_num_terms: usize,
    pub narg_string: Vec<u8>,
    pub narg_string_len: usize,
    pub hints: Vec<u8>,
    pub hints_len: usize,
    pub protocol_id: Vec<u8>,
    pub num_challenges: usize,
    pub challenge_offsets: Vec<usize>,
    pub w1_size: usize,
    pub public_inputs: PublicInputs<FieldElement>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WHIRConfigGnark {
    /// Number of WHIR rounds.
    pub n_rounds: usize,
    /// Reed-Solomon rate (log₂ of inverse rate).
    pub rate: usize,
    /// Number of variables in the multilinear polynomial.
    pub n_vars: usize,
    /// Folding factor per round.
    pub folding_factor: Vec<usize>,
    /// Out-of-domain samples per round.
    pub ood_samples: Vec<usize>,
    /// Number of queries per round.
    pub num_queries: Vec<usize>,
    /// Proof-of-work bits per round (truncated integer, kept for backwards
    /// compat).
    pub pow_bits: Vec<i32>,
    /// Proof-of-work u64 thresholds per WHIR round (exact values from Rust).
    pub pow_thresholds: Vec<u64>,
    /// Sumcheck round PoW thresholds per WHIR round.
    pub sumcheck_pow_thresholds: Vec<u64>,
    /// Initial sumcheck round PoW threshold.
    pub initial_sumcheck_pow_threshold: u64,
    /// Initial skip PoW threshold (used when initial sumcheck is skipped).
    pub initial_skip_pow_threshold: u64,
    /// Final round query count.
    pub final_queries: usize,
    /// Final round proof-of-work bits (truncated integer).
    pub final_pow_bits: i32,
    /// Final round proof-of-work threshold (exact u64).
    pub final_pow_threshold: u64,
    /// Final folding proof-of-work bits (truncated integer).
    pub final_folding_pow_bits: i32,
    /// Final folding proof-of-work threshold (exact u64).
    pub final_folding_pow_threshold: u64,
    /// Domain generator as a string.
    pub domain_generator: String,
    /// Batch size (number of polynomials committed together).
    pub batch_size: usize,
    /// Initial committer in-domain samples (WHIR in-domain query count).
    pub initial_in_domain_samples: usize,
}

impl WHIRConfigGnark {
    pub fn new(whir_params: &WhirConfig) -> Self {
        let n_rounds = whir_params.n_rounds();
        let n_vars = whir_params.initial_num_variables();
        let message_length = whir_params.initial_committer.vector_size()
            / whir_params.initial_committer.interleaving_depth();
        let rate =
            (whir_params.initial_committer.codeword_length() / message_length).ilog2() as usize;

        // Folding factor: initial round uses initial_sumcheck.num_rounds,
        // subsequent rounds use round_configs[i].sumcheck.num_rounds
        let mut folding_factor = Vec::with_capacity(n_rounds + 1);
        folding_factor.push(whir_params.initial_sumcheck.num_rounds());
        for rc in &whir_params.round_configs {
            folding_factor.push(rc.sumcheck.num_rounds());
        }

        let ood_samples: Vec<usize> = whir_params
            .round_configs
            .iter()
            .map(|rc| rc.out_domain_samples)
            .collect();

        let num_queries: Vec<usize> = whir_params
            .round_configs
            .iter()
            .map(|rc| rc.irs_committer.in_domain_samples())
            .collect();

        let pow_bits: Vec<i32> = whir_params
            .round_configs
            .iter()
            .map(|rc| {
                f64::from(whir::protocols::proof_of_work::difficulty(rc.pow.threshold)) as i32
            })
            .collect();
        let pow_thresholds: Vec<u64> = whir_params
            .round_configs
            .iter()
            .map(|rc| rc.pow.threshold)
            .collect();
        let sumcheck_pow_thresholds: Vec<u64> = whir_params
            .round_configs
            .iter()
            .map(|rc| rc.sumcheck.round_pow().threshold)
            .collect();
        let initial_sumcheck_pow_threshold = whir_params.initial_sumcheck.round_pow().threshold;
        let initial_skip_pow_threshold = whir_params.initial_skip_pow.threshold;

        // If there are no folding rounds, fall back to the initial commitment's
        // in-domain samples.
        let final_queries = whir_params
            .round_configs
            .last()
            .map_or(whir_params.initial_committer.in_domain_samples(), |rc| {
                rc.irs_committer.in_domain_samples()
            });
        let final_pow_bits = f64::from(whir::protocols::proof_of_work::difficulty(
            whir_params.final_pow.threshold,
        )) as i32;
        let final_folding_pow_bits = f64::from(whir::protocols::proof_of_work::difficulty(
            whir_params.final_sumcheck.round_pow().threshold,
        )) as i32;

        // Reconstruct the starting domain to get its generator
        let domain = GeneralEvaluationDomain::<FieldElement>::new((1 << n_vars) << rate)
            .expect("Should have found an appropriate domain");
        let domain_generator = format!("{}", domain.group_gen());

        let batch_size = whir_params.initial_committer.num_vectors();
        let initial_in_domain_samples = whir_params.initial_committer.in_domain_samples();

        WHIRConfigGnark {
            n_rounds,
            rate,
            n_vars,
            folding_factor,
            ood_samples,
            num_queries,
            pow_bits,
            pow_thresholds,
            sumcheck_pow_thresholds,
            initial_sumcheck_pow_threshold,
            initial_skip_pow_threshold,
            final_queries,
            final_pow_bits,
            final_pow_threshold: whir_params.final_pow.threshold,
            final_folding_pow_bits,
            final_folding_pow_threshold: whir_params.final_sumcheck.round_pow().threshold,
            domain_generator,
            batch_size,
            initial_in_domain_samples,
        }
    }
}

#[instrument(skip_all)]
pub fn gnark_parameters(
    scheme: &WhirR1CSScheme<Bn254Field>,
    blinded_commitment: &WhirConfig,
    blinding_commitment: &WhirConfig,
    proof: &WhirR1CSProof,
    m_0: usize,
    m: usize,
    a_num_terms: usize,
    num_challenges: usize,
    w1_size: usize,
    public_inputs: &PublicInputs<FieldElement>,
) -> GnarkConfig {
    let ds = scheme.create_domain_separator();
    let protocol_id: Vec<u8> = ds.protocol_id.to_vec();
    GnarkConfig {
        blinded_commitment_whir_config: WHIRConfigGnark::new(blinded_commitment),
        blinding_commitment_whir_config: WHIRConfigGnark::new(blinding_commitment),
        log_num_constraints: m_0,
        log_num_variables: m,
        log_a_num_terms: a_num_terms,
        narg_string: proof.narg_string.clone(),
        narg_string_len: proof.narg_string.len(),
        hints: proof.hints.clone(),
        hints_len: proof.hints.len(),
        protocol_id,
        num_challenges,
        challenge_offsets: scheme.challenge_offsets.clone(),
        w1_size,
        public_inputs: public_inputs.clone(),
    }
}

#[instrument(skip_all)]
pub fn write_gnark_parameters_to_file(
    scheme: &WhirR1CSScheme<Bn254Field>,
    blinded_commitment: &WhirConfig,
    blinding_commitment: &WhirConfig,
    proof: &WhirR1CSProof,
    m_0: usize,
    m: usize,
    a_num_terms: usize,
    num_challenges: usize,
    w1_size: usize,
    public_inputs: &PublicInputs<FieldElement>,
    file_path: &str,
) {
    warn!(
        "Writing gnark parameters in the proof-format-2.0 split witness/blinding commitment \
         layout. The Go recursive-verifier still expects the old fused zkWHIR commitment layout, \
         so it deserializes these parameters without error but fails verification silently. These \
         files will not verify on the Go side until the paired recursive-verifier update lands."
    );
    let gnark_config = gnark_parameters(
        scheme,
        blinded_commitment,
        blinding_commitment,
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
