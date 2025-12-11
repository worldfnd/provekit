use {
    provekit_common::{utils::next_power_of_two, WhirConfig, WhirR1CSScheme, R1CS},
    spartan_vm::compiler::r1cs_gen::R1CS as SpartanR1CS,
    std::sync::Arc,
    whir::{
        ntt::RSDefault,
        parameters::{
            default_max_pow, DeduplicationStrategy, FoldingFactor, MerkleProofStrategy,
            MultivariateParameters, ProtocolParameters, SoundnessType,
        },
    },
};

// Minimum log2 of the WHIR evaluation domain (lower bound for m).
const MIN_WHIR_NUM_VARIABLES: usize = 12;
// Minimum number of variables in the sumcheck's multilinear polynomial (lower
// bound for m_0).
const MIN_SUMCHECK_NUM_VARIABLES: usize = 1;

pub trait WhirR1CSSchemeBuilder {
    fn new_for_r1cs(r1cs: &R1CS) -> Self;

    /// Create a WhirR1CSScheme directly from spartan R1CS dimensions.
    /// This avoids the expensive R1CS conversion step.
    fn new_from_spartan_r1cs(r1cs: &SpartanR1CS) -> Self;

    /// Create a WhirR1CSScheme from raw R1CS dimensions.
    /// - `num_witnesses`: number of witnesses (columns) in the R1CS matrices
    /// - `num_constraints`: number of constraints (rows) in the R1CS matrices
    /// - `a_num_entries`: number of non-zero entries in matrix A
    fn new_from_dimensions(num_witnesses: usize, num_constraints: usize, a_num_entries: usize)
        -> Self;

    fn new_whir_config_for_size(num_variables: usize, batch_size: usize) -> WhirConfig;
}

impl WhirR1CSSchemeBuilder for WhirR1CSScheme {
    fn new_for_r1cs(r1cs: &R1CS) -> Self {
        Self::new_from_dimensions(
            r1cs.num_witnesses(),
            r1cs.num_constraints(),
            r1cs.a().iter().count(),
        )
    }

    fn new_from_spartan_r1cs(r1cs: &SpartanR1CS) -> Self {
        let num_witnesses = r1cs.witness_layout.size();
        let num_constraints = r1cs.constraints.len();
        let a_num_entries: usize = r1cs.constraints.iter().map(|c| c.a.len()).sum();

        Self::new_from_dimensions(num_witnesses, num_constraints, a_num_entries)
    }

    fn new_from_dimensions(
        num_witnesses: usize,
        num_constraints: usize,
        a_num_entries: usize,
    ) -> Self {
        // m_raw is equal to ceiling(log(number of variables in constraint system)). It
        // is equal to the log of the width of the matrices.
        let m_raw = next_power_of_two(num_witnesses);

        // m0_raw is equal to ceiling(log(number_of_constraints)). It is equal to the
        // number of variables in the multilinear polynomial we are running our sumcheck
        // on.
        let m0_raw = next_power_of_two(num_constraints);

        let m = m_raw.max(MIN_WHIR_NUM_VARIABLES);
        let m_0 = m0_raw.max(MIN_SUMCHECK_NUM_VARIABLES);

        // Whir parameters
        Self {
            m: m + 1,
            m_0,
            a_num_terms: next_power_of_two(a_num_entries),
            whir_witness: Self::new_whir_config_for_size(m + 1, 2),
            whir_for_hiding_spartan: Self::new_whir_config_for_size(
                next_power_of_two(4 * m_0) + 1,
                2,
            ),
        }
    }

    fn new_whir_config_for_size(num_variables: usize, batch_size: usize) -> WhirConfig {
        let nv = num_variables.max(MIN_WHIR_NUM_VARIABLES);

        let mv_params = MultivariateParameters::new(nv);
        let whir_params = ProtocolParameters {
            initial_statement: true,
            security_level: 128,
            pow_bits: default_max_pow(nv, 1),
            folding_factor: FoldingFactor::Constant(4),
            leaf_hash_params: (),
            two_to_one_params: (),
            soundness_type: SoundnessType::ConjectureList,
            _pow_parameters: Default::default(),
            starting_log_inv_rate: 1,
            batch_size,
            deduplication_strategy: DeduplicationStrategy::Disabled,
            merkle_proof_strategy: MerkleProofStrategy::Uncompressed,
        };
        let reed_solomon = Arc::new(RSDefault);
        let basefield_reed_solomon = reed_solomon.clone();
        WhirConfig::new(reed_solomon, basefield_reed_solomon, mv_params, whir_params)
    }
}
