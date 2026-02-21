use {
    provekit_common::{utils::next_power_of_two, WhirR1CSScheme, WhirZkConfig, R1CS},
    whir::parameters::{
        default_max_pow, FoldingFactor, MultivariateParameters, ProtocolParameters, SoundnessType,
    },
};

// Minimum log2 of the WHIR evaluation domain (lower bound for m).
const MIN_WHIR_NUM_VARIABLES: usize = 14;
// Minimum number of variables in the sumcheck's multilinear polynomial (lower
// bound for m_0).
const MIN_SUMCHECK_NUM_VARIABLES: usize = 1;

pub trait WhirR1CSSchemeBuilder {
    fn new_for_r1cs(
        r1cs: &R1CS,
        w1_size: usize,
        num_challenges: usize,
        has_public_inputs: bool,
    ) -> Self;

    fn new_whir_zk_config_for_size(num_variables: usize, num_polynomials: usize) -> WhirZkConfig;
}

impl WhirR1CSSchemeBuilder for WhirR1CSScheme {
    fn new_for_r1cs(
        r1cs: &R1CS,
        w1_size: usize,
        num_challenges: usize,
        has_public_inputs: bool,
    ) -> Self {
        let total_witnesses = r1cs.num_witnesses();
        assert!(
            w1_size <= total_witnesses,
            "w1_size exceeds total witnesses"
        );
        let w2_size = total_witnesses - w1_size;

        let m1_raw = next_power_of_two(w1_size);
        let m2_raw = next_power_of_two(w2_size);
        let m0_raw = next_power_of_two(r1cs.num_constraints());

        let m_raw = m1_raw.max(m2_raw).max(MIN_WHIR_NUM_VARIABLES);
        let m_0 = m0_raw.max(MIN_SUMCHECK_NUM_VARIABLES);

        Self {
            m: m_raw,
            w1_size,
            m_0,
            a_num_terms: next_power_of_two(r1cs.a().iter().count()),
            num_challenges,
            whir_witness: Self::new_whir_zk_config_for_size(m_raw, 1),
            whir_for_hiding_spartan: Self::new_whir_zk_config_for_size(
                next_power_of_two(4 * m_0),
                1,
            ),
            has_public_inputs,
        }
    }

    fn new_whir_zk_config_for_size(num_variables: usize, num_polynomials: usize) -> WhirZkConfig {
        let nv = num_variables.max(MIN_WHIR_NUM_VARIABLES);

        let mv_params = MultivariateParameters::new(nv);
        let whir_params = ProtocolParameters {
            initial_statement:     true,
            security_level:        128,
            pow_bits:              default_max_pow(nv, 1),
            folding_factor:        FoldingFactor::Constant(4),
            soundness_type:        SoundnessType::ConjectureList,
            starting_log_inv_rate: 1,
            batch_size:            1,
            hash_id:               whir::hash::SHA2,
        };
        WhirZkConfig::new(
            mv_params,
            &whir_params,
            FoldingFactor::Constant(1),
            num_polynomials,
        )
    }
}
