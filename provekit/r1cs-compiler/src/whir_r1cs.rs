use {
    provekit_common::{utils::next_power_of_two, WhirConfig, WhirR1CSScheme, WhirZkConfig, R1CS},
    whir::parameters::{
        default_max_pow, FoldingFactor, MultivariateParameters, ProtocolParameters, SoundnessType,
    },
};

const MIN_WHIR_NUM_VARIABLES: usize = 12;
const MIN_SUMCHECK_NUM_VARIABLES: usize = 1;

pub trait WhirR1CSSchemeBuilder {
    fn new_for_r1cs(
        r1cs: &R1CS,
        w1_size: usize,
        num_challenges: usize,
        has_public_inputs: bool,
    ) -> Self;
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

        let (whir_witness_blinded, whir_witness_blinding) = new_whir_zk_config_for_size(m_raw, 1);
        let (whir_spartan_blinded, whir_spartan_blinding) =
            new_whir_zk_config_for_size(next_power_of_two(4 * m_0), 1);

        Self {
            m: m_raw,
            w1_size,
            m_0,
            a_num_terms: next_power_of_two(r1cs.a().iter().count()),
            num_challenges,
            has_public_inputs,
            whir_witness_blinded,
            whir_witness_blinding,
            whir_spartan_blinded,
            whir_spartan_blinding,
        }
    }
}

fn new_whir_zk_config_for_size(
    num_variables: usize,
    num_polynomials: usize,
) -> (WhirConfig, WhirConfig) {
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

    let zk_config = WhirZkConfig::new(
        mv_params,
        &whir_params,
        FoldingFactor::Constant(1),
        num_polynomials,
    );
    (zk_config.blinded_commitment, zk_config.blinding_commitment)
}
