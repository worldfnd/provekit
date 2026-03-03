use {
    mavros_artifacts::R1CS as MavrosR1CS,
    provekit_common::{utils::next_power_of_two, WhirR1CSScheme, WhirZkConfig, R1CS},
    whir::{engines::EngineId, parameters::ProtocolParameters},
};

const MIN_WHIR_NUM_VARIABLES: usize = 13;
const MIN_SUMCHECK_NUM_VARIABLES: usize = 1;

pub trait WhirR1CSSchemeBuilder {
    fn new_for_r1cs(
        r1cs: &R1CS,
        w1_size: usize,
        num_challenges: usize,
        has_public_inputs: bool,
        hash_id: EngineId,
    ) -> Self;

    fn new_from_mavros_r1cs(
        r1cs: &MavrosR1CS,
        w1_size: usize,
        num_challenges: usize,
        has_public_inputs: bool,
    ) -> Self;

    fn new_from_dimensions(
        num_witnesses: usize,
        num_constraints: usize,
        a_num_entries: usize,
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
        hash_id: EngineId,
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

        let mut m_raw = m1_raw.max(m2_raw).max(MIN_WHIR_NUM_VARIABLES);
        let m_0 = m0_raw.max(MIN_SUMCHECK_NUM_VARIABLES);

        // Ensure w1's zero-padding has room for the blinding polynomial coefficients.
        if (1usize << m_raw) - w1_size < 4 * m_0 {
            m_raw += 1;
        }

        Self {
            m: m_raw,
            w1_size,
            m_0,
            a_num_terms: next_power_of_two(r1cs.a().iter().count()),
            num_challenges,
            whir_witness: Self::new_whir_zk_config_for_size(m_raw, 1, hash_id),
            has_public_inputs,
        }
    }

    fn new_whir_zk_config_for_size(
        num_variables: usize,
        num_polynomials: usize,
        hash_id: EngineId,
    ) -> WhirZkConfig {
        let nv = num_variables.max(MIN_WHIR_NUM_VARIABLES);

        // Parameters tuned for 128-bit security under the Johnson bound (the old
        // ConjectureList soundness was disproven). Rate=2 balances query count vs
        // codeword size; ff=3 keeps blinding polynomials small; pow_bits=10 shifts
        // security budget toward algebraic hardness (118 bits) with light PoW per
        // round, which is faster than the default ~18-bit grinding.
        let whir_params = ProtocolParameters {
            unique_decoding: false,
            security_level: 128,
            pow_bits: 10,
            initial_folding_factor: 3,
            folding_factor: 3,
            starting_log_inv_rate: 2,
            batch_size: 1,
            hash_id,
        };
        WhirZkConfig::new(1 << nv, &whir_params, num_polynomials)
    }

    fn new_from_mavros_r1cs(
        r1cs: &MavrosR1CS,
        w1_size: usize,
        num_challenges: usize,
        has_public_inputs: bool,
    ) -> Self {
        let num_witnesses = r1cs.witness_layout.size();
        let num_constraints = r1cs.constraints.len();
        let a_num_entries: usize = r1cs.constraints.iter().map(|c| c.a.len()).sum();

        Self::new_from_dimensions(
            num_witnesses,
            num_constraints,
            a_num_entries,
            w1_size,
            num_challenges,
            has_public_inputs,
        )
    }

    fn new_from_dimensions(
        num_witnesses: usize,
        num_constraints: usize,
        a_num_entries: usize,
        w1_size: usize,
        num_challenges: usize,
        has_public_inputs: bool,
    ) -> Self {
        let m_raw = next_power_of_two(num_witnesses);
        let m0_raw = next_power_of_two(num_constraints);

        let mut m = m_raw.max(MIN_WHIR_NUM_VARIABLES);
        let m_0 = m0_raw.max(MIN_SUMCHECK_NUM_VARIABLES);

        // Ensure w1's zero-padding has room for the blinding polynomial coefficients.
        if (1usize << m) - w1_size < 4 * m_0 {
            m += 1;
        }

        Self {
            m,
            m_0,
            a_num_terms: next_power_of_two(a_num_entries),
            whir_witness: Self::new_whir_zk_config_for_size(m, 1),
            w1_size,
            num_challenges,
            has_public_inputs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_security_level() {
        let config = WhirR1CSScheme::new_whir_zk_config_for_size(20, 1, whir::hash::SHA2);
        let sec_blinded = config
            .blinded_commitment
            .security_level(config.blinded_commitment.initial_committer.num_vectors, 1);
        let sec_blinding = config
            .blinding_commitment
            .security_level(config.blinding_commitment.initial_committer.num_vectors, 1);
        assert!(
            sec_blinded >= 128.0,
            "Blinded commitment security {sec_blinded:.2} < 128 bits"
        );
        assert!(
            sec_blinding >= 128.0,
            "Blinding commitment security {sec_blinding:.2} < 128 bits"
        );
    }

    #[test]
    fn verify_security_level_min_variables() {
        let config = WhirR1CSScheme::new_whir_zk_config_for_size(
            MIN_WHIR_NUM_VARIABLES,
            1,
            whir::hash::SHA2,
        );
        let sec_blinded = config
            .blinded_commitment
            .security_level(config.blinded_commitment.initial_committer.num_vectors, 1);
        let sec_blinding = config
            .blinding_commitment
            .security_level(config.blinding_commitment.initial_committer.num_vectors, 1);
        assert!(
            sec_blinded >= 128.0,
            "Blinded commitment security {sec_blinded:.2} < 128 bits at nv={}",
            MIN_WHIR_NUM_VARIABLES
        );
        assert!(
            sec_blinding >= 128.0,
            "Blinding commitment security {sec_blinding:.2} < 128 bits at nv={}",
            MIN_WHIR_NUM_VARIABLES
        );
    }
}
