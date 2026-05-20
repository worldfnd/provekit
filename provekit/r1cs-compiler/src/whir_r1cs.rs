use {
    mavros_artifacts::R1CS as MavrosR1CS,
    provekit_common::{
        utils::next_power_of_two, HashConfig, R1csHash, WhirR1CSScheme, WhirZkConfig, R1CS,
    },
    whir::{
        engines::EngineId,
        parameters::ProtocolParameters,
        protocols::params::spec::{FoldingFactor, Mode, SecuritySpec, TuningSpec},
    },
};

const MIN_WHIR_NUM_VARIABLES: usize = 15;
const MIN_SUMCHECK_NUM_VARIABLES: usize = 1;

/// Translates the legacy `ProtocolParameters` shape (still used at provekit's
/// call sites) into zook's `(SecuritySpec, TuningSpec)` pair.
/// `initial_folding_factor` vs. `folding_factor` map to
/// `ConstantFromSecondRound`; equal values collapse to `Constant`.
fn protocol_parameters_to_zook(
    params: &ProtocolParameters,
    vector_size: usize,
) -> (SecuritySpec, TuningSpec) {
    let folding_factor = if params.initial_folding_factor == params.folding_factor {
        FoldingFactor::Constant(params.folding_factor)
    } else {
        FoldingFactor::ConstantFromSecondRound {
            initial: params.initial_folding_factor,
            rest:    params.folding_factor,
        }
    };
    let spec = SecuritySpec {
        mode:                 Mode::ZeroKnowledge,
        target_security_bits: params.security_level as u32,
        max_pow_bits:         Some(params.pow_bits as u32),
        hash_id:              params.hash_id,
    };
    let tuning = TuningSpec {
        vector_size,
        starting_log_inv_rate: params.starting_log_inv_rate as u32,
        folding_factor,
    };
    (spec, tuning)
}

pub trait WhirR1CSSchemeBuilder {
    fn new_for_r1cs(
        r1cs: &R1CS,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
    ) -> Self;

    fn new_from_mavros_r1cs(
        r1cs: &MavrosR1CS,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
    ) -> Self;

    fn new_from_dimensions(
        num_witnesses: usize,
        num_constraints: usize,
        a_num_entries: usize,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
    ) -> Self;

    fn new_whir_zk_config_for_size(
        num_variables: usize,
        num_polynomials: usize,
        hash_id: EngineId,
    ) -> WhirZkConfig;
}

impl WhirR1CSSchemeBuilder for WhirR1CSScheme {
    fn new_for_r1cs(
        r1cs: &R1CS,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
    ) -> Self {
        assert_eq!(
            num_challenges,
            challenge_offsets.len(),
            "num_challenges ({num_challenges}) != challenge_offsets.len() ({})",
            challenge_offsets.len()
        );
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
            challenge_offsets,
            whir_witness: Self::new_whir_zk_config_for_size(m_raw, 1, hash_config.engine_id()),
            has_public_inputs,
            r1cs_hash: r1cs.hash(),
            hash_config,
        }
    }

    fn new_whir_zk_config_for_size(
        num_variables: usize,
        num_polynomials: usize,
        hash_id: EngineId,
    ) -> WhirZkConfig {
        // Zook is single-poly; `num_polynomials` is kept on the trait for
        // callsite compatibility but ignored here.
        let _ = num_polynomials;
        let nv = num_variables.max(MIN_WHIR_NUM_VARIABLES);

        // Same security target as before (128 bits, 10 bits per-slot PoW budget) — the
        // old whir_zk wrapper is replaced by zook's per-round Construction 9.7
        // orchestrator. Tuning maps directly: same starting_log_inv_rate (2)
        // and folding_factor (3).
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
        let (spec, tuning) = protocol_parameters_to_zook(&whir_params, 1 << nv);
        WhirZkConfig::derive(spec, tuning)
    }

    fn new_from_mavros_r1cs(
        r1cs: &MavrosR1CS,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
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
            challenge_offsets,
            has_public_inputs,
            hash_config,
        )
    }

    fn new_from_dimensions(
        num_witnesses: usize,
        num_constraints: usize,
        a_num_entries: usize,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
    ) -> Self {
        debug_assert_eq!(
            num_challenges,
            challenge_offsets.len(),
            "num_challenges ({num_challenges}) != challenge_offsets.len() ({})",
            challenge_offsets.len()
        );
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
            whir_witness: Self::new_whir_zk_config_for_size(m, 1, hash_config.engine_id()),
            w1_size,
            num_challenges,
            challenge_offsets,
            has_public_inputs,
            r1cs_hash: R1csHash::UNSET,
            hash_config,
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, whir::protocols::params::bounds::SoundnessBounded};

    fn assert_zook_security_at_least(config: &WhirZkConfig, target: f64, label: &str) {
        let bits = f64::from(config.analytic_bits());
        assert!(
            bits >= target,
            "{label}: zook analytic bits {bits:.2} < target {target}"
        );
    }

    #[test]
    fn verify_security_level() {
        let config = WhirR1CSScheme::new_whir_zk_config_for_size(20, 1, whir::hash::SHA2);
        // We allow up to 10 bits of PoW credit (see `new_whir_zk_config_for_size`),
        // so analytic floor is target − pow = 118 bits.
        assert_zook_security_at_least(&config, 118.0, "nv=20");
    }

    #[test]
    fn verify_security_level_min_variables() {
        let config = WhirR1CSScheme::new_whir_zk_config_for_size(
            MIN_WHIR_NUM_VARIABLES,
            1,
            whir::hash::SHA2,
        );
        assert_zook_security_at_least(&config, 118.0, "nv=MIN");
    }
}
