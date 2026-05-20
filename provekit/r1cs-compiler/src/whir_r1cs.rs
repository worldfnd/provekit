use {
    provekit_common::{utils::next_power_of_two, WhirR1CSScheme, WhirZkConfig, R1CS},
    whir::{
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
        // provekit's current pipeline runs in standard mode; zook also supports ZK,
        // but for this migration we preserve provekit's existing mode.
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
    ) -> Self;

    fn new_whir_zk_config_for_size(num_variables: usize) -> WhirZkConfig;
}

impl WhirR1CSSchemeBuilder for WhirR1CSScheme {
    fn new_for_r1cs(
        r1cs: &R1CS,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
    ) -> Self {
        assert_eq!(
            num_challenges,
            challenge_offsets.len(),
            "num_challenges ({num_challenges}) must equal challenge_offsets.len() ({})",
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
            whir_witness: Self::new_whir_zk_config_for_size(m_raw),
            has_public_inputs,
            r1cs_hash: r1cs.hash(),
        }
    }

    fn new_whir_zk_config_for_size(num_variables: usize) -> WhirZkConfig {
        let nv = num_variables.max(MIN_WHIR_NUM_VARIABLES);

        // Same security target as before (128 bits, 10 bits per-slot PoW budget) — the
        // old whir_zk wrapper is replaced by zook's per-round Construction 9.7
        // orchestrator. Tuning maps directly: same starting_log_inv_rate (2)
        // and folding_factor (3).
        let whir_params = ProtocolParameters {
            unique_decoding:        false,
            security_level:         128,
            pow_bits:               10,
            initial_folding_factor: 3,
            folding_factor:         3,
            starting_log_inv_rate:  2,
            batch_size:             1,
            hash_id:                whir::hash::SHA2,
        };
        let (spec, tuning) = protocol_parameters_to_zook(&whir_params, 1 << nv);
        println!(">>> spec : {:?}", spec);
        println!(">>> tuning : {:?}", tuning);
        WhirZkConfig::derive(spec, tuning)
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
        let config = WhirR1CSScheme::new_whir_zk_config_for_size(20);
        // We allow up to 10 bits of PoW credit (see `new_whir_zk_config_for_size`),
        // so analytic floor is target − pow = 118 bits.
        assert_zook_security_at_least(&config, 118.0, "nv=20");
    }

    #[test]
    fn verify_security_level_min_variables() {
        let config = WhirR1CSScheme::new_whir_zk_config_for_size(MIN_WHIR_NUM_VARIABLES);
        assert_zook_security_at_least(&config, 118.0, "nv=MIN");
    }
}
