use {
    mavros_artifacts::R1CS as MavrosR1CS,
    provekit_backend_bn254::Bn254Field,
    provekit_common::{HashConfig, WhirR1CSScheme},
};

/// bn254-only scheme construction from a Mavros R1CS instance.
///
/// Mavros artifacts are bn254-specific, so this constructor lives here rather
/// than on the field-generic [`WhirR1CSScheme`]; it forwards the instance's
/// dimensions to [`WhirR1CSScheme::new_from_dimensions`].
pub trait MavrosSchemeBuilder {
    /// Build a scheme from a Mavros R1CS instance's dimensions.
    ///
    /// Like [`WhirR1CSScheme::new_from_dimensions`], this leaves `r1cs_hash`
    /// UNSET: the caller must populate it (from the converted provekit R1CS)
    /// before creating a domain separator.
    fn new_from_mavros_r1cs(
        r1cs: &MavrosR1CS,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
    ) -> Self;
}

impl MavrosSchemeBuilder for WhirR1CSScheme<Bn254Field> {
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
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        provekit_backend_bn254::FieldElement,
        provekit_common::{MIN_WHIR_NUM_VARIABLES, R1CS},
    };

    fn r1cs_with_dimensions(num_witnesses: usize, num_constraints: usize) -> R1CS<FieldElement> {
        let mut r1cs = R1CS::new();
        r1cs.grow_matrices(num_constraints, num_witnesses);
        r1cs
    }

    fn assert_dimension_builders(
        num_witnesses: usize,
        num_constraints: usize,
        w1_size: usize,
        expected_m: usize,
        expected_m_0: usize,
    ) {
        let from_dimensions = WhirR1CSScheme::<Bn254Field>::new_from_dimensions(
            num_witnesses,
            num_constraints,
            0,
            w1_size,
            0,
            vec![],
            false,
            HashConfig::Sha256,
        );
        assert_eq!(from_dimensions.m, expected_m);
        assert_eq!(from_dimensions.m_0, expected_m_0);
        assert_eq!(from_dimensions.w1_size, w1_size);

        let r1cs = r1cs_with_dimensions(num_witnesses, num_constraints);
        let from_r1cs = WhirR1CSScheme::<Bn254Field>::new_for_r1cs(
            &r1cs,
            w1_size,
            0,
            vec![],
            false,
            HashConfig::Sha256,
        );
        assert_eq!(from_r1cs.m, expected_m);
        assert_eq!(from_r1cs.m_0, expected_m_0);
        assert_eq!(from_r1cs.w1_size, w1_size);
        // Both construction paths agree on every transcript-bound scheme field.
        assert_eq!(from_r1cs.a_num_terms, from_dimensions.a_num_terms);
        assert_eq!(from_r1cs.num_challenges, from_dimensions.num_challenges);
    }

    fn assert_configs_secure(size: usize) {
        let witness =
            WhirR1CSScheme::<Bn254Field>::new_witness_config_for_size(size, whir::hash::SHA2);
        let blinding =
            WhirR1CSScheme::<Bn254Field>::new_blinding_config_for_size(size, whir::hash::SHA2);
        let sec_witness = witness.security_level(witness.initial_committer.num_vectors, 1);
        let sec_blinding = blinding.security_level(blinding.initial_committer.num_vectors, 1);
        assert!(
            sec_witness >= 128.0,
            "Witness commitment security {sec_witness:.2} < 128 bits at size {size}"
        );
        assert!(
            sec_blinding >= 128.0,
            "Blinding commitment security {sec_blinding:.2} < 128 bits at size {size}"
        );
    }

    #[test]
    fn verify_security_level() {
        assert_configs_secure(20);
    }

    #[test]
    fn verify_security_level_min_variables() {
        assert_configs_secure(MIN_WHIR_NUM_VARIABLES);
    }

    #[test]
    fn mavros_dimensions_use_largest_commitment_not_total_witnesses() {
        let scheme = WhirR1CSScheme::<Bn254Field>::new_from_dimensions(
            600_000,
            8,
            8,
            300_000,
            2,
            vec![0, 1],
            false,
            HashConfig::Sha256,
        );

        assert_eq!(scheme.m, 19);
    }

    #[test]
    fn dimension_builders_handle_empty_w2() {
        assert_dimension_builders(64, 8, 64, MIN_WHIR_NUM_VARIABLES, 3);
    }

    #[test]
    fn dimension_builders_handle_empty_w1() {
        assert_dimension_builders(64, 8, 0, MIN_WHIR_NUM_VARIABLES, 3);
    }

    #[test]
    fn dimension_builders_exact_power_of_two_w1() {
        assert_dimension_builders(12_288, 2_048, 8_192, 13, 11);
    }
}
