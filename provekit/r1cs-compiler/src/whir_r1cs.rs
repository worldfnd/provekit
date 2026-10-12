use {
    provekit_backend_bn254::{Bn254Field, FieldElement},
    provekit_backend_goldilocks::GoldilocksField,
    provekit_common::{
        FieldHash, HashConfig, WhirR1CSScheme, WitnessCommitmentMode, MIN_WHIR_NUM_VARIABLES, R1CS,
    },
};

#[test]
fn commitment_dimensions_follow_witness_layers() {
    for (witnesses, constraints, w1_size, challenges, m, m_0) in [
        (64, 8, 64, 0, MIN_WHIR_NUM_VARIABLES, 3),
        (64, 8, 0, 0, MIN_WHIR_NUM_VARIABLES, 3),
        (12_288, 2_048, 8_192, 0, 13, 11),
        (600_000, 8, 300_000, 2, 19, 3),
    ] {
        let mut r1cs = R1CS::<FieldElement>::new();
        r1cs.grow_matrices(constraints, witnesses);
        let scheme = WhirR1CSScheme::<Bn254Field>::new_for_r1cs(
            &r1cs,
            w1_size,
            challenges,
            (0..challenges).collect(),
            false,
            HashConfig::Sha256,
            WitnessCommitmentMode::default(),
        )
        .unwrap();
        assert_eq!((scheme.m, scheme.m_0, scheme.w1_size), (m, m_0, w1_size));
    }
}

fn assert_configs_secure<P: FieldHash>(size: usize) {
    let witness = WhirR1CSScheme::<P>::new_witness_config_for_size(
        size,
        whir::hash::SHA2,
        WitnessCommitmentMode::default(),
    )
    .unwrap();
    let blinding = WhirR1CSScheme::<P>::new_blinding_config_for_size(size, whir::hash::SHA2);
    witness
        .validate()
        .expect("valid witness security parameters");
    assert_eq!(witness.security().target_security_bits, 128);
    assert!(blinding.security_level(blinding.initial_committer.num_vectors(), 1) >= 128.0);
}

#[test]
fn commitment_configs_meet_security_target() {
    for size in [MIN_WHIR_NUM_VARIABLES, 20] {
        assert_configs_secure::<Bn254Field>(size);
        assert_configs_secure::<GoldilocksField>(size);
    }
}
