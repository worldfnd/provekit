use {
    ark_ff::{AdditiveGroup, Field},
    provekit_backend_bn254::{Bn254Field, FieldElement as F},
    provekit_common::{
        FieldHash, HashConfig, PublicInputs, PublicInputsHash, WhirR1CSProof, WhirR1CSScheme,
        WitnessCommitmentMode, R1CS,
    },
    provekit_prover::WhirR1CSProver,
    provekit_verifier::WhirR1CSVerifier,
    whir::transcript::{ProverState, VerifierMessage},
};

const CASES: [(bool, WitnessCommitmentMode); 4] = [
    (false, WitnessCommitmentMode::Standard),
    (true, WitnessCommitmentMode::Standard),
    (false, WitnessCommitmentMode::ZeroKnowledge),
    (true, WitnessCommitmentMode::ZeroKnowledge),
];

fn prove(
    pair: bool,
    mode: WitnessCommitmentMode,
    num_public_inputs: usize,
    constant: F,
    public: &PublicInputs<F>,
) -> (R1CS<F>, WhirR1CSScheme<Bn254Field>, WhirR1CSProof) {
    Bn254Field::register();
    let mut witness = vec![constant, F::from(3), F::from(7)];
    let mut r1cs = R1CS::new();
    r1cs.add_witnesses(witness.len() + usize::from(pair));
    r1cs.num_public_inputs = num_public_inputs;
    // Both zero and one satisfy these matrices. The public claim must bind
    // witness[0] to one.
    for _ in 0..2 {
        r1cs.add_constraint(&[(F::ONE, 0)], &[(F::ONE, 0)], &[(F::ONE, 0)]);
    }
    let scheme = WhirR1CSScheme::<Bn254Field>::new_for_r1cs(
        &r1cs,
        witness.len(),
        usize::from(pair),
        if pair { vec![0] } else { vec![] },
        num_public_inputs > 0,
        HashConfig::Sha256,
        mode,
    )
    .unwrap();
    let instance = public.hash_bytes::<Bn254Field>(HashConfig::Sha256);
    let ds = scheme.create_domain_separator().instance(&instance);
    let mut prover = ProverState::new(&ds, Bn254Field::transcript_sponge(HashConfig::Sha256));
    let mut commitments = vec![scheme
        .commit(
            &mut prover,
            r1cs.num_witnesses(),
            r1cs.num_constraints(),
            witness.clone(),
            true,
        )
        .unwrap()];
    if pair {
        let challenge: F = prover.verifier_message();
        witness.push(challenge);
        commitments.push(
            scheme
                .commit(
                    &mut prover,
                    r1cs.num_witnesses(),
                    r1cs.num_constraints(),
                    vec![challenge],
                    false,
                )
                .unwrap(),
        );
    }
    let proof = scheme
        .prove_noir(prover, r1cs.clone(), commitments, witness, public)
        .expect("proving must succeed so each rejection tests the verifier");
    (r1cs, scheme, proof)
}

#[test]
fn constant_one_is_bound_without_public_inputs() {
    let public = PublicInputs::new();
    for (pair, mode) in CASES {
        let (r1cs, scheme, proof) = prove(pair, mode, 0, F::ZERO, &public);
        assert!(
            scheme.verify(&proof, &public, &r1cs).is_err(),
            "invalid constant must fail: pair={pair}, mode={mode:?}"
        );
    }
}

#[test]
fn public_input_count_must_match_r1cs() {
    // Use matching inputs for proving and verification to avoid a transcript hash
    // mismatch.
    for inputs in [vec![], vec![F::from(3), F::from(7)]] {
        let public = PublicInputs::from_vec(inputs);
        for (pair, mode) in CASES {
            let (r1cs, scheme, proof) = prove(pair, mode, 1, F::ONE, &public);
            assert!(
                scheme.verify(&proof, &public, &r1cs).is_err(),
                "wrong public input count must fail: pair={pair}, mode={mode:?}, count={}",
                public.len()
            );
        }
    }
}

#[test]
fn valid_constant_and_public_inputs_verify() {
    for inputs in [vec![], vec![F::from(3)]] {
        let public = PublicInputs::from_vec(inputs);
        for (pair, mode) in CASES {
            let (r1cs, scheme, proof) = prove(pair, mode, public.len(), F::ONE, &public);
            scheme.verify(&proof, &public, &r1cs).unwrap();
        }
    }
}
