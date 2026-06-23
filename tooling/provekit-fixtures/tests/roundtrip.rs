//! bn254 prove→verify roundtrips over synthetic R1CS fixtures.

use {
    ark_ff::One,
    provekit_backend_bn254::{register, Bn254Field, FieldElement},
    provekit_common::PublicInputs,
    provekit_fixtures::{
        builders::{random_satisfiable, satisfies, squaring_chain, two_public_inputs},
        harness::prove_and_verify,
    },
};

#[test]
fn oracle_accepts_satisfying_and_rejects_broken() {
    let (r1cs, w) = squaring_chain::<FieldElement>(3, 6);
    assert!(satisfies(&r1cs, &w));

    let mut broken = w.clone();
    let last = broken.len() - 1;
    broken[last] += FieldElement::one();
    assert!(!satisfies(&r1cs, &broken));
}

#[test]
fn squaring_chain_small_roundtrip() {
    register();
    let (r1cs, w) = squaring_chain::<FieldElement>(3, 8); // depth 8: m = 13 floor
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(satisfies(&r1cs, &w));
    prove_and_verify::<Bn254Field>(&r1cs, w, &public_inputs).expect("roundtrip");
}

#[test]
fn two_public_inputs_roundtrip() {
    register();
    let (r1cs, w) = two_public_inputs::<FieldElement>(6, 7);
    let public_inputs = PublicInputs::from_vec(vec![w[1], w[2]]);
    assert!(satisfies(&r1cs, &w));
    prove_and_verify::<Bn254Field>(&r1cs, w, &public_inputs).expect("roundtrip");
}

/// Full prove→verify at exactly the `2^13` witness-domain floor (the smallest
/// size a WHIR commitment pads up to). Functional only — it exercises the
/// proving path at the boundary and pins no field-specific scheme parameter
/// (those are covered by the r1cs-compiler builder tests).
#[test]
fn witness_domain_floor_roundtrip() {
    register();
    const WITNESS_FLOOR: usize = 8192; // 2^13
    let (r1cs, w) = squaring_chain::<FieldElement>(2, WITNESS_FLOOR - 2);
    assert_eq!(r1cs.num_witnesses(), WITNESS_FLOOR);

    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(satisfies(&r1cs, &w));
    prove_and_verify::<Bn254Field>(&r1cs, w, &public_inputs).expect("roundtrip");
}

/// Larger-scale prove→verify past `2^14` witnesses. Functional only — confirms
/// the proving path holds at scale, with no field-specific parameter checks.
#[test]
fn milestone_2pow14_roundtrip() {
    register();
    let (r1cs, w) = squaring_chain::<FieldElement>(2, 16_384);
    assert!(r1cs.num_witnesses() >= 16_384 && r1cs.num_constraints() >= 16_384);
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(satisfies(&r1cs, &w));
    prove_and_verify::<Bn254Field>(&r1cs, w, &public_inputs).expect("roundtrip");
}

/// Per seed: the instance proves and verifies, and a perturbed output breaks
/// satisfaction.
#[test]
fn random_satisfiable_proves_and_perturbation_rejects() {
    register();
    for seed in 0..8u64 {
        let (r1cs, w) = random_satisfiable::<FieldElement>(seed, 4, 8);
        assert!(satisfies(&r1cs, &w), "seed {seed}: must satisfy its R1CS");

        let mut broken = w.clone();
        *broken.last_mut().unwrap() += FieldElement::one();
        assert!(
            !satisfies(&r1cs, &broken),
            "seed {seed}: perturbation must break a constraint"
        );

        let public_inputs = PublicInputs::from_vec(vec![w[1]]);
        prove_and_verify::<Bn254Field>(&r1cs, w, &public_inputs)
            .unwrap_or_else(|e| panic!("seed {seed}: honest proof must verify: {e}"));
    }
}
