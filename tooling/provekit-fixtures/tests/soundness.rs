//! bn254 soundness checks: malformed witnesses and public inputs must be
//! rejected at verification.
//!
//! `prove` never checks satisfaction (it produces a proof even for a
//! non-satisfying witness), so the `prove(...).expect(...)` keeps each
//! verify-rejection assertion live.

use {
    ark_ff::One,
    provekit_backend_bn254::{register, Bn254Field, FieldElement},
    provekit_common::PublicInputs,
    provekit_fixtures::{
        builders::{satisfies, squaring_chain, two_public_inputs},
        harness::prove,
    },
    provekit_verifier::WhirR1CSVerifier,
};

/// R1CS satisfaction: a broken witness must not verify.
#[test]
fn corrupted_witness_is_rejected() {
    register();
    let (r1cs, mut w) = squaring_chain::<FieldElement>(3, 8);
    let last = w.len() - 1;
    w[last] += FieldElement::one();
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(!satisfies(&r1cs, &w));

    let (scheme, proof) = prove::<Bn254Field>(&r1cs, w, &public_inputs)
        .expect("prover produces a proof even for a non-satisfying witness");
    assert!(scheme.verify(&proof, &public_inputs, &r1cs).is_err());
}

/// Instance binding: a proof must not verify against public inputs substituted
/// after proving.
#[test]
fn tampered_public_input_is_rejected() {
    register();
    let (r1cs, w) = squaring_chain::<FieldElement>(3, 8);
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(satisfies(&r1cs, &w));
    let (scheme, proof) = prove::<Bn254Field>(&r1cs, w, &public_inputs).expect("proving failed");

    let tampered = PublicInputs::from_vec(vec![FieldElement::from(999u64)]);
    assert!(scheme.verify(&proof, &tampered, &r1cs).is_err());
}

/// Public-input binding: `witness[1] != public[0]` must not verify even though
/// the R1CS is satisfied. Unlike instance tampering, prove and verify agree on
/// the wrong input, so the binding is what rejects.
#[test]
fn mismatched_public_input_binding_is_rejected() {
    register();
    let (r1cs, w) = squaring_chain::<FieldElement>(3, 8);
    assert!(satisfies(&r1cs, &w));

    let wrong = PublicInputs::from_vec(vec![w[1] + FieldElement::one()]);
    let (scheme, proof) = prove::<Bn254Field>(&r1cs, w, &wrong)
        .expect("proving succeeds; the binding is checked at verify time");
    assert!(scheme.verify(&proof, &wrong, &r1cs).is_err());
}

/// Public-input binding at `N = 2`: corrupting only the second public input
/// must still reject (the binding loop is non-trivial here, unlike `N = 1`).
#[test]
fn two_public_inputs_binding_mismatch_is_rejected() {
    register();
    let (r1cs, w) = two_public_inputs::<FieldElement>(6, 7);
    assert!(satisfies(&r1cs, &w));

    let wrong = PublicInputs::from_vec(vec![w[1], w[2] + FieldElement::one()]);
    let (scheme, proof) = prove::<Bn254Field>(&r1cs, w, &wrong)
        .expect("proving succeeds; the binding is checked at verify time");
    assert!(scheme.verify(&proof, &wrong, &r1cs).is_err());
}
