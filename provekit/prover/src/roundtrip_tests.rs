//! End-to-end toy-circuit roundtrip tests, runnable under either field
//! feature (`bn254` or `goldilocks`).
//!
//! The circuit is a single constraint `x * y = z` with `z` public. The
//! witness layout is load-bearing: `witness[0]` is the constant `1`,
//! public inputs occupy `1..=num_public_inputs`, so the full witness is
//! `[1, z, x, y]`. The hash configuration is pinned to SHA-256 because the
//! BN254 default (Skyscraper) does not exist in goldilocks builds.

use {
    crate::whir_r1cs::WhirR1CSProver,
    ark_ff::One,
    provekit_common::{
        register_ntt, FieldElement, HashConfig, PublicInputs, TranscriptSponge, WhirR1CSProof,
        WhirR1CSScheme, WhirR1CSSchemeBuilder, R1CS,
    },
    provekit_verifier::whir_r1cs::WhirR1CSVerifier,
    whir::transcript::ProverState,
};

const HASH: HashConfig = HashConfig::Sha256;

/// Build the toy R1CS for `x * y = z` over witness layout `[1, z, x, y]`.
fn toy_r1cs() -> R1CS {
    let mut r1cs = R1CS::new();
    r1cs.add_witnesses(4);
    r1cs.num_public_inputs = 1;
    let one = FieldElement::one();
    // A·w = x (index 2), B·w = y (index 3), C·w = z (index 1)
    r1cs.add_constraint(&[(one, 2)], &[(one, 3)], &[(one, 1)]);
    r1cs
}

/// Full witness `[1, z, x, y]` for given x, y (z computed).
fn toy_witness(x: u64, y: u64) -> Vec<FieldElement> {
    let xf = FieldElement::from(x);
    let yf = FieldElement::from(y);
    vec![FieldElement::one(), xf * yf, xf, yf]
}

/// Prove the toy circuit with the given full witness and public inputs.
fn prove(
    r1cs: &R1CS,
    full_witness: Vec<FieldElement>,
    public_inputs: &PublicInputs,
) -> anyhow::Result<(WhirR1CSScheme, WhirR1CSProof)> {
    register_ntt();
    let scheme = WhirR1CSScheme::new_for_r1cs(
        r1cs,
        full_witness.len(), // w1_size: everything in w1, no challenge phase
        0,
        vec![],
        true,
        HASH,
    );

    let instance = public_inputs.hash_bytes(HASH);
    let ds = scheme.create_domain_separator().instance(&instance);
    let mut merlin = ProverState::new(&ds, TranscriptSponge::from_config(HASH));

    let commitment = scheme.commit(
        &mut merlin,
        r1cs.num_witnesses(),
        r1cs.num_constraints(),
        full_witness.clone(),
        true,
    )?;
    let proof = scheme.prove_noir(
        merlin,
        r1cs.clone(),
        vec![commitment],
        full_witness,
        public_inputs,
    )?;
    Ok((scheme, proof))
}

#[test]
fn toy_roundtrip_proves_and_verifies() {
    let r1cs = toy_r1cs();
    let witness = toy_witness(3, 5);
    let public_inputs = PublicInputs::from_vec(vec![witness[1]]);

    let (scheme, proof) = prove(&r1cs, witness, &public_inputs).expect("proving failed");
    scheme
        .verify(&proof, &public_inputs, &r1cs)
        .expect("verification failed");
}

#[test]
fn corrupted_witness_is_rejected() {
    let r1cs = toy_r1cs();
    let mut witness = toy_witness(3, 5);
    // Break the constraint: z stays 15 but y becomes 6.
    witness[3] = FieldElement::from(6u64);
    let public_inputs = PublicInputs::from_vec(vec![witness[1]]);

    // Proving may fail outright; if it mechanically succeeds, the proof
    // must not verify.
    if let Ok((scheme, proof)) = prove(&r1cs, witness, &public_inputs) {
        assert!(
            scheme.verify(&proof, &public_inputs, &r1cs).is_err(),
            "proof over a non-satisfying witness must not verify"
        );
    }
}

#[test]
fn tampered_public_input_is_rejected() {
    let r1cs = toy_r1cs();
    let witness = toy_witness(3, 5);
    let public_inputs = PublicInputs::from_vec(vec![witness[1]]);

    let (scheme, proof) = prove(&r1cs, witness, &public_inputs).expect("proving failed");

    let tampered = PublicInputs::from_vec(vec![FieldElement::from(16u64)]);
    assert!(
        scheme.verify(&proof, &tampered, &r1cs).is_err(),
        "verification must fail when public inputs are tampered after proving"
    );
}

/// The goldilocks field must be the ~192-bit cubic extension and clear the
/// 128-bit security floor the WHIR parameters assume.
#[cfg(all(feature = "goldilocks", not(feature = "bn254")))]
#[test]
fn goldilocks_field_size_is_192_bits() {
    use whir::algebra::fields::FieldWithSize;
    let bits = <FieldElement as FieldWithSize>::field_size_bits();
    assert!(
        (190.0..=194.0).contains(&bits),
        "expected ~192-bit field, got {bits}"
    );
    assert!(bits >= 128.0, "below the 128-bit security floor");
}
