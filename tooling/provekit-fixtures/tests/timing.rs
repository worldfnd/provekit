//! `#[ignore]` timing probes: prove + verify a 2^14 `squaring_chain` for each
//! proof field, printing wall-clock durations. Run with:
//!
//! ```text
//! cargo test -p provekit-fixtures --release -- --ignored --nocapture
//! ```

use {
    ark_std::rand::distributions::{Distribution, Standard},
    provekit_common::{Base, Ext, FieldHash, PublicInputs},
    provekit_fixtures::{
        builders::{satisfies, squaring_chain},
        harness::prove,
    },
    provekit_verifier::WhirR1CSVerifier,
    std::time::Instant,
};

/// Prove then verify a 2^14-witness `squaring_chain`, printing both durations.
fn time_squaring_chain_2pow14<P>(label: &str)
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    let (r1cs, w) = squaring_chain::<Base<P>>(2, 16_384);
    assert!(r1cs.num_witnesses() >= 16_384 && r1cs.num_constraints() >= 16_384);
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(satisfies(&r1cs, &w));

    let t_prove = Instant::now();
    let (scheme, proof) = prove::<P>(&r1cs, w, &public_inputs).expect("prove");
    let prove_elapsed = t_prove.elapsed();

    let t_verify = Instant::now();
    scheme
        .verify(&proof, &public_inputs, &r1cs)
        .expect("verify");
    let verify_elapsed = t_verify.elapsed();

    println!(
        "[timing/{label}] 2^14 squaring_chain: num_witnesses={}, num_constraints={}, \
         narg_string={}B, hints={}B | prove={prove_elapsed:?} verify={verify_elapsed:?}",
        r1cs.num_witnesses(),
        r1cs.num_constraints(),
        proof.narg_string.len(),
        proof.hints.len(),
    );
}

#[test]
#[ignore = "timing probe; run --release -- --ignored --nocapture"]
fn timing_goldilocks_bf_2pow14() {
    provekit_backend_goldilocks::register();
    time_squaring_chain_2pow14::<provekit_backend_goldilocks::GoldilocksField>("goldilocks-BF");
}

#[test]
#[ignore = "timing probe; run --release -- --ignored --nocapture"]
fn timing_bn254_2pow14() {
    provekit_backend_bn254::register();
    time_squaring_chain_2pow14::<provekit_backend_bn254::Bn254Field>("bn254");
}
