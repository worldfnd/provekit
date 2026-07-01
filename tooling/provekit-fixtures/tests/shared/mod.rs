//! Field-generic prove→verify and soundness test bodies, instantiated per proof
//! field by the `roundtrip_suite!` / `soundness_suite!` macros.
//!
//! Each test binary includes this whole module but exercises only the suite it
//! invokes, so the unused half is expected.
//!
//! # Scope
//! These drive the field-generic proving spine (commitment, transcript,
//! sumcheck, WHIR, bindings) over synthetic R1CS; the circuits are vehicles.
//! The LogUp builders cover the dual-commit path, not the real lookup machinery
//! (witness-builder solver, compiler emission) — memory, range, binops, EC, the
//! frontend, and the recursive verifier are out of scope.
#![allow(dead_code)]

use {
    ark_ff::One,
    ark_std::rand::distributions::{Distribution, Standard},
    provekit_common::{Base, Ext, FieldHash, HashConfig, PublicInputs},
    provekit_fixtures::{
        builders::{
            challenge_with_public_input, logup_lookup, logup_lookup_w2, multi_challenge_inverses,
            multi_challenge_inverses_w2, random_satisfiable, satisfies, squaring_chain,
            two_public_inputs, LogUpInstance,
        },
        harness::{
            prove, prove_and_verify, prove_and_verify_with_challenge,
            prove_and_verify_with_challenge_and_public, prove_with_tampered_challenge,
        },
    },
    provekit_verifier::WhirR1CSVerifier,
    whir::algebra::embedding::Embedding,
};

// --- roundtrip bodies ---

/// The satisfaction oracle accepts a satisfying witness and rejects a one-term
/// perturbation. Needs no proving, so it is field-generic over `F = Base<P>`.
pub fn oracle_accepts_satisfying_and_rejects_broken<P: FieldHash>() {
    let (r1cs, w) = squaring_chain::<Base<P>>(3, 6);
    assert!(satisfies(&r1cs, &w));

    let mut broken = w.clone();
    let last = broken.len() - 1;
    broken[last] += Base::<P>::one();
    assert!(!satisfies(&r1cs, &broken));
}

pub fn two_public_inputs_roundtrip<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    let (r1cs, w) = two_public_inputs::<Base<P>>(6, 7);
    let public_inputs = PublicInputs::from_vec(vec![w[1], w[2]]);
    assert!(satisfies(&r1cs, &w));
    prove_and_verify::<P>(&r1cs, w, &public_inputs).expect("roundtrip");
}

/// Full prove→verify across squaring-chain sizes straddling WHIR's
/// witness-domain floor: exactly `2^13` (the smallest size a WHIR commitment
/// pads up to — asserted unpadded) and past the `2^14` milestone.
pub fn squaring_chain_size_sweep_roundtrip<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    const WITNESS_FLOOR: usize = 8192; // 2^13

    // Each case is `(depth, exact)`: `Some(n)` requires exactly `n` (unpadded)
    // witnesses; `None` only checks the milestone lower bound.
    let cases: [(usize, Option<usize>); 2] =
        [(WITNESS_FLOOR - 2, Some(WITNESS_FLOOR)), (16_384, None)];
    for (depth, exact) in cases {
        let (r1cs, w) = squaring_chain::<Base<P>>(2, depth);
        match exact {
            Some(n) => assert_eq!(r1cs.num_witnesses(), n, "depth {depth}: floor"),
            None => assert!(
                r1cs.num_witnesses() >= 16_384 && r1cs.num_constraints() >= 16_384,
                "depth {depth}: past 2^14"
            ),
        }
        let public_inputs = PublicInputs::from_vec(vec![w[1]]);
        assert!(satisfies(&r1cs, &w));
        prove_and_verify::<P>(&r1cs, w, &public_inputs).expect("roundtrip");
    }
}

/// Per seed: the instance proves and verifies, and a perturbed output breaks
/// satisfaction.
pub fn random_satisfiable_proves_and_perturbation_rejects<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    for seed in 0..8u64 {
        let (r1cs, w) = random_satisfiable::<Base<P>>(seed, 4, 8);
        assert!(satisfies(&r1cs, &w), "seed {seed}: must satisfy its R1CS");

        let mut broken = w.clone();
        *broken.last_mut().unwrap() += Base::<P>::one();
        assert!(
            !satisfies(&r1cs, &broken),
            "seed {seed}: perturbation must break a constraint"
        );

        let public_inputs = PublicInputs::from_vec(vec![w[1]]);
        prove_and_verify::<P>(&r1cs, w, &public_inputs)
            .unwrap_or_else(|e| panic!("seed {seed}: honest proof must verify: {e}"));
    }
}

/// Prove→verify a LogUp instance under the given hash configuration.
fn logup_roundtrip<P>(
    table_len: usize,
    lookup_len: usize,
    seed: u64,
    hash: HashConfig,
) -> anyhow::Result<()>
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    let LogUpInstance {
        r1cs,
        w1,
        challenge_offsets,
        table_len,
        lookup_len,
    } = logup_lookup::<Base<P>>(table_len, lookup_len, seed);
    prove_and_verify_with_challenge::<P>(&r1cs, w1, challenge_offsets, hash, |ch, w1v| {
        logup_lookup_w2(ch, w1v, table_len, lookup_len)
    })
}

/// LogUp roundtrip across instance sizes: small instances over several seeds,
/// plus one large instance crossing the `2^13` witness-domain floor.
pub fn logup_lookup_size_sweep_roundtrip<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    for seed in 0..6u64 {
        logup_roundtrip::<P>(5, 11, seed, HashConfig::Sha256)
            .unwrap_or_else(|e| panic!("seed {seed}: honest lookup must verify: {e}"));
    }
    // 2 + 4·table + 2·lookup ≈ 16k witnesses crosses the 2^13 floor.
    logup_roundtrip::<P>(2_000, 4_000, 0xa11ce, HashConfig::Sha256)
        .expect("milestone lookup must verify");
}

/// Multi-challenge binding: several challenges, each pinned by `c · (1/c) = 1`.
pub fn multi_challenge_binding_roundtrip<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    let (r1cs, w1, offsets) = multi_challenge_inverses::<Base<P>>(4);
    prove_and_verify_with_challenge::<P>(
        &r1cs,
        w1,
        offsets,
        HashConfig::Sha256,
        multi_challenge_inverses_w2::<Base<P>>,
    )
    .expect("multi-challenge binding roundtrip must verify");
}

/// Dual-commit *and* a public input in one proof: the verifier must enforce
/// both the challenge binding (`c · 1/c = 1`) and the public-input binding
/// (`witness[1] == public_inputs[0]`).
pub fn dual_commit_with_public_roundtrip<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    let (r1cs, w1, offsets) = challenge_with_public_input::<Base<P>>(7);
    let public_inputs = PublicInputs::from_vec(vec![w1[1]]);
    prove_and_verify_with_challenge_and_public::<P>(
        &r1cs,
        w1,
        offsets,
        &public_inputs,
        HashConfig::Sha256,
        multi_challenge_inverses_w2::<Base<P>>,
    )
    .expect("dual-commit + public-input roundtrip must verify");
}

// --- soundness bodies ---
//
// `prove` never checks satisfaction (it produces a proof even for a
// non-satisfying witness), so the `prove(...).expect(...)` keeps each
// verify-rejection assertion live.

/// R1CS satisfaction: a broken witness must not verify.
pub fn corrupted_witness_is_rejected<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    let (r1cs, mut w) = squaring_chain::<Base<P>>(3, 8);
    let last = w.len() - 1;
    w[last] += Base::<P>::one();
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(!satisfies(&r1cs, &w));

    let (scheme, proof) = prove::<P>(&r1cs, w, &public_inputs)
        .expect("prover produces a proof even for a non-satisfying witness");
    assert!(scheme.verify(&proof, &public_inputs, &r1cs).is_err());
}

/// Instance/structure binding: a proof made for one R1CS must not verify
/// against a structurally different R1CS.
pub fn wrong_r1cs_is_rejected<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    let (r1cs_a, w) = squaring_chain::<Base<P>>(3, 8);
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(satisfies(&r1cs_a, &w));
    let (scheme, proof) = prove::<P>(&r1cs_a, w, &public_inputs).expect("proving failed");

    // A structurally different instance (more constraints/witnesses).
    let (r1cs_b, _) = squaring_chain::<Base<P>>(3, 12);
    assert!(scheme.verify(&proof, &public_inputs, &r1cs_b).is_err());
}

/// Public-input binding covector: prover and verifier agree on public inputs
/// that disagree with the witness (`public[i] != witness[1 + i]`). The
/// public-inputs hash matches on both sides, so the "hash mismatch" guard
/// passes and the binding covector (the PR #321 path) is what rejects. Unlike
/// [`tampered_public_input_is_rejected`], which trips the guard first, this
/// exercises the covector math itself — at both `N = 1` (trivial binding) and
/// `N = 2` (non-trivial binding loop), with the R1CS itself satisfied.
pub fn public_input_binding_mismatch_is_rejected<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    // N = 1: prove and verify with the same wrong public input.
    let (r1cs, w) = squaring_chain::<Base<P>>(3, 8);
    assert!(satisfies(&r1cs, &w));
    let wrong = PublicInputs::from_vec(vec![w[1] + Base::<P>::one()]);
    let (scheme, proof) = prove::<P>(&r1cs, w, &wrong)
        .expect("proving succeeds; the binding is checked at verify time");
    assert!(
        scheme.verify(&proof, &wrong, &r1cs).is_err(),
        "N=1 covector binding must reject"
    );

    // N = 2: corrupt only the second public input, identically on both sides.
    let (r1cs, w) = two_public_inputs::<Base<P>>(6, 7);
    assert!(satisfies(&r1cs, &w));
    let wrong = PublicInputs::from_vec(vec![w[1], w[2] + Base::<P>::one()]);
    let (scheme, proof) = prove::<P>(&r1cs, w, &wrong)
        .expect("proving succeeds; the binding is checked at verify time");
    assert!(
        scheme.verify(&proof, &wrong, &r1cs).is_err(),
        "N=2 covector binding must reject"
    );
}

/// Public-input instance binding: a proof made for the correct public inputs
/// must not verify when the verifier substitutes different inputs after
/// proving. The substitution changes the public-inputs hash, so the verifier
/// rejects at the hash guard (before the binding covector runs) — the
/// complement of [`public_input_binding_mismatch_is_rejected`], which passes
/// the guard. Checked at `N = 1` and `N = 2`.
pub fn tampered_public_input_is_rejected<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
{
    // N = 1.
    let (r1cs, w) = squaring_chain::<Base<P>>(3, 8);
    assert!(satisfies(&r1cs, &w));
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    let tampered = PublicInputs::from_vec(vec![w[1] + Base::<P>::one()]);
    let (scheme, proof) = prove::<P>(&r1cs, w, &public_inputs).expect("proving failed");
    assert!(
        scheme.verify(&proof, &tampered, &r1cs).is_err(),
        "N=1 tampered public input must reject"
    );

    // N = 2.
    let (r1cs, w) = two_public_inputs::<Base<P>>(6, 7);
    assert!(satisfies(&r1cs, &w));
    let public_inputs = PublicInputs::from_vec(vec![w[1], w[2]]);
    let tampered = PublicInputs::from_vec(vec![w[1], w[2] + Base::<P>::one()]);
    let (scheme, proof) = prove::<P>(&r1cs, w, &public_inputs).expect("proving failed");
    assert!(
        scheme.verify(&proof, &tampered, &r1cs).is_err(),
        "N=2 tampered public input must reject"
    );
}

/// Challenge binding: a `w2` whose committed challenge differs from the drawn
/// one must not verify.
pub fn tampered_challenge_is_rejected<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    let LogUpInstance {
        r1cs,
        w1,
        challenge_offsets,
        table_len,
        lookup_len,
    } = logup_lookup::<Base<P>>(5, 11, 5);
    let res = prove_with_tampered_challenge::<P>(
        &r1cs,
        w1,
        challenge_offsets,
        HashConfig::Sha256,
        |ch, w1v| logup_lookup_w2(ch, w1v, table_len, lookup_len),
    );
    assert!(
        res.is_err(),
        "a w2 disagreeing with the drawn challenge must be rejected"
    );
}

/// Prove→verify a LogUp instance whose `w1` is corrupted by `corrupt`.
fn logup_corrupted_verify<P>(
    seed: u64,
    corrupt: impl FnOnce(&mut [Base<P>], usize, usize),
) -> anyhow::Result<()>
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    let LogUpInstance {
        r1cs,
        mut w1,
        challenge_offsets,
        table_len,
        lookup_len,
    } = logup_lookup::<Base<P>>(5, 11, seed);
    corrupt(&mut w1, table_len, lookup_len);
    prove_and_verify_with_challenge::<P>(
        &r1cs,
        w1,
        challenge_offsets,
        HashConfig::Sha256,
        |ch, w1v| logup_lookup_w2(ch, w1v, table_len, lookup_len),
    )
}

/// LogUp soundness: a non-member lookup and a wrong multiplicity must each be
/// rejected.
pub fn logup_corruption_is_rejected<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    // First lookup sits at w1[1 + table_len]; set it outside `0..table_len`.
    assert!(
        logup_corrupted_verify::<P>(7, |w1, table_len, _lookup_len| {
            w1[1 + table_len] = Base::<P>::from(table_len as u64 + 999);
        })
        .is_err(),
        "a non-member lookup must be rejected"
    );
    // First multiplicity sits at w1[1 + table_len + lookup_len]; bump it.
    assert!(
        logup_corrupted_verify::<P>(9, |w1, table_len, lookup_len| {
            w1[1 + table_len + lookup_len] += Base::<P>::one();
        })
        .is_err(),
        "a wrong multiplicity must be rejected"
    );
}

/// Emit the prove→verify roundtrip suite for a concrete proof field.
/// `$register` registers that field's engines before each proving test.
#[macro_export]
macro_rules! roundtrip_suite {
    ($field:ty, $register:path) => {
        #[test]
        fn oracle_accepts_satisfying_and_rejects_broken() {
            $crate::shared::oracle_accepts_satisfying_and_rejects_broken::<$field>();
        }
        #[test]
        fn two_public_inputs_roundtrip() {
            $register();
            $crate::shared::two_public_inputs_roundtrip::<$field>();
        }
        #[test]
        fn squaring_chain_size_sweep_roundtrip() {
            $register();
            $crate::shared::squaring_chain_size_sweep_roundtrip::<$field>();
        }
        #[test]
        fn random_satisfiable_proves_and_perturbation_rejects() {
            $register();
            $crate::shared::random_satisfiable_proves_and_perturbation_rejects::<$field>();
        }
    };
}

/// Challenge-bearing roundtrip suite (LogUp + multi-challenge). The witness
/// holds challenge-derived (ext) values, so this requires an `Identity` field
/// where the base and extension fields coincide.
// TODO: support fields whose base and extension differ by drawing the LogUp
// challenges in the base field.
#[macro_export]
macro_rules! challenge_roundtrip_suite {
    ($field:ty, $register:path) => {
        #[test]
        fn logup_lookup_size_sweep_roundtrip() {
            $register();
            $crate::shared::logup_lookup_size_sweep_roundtrip::<$field>();
        }
        #[test]
        fn multi_challenge_binding_roundtrip() {
            $register();
            $crate::shared::multi_challenge_binding_roundtrip::<$field>();
        }
        #[test]
        fn dual_commit_with_public_roundtrip() {
            $register();
            $crate::shared::dual_commit_with_public_roundtrip::<$field>();
        }
    };
}

/// Emit the soundness suite for a concrete proof field.
#[macro_export]
macro_rules! soundness_suite {
    ($field:ty, $register:path) => {
        #[test]
        fn corrupted_witness_is_rejected() {
            $register();
            $crate::shared::corrupted_witness_is_rejected::<$field>();
        }
        #[test]
        fn wrong_r1cs_is_rejected() {
            $register();
            $crate::shared::wrong_r1cs_is_rejected::<$field>();
        }
        #[test]
        fn public_input_binding_mismatch_is_rejected() {
            $register();
            $crate::shared::public_input_binding_mismatch_is_rejected::<$field>();
        }
    };
}

/// Challenge-bearing soundness suite (see [`challenge_roundtrip_suite!`]):
/// requires an `Identity` field where the base and extension fields coincide.
#[macro_export]
macro_rules! challenge_soundness_suite {
    ($field:ty, $register:path) => {
        #[test]
        fn tampered_public_input_is_rejected() {
            $register();
            $crate::shared::tampered_public_input_is_rejected::<$field>();
        }
        #[test]
        fn tampered_challenge_is_rejected() {
            $register();
            $crate::shared::tampered_challenge_is_rejected::<$field>();
        }
        #[test]
        fn logup_corruption_is_rejected() {
            $register();
            $crate::shared::logup_corruption_is_rejected::<$field>();
        }
    };
}
