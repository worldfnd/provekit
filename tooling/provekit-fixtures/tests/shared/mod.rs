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
            logup_lookup, logup_lookup_w2, multi_challenge_inverses, multi_challenge_inverses_w2,
            random_satisfiable, satisfies, squaring_chain, two_public_inputs, LogUpInstance,
        },
        harness::{
            prove, prove_and_verify, prove_and_verify_with_challenge, prove_with_tampered_challenge,
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

pub fn squaring_chain_small_roundtrip<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
{
    let (r1cs, w) = squaring_chain::<Base<P>>(3, 8); // depth 8: m = 13 floor
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(satisfies(&r1cs, &w));
    prove_and_verify::<P>(&r1cs, w, &public_inputs).expect("roundtrip");
}

pub fn two_public_inputs_roundtrip<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
{
    let (r1cs, w) = two_public_inputs::<Base<P>>(6, 7);
    let public_inputs = PublicInputs::from_vec(vec![w[1], w[2]]);
    assert!(satisfies(&r1cs, &w));
    prove_and_verify::<P>(&r1cs, w, &public_inputs).expect("roundtrip");
}

/// Full prove→verify at exactly the `2^13` witness-domain floor (the smallest
/// size a WHIR commitment pads up to).
pub fn witness_domain_floor_roundtrip<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
{
    const WITNESS_FLOOR: usize = 8192; // 2^13
    let (r1cs, w) = squaring_chain::<Base<P>>(2, WITNESS_FLOOR - 2);
    assert_eq!(r1cs.num_witnesses(), WITNESS_FLOOR);
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(satisfies(&r1cs, &w));
    prove_and_verify::<P>(&r1cs, w, &public_inputs).expect("roundtrip");
}

/// Larger-scale prove→verify past `2^14` witnesses.
pub fn milestone_2pow14_roundtrip<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
{
    let (r1cs, w) = squaring_chain::<Base<P>>(2, 16_384);
    assert!(r1cs.num_witnesses() >= 16_384 && r1cs.num_constraints() >= 16_384);
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(satisfies(&r1cs, &w));
    prove_and_verify::<P>(&r1cs, w, &public_inputs).expect("roundtrip");
}

/// Per seed: the instance proves and verifies, and a perturbed output breaks
/// satisfaction.
pub fn random_satisfiable_proves_and_perturbation_rejects<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
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
    Standard: Distribution<Ext<P>>,
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

/// LogUp lookup over small instances and several seeds.
pub fn logup_lookup_small_roundtrip<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    for seed in 0..6u64 {
        logup_roundtrip::<P>(5, 11, seed, HashConfig::Sha256)
            .unwrap_or_else(|e| panic!("seed {seed}: honest lookup must verify: {e}"));
    }
}

/// Larger LogUp roundtrip crossing the `2^13` witness-domain floor.
pub fn logup_lookup_milestone_roundtrip<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    // 2 + 4·table + 2·lookup ≈ 16k witnesses crosses the 2^13 floor.
    logup_roundtrip::<P>(2_000, 4_000, 0xa11ce, HashConfig::Sha256)
        .expect("milestone lookup must verify");
}

/// LogUp roundtrip under each field-agnostic hash engine (`Sha256`, `Keccak`,
/// `Blake3`). `Skyscraper`/`Poseidon2` are bn254-only.
pub fn logup_lookup_hash_sweep_roundtrip<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    for hash in [HashConfig::Sha256, HashConfig::Keccak, HashConfig::Blake3] {
        logup_roundtrip::<P>(5, 11, 0x5217, hash)
            .unwrap_or_else(|e| panic!("lookup must verify under {hash:?}: {e}"));
    }
}

/// Multi-challenge binding: several challenges, each pinned by `c · (1/c) = 1`.
pub fn multi_challenge_binding_roundtrip<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
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

// --- soundness bodies ---
//
// `prove` never checks satisfaction (it produces a proof even for a
// non-satisfying witness), so the `prove(...).expect(...)` keeps each
// verify-rejection assertion live.

/// R1CS satisfaction: a broken witness must not verify.
pub fn corrupted_witness_is_rejected<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
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

/// Instance binding: a proof must not verify against public inputs substituted
/// after proving.
pub fn tampered_public_input_is_rejected<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
{
    let (r1cs, w) = squaring_chain::<Base<P>>(3, 8);
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(satisfies(&r1cs, &w));
    let (scheme, proof) = prove::<P>(&r1cs, w, &public_inputs).expect("proving failed");

    let tampered = PublicInputs::from_vec(vec![Base::<P>::from(999u64)]);
    assert!(scheme.verify(&proof, &tampered, &r1cs).is_err());
}

/// Public-input binding: `witness[1] != public[0]` must not verify even though
/// the R1CS is satisfied.
pub fn mismatched_public_input_binding_is_rejected<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
{
    let (r1cs, w) = squaring_chain::<Base<P>>(3, 8);
    assert!(satisfies(&r1cs, &w));

    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    let wrong = PublicInputs::from_vec(vec![w[1] + Base::<P>::one()]);
    let (scheme, proof) = prove::<P>(&r1cs, w, &public_inputs)
        .expect("proving succeeds; the binding is checked at verify time");
    assert!(scheme.verify(&proof, &wrong, &r1cs).is_err());
}

/// Public-input binding at `N = 2`: corrupting only the second public input
/// must still reject (the binding loop is non-trivial here, unlike `N = 1`).
pub fn two_public_inputs_binding_mismatch_is_rejected<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
{
    let (r1cs, w) = two_public_inputs::<Base<P>>(6, 7);
    assert!(satisfies(&r1cs, &w));

    let public_inputs = PublicInputs::from_vec(vec![w[1], w[2]]);
    let wrong = PublicInputs::from_vec(vec![w[1], w[2] + Base::<P>::one()]);
    let (scheme, proof) = prove::<P>(&r1cs, w, &public_inputs)
        .expect("proving succeeds; the binding is checked at verify time");
    assert!(scheme.verify(&proof, &wrong, &r1cs).is_err());
}

/// Challenge binding: a `w2` whose committed challenge differs from the drawn
/// one must not verify.
pub fn tampered_challenge_is_rejected<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
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
    Standard: Distribution<Ext<P>>,
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

/// LogUp membership soundness: a looked-up value not in the table must be
/// rejected.
pub fn logup_non_member_is_rejected<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    let res = logup_corrupted_verify::<P>(7, |w1, table_len, _lookup_len| {
        // First lookup sits at w1[1 + table_len]; set it outside `0..table_len`.
        w1[1 + table_len] = Base::<P>::from(table_len as u64 + 999);
    });
    assert!(res.is_err(), "a non-member lookup must be rejected");
}

/// LogUp multiplicity soundness: a wrong multiplicity must be rejected.
pub fn logup_wrong_multiplicity_is_rejected<P>()
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    let res = logup_corrupted_verify::<P>(9, |w1, table_len, lookup_len| {
        // First multiplicity sits at w1[1 + table_len + lookup_len]; bump it.
        w1[1 + table_len + lookup_len] += Base::<P>::one();
    });
    assert!(res.is_err(), "a wrong multiplicity must be rejected");
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
        fn squaring_chain_small_roundtrip() {
            $register();
            $crate::shared::squaring_chain_small_roundtrip::<$field>();
        }
        #[test]
        fn two_public_inputs_roundtrip() {
            $register();
            $crate::shared::two_public_inputs_roundtrip::<$field>();
        }
        #[test]
        fn witness_domain_floor_roundtrip() {
            $register();
            $crate::shared::witness_domain_floor_roundtrip::<$field>();
        }
        #[test]
        fn milestone_2pow14_roundtrip() {
            $register();
            $crate::shared::milestone_2pow14_roundtrip::<$field>();
        }
        #[test]
        fn random_satisfiable_proves_and_perturbation_rejects() {
            $register();
            $crate::shared::random_satisfiable_proves_and_perturbation_rejects::<$field>();
        }
        #[test]
        fn logup_lookup_small_roundtrip() {
            $register();
            $crate::shared::logup_lookup_small_roundtrip::<$field>();
        }
        #[test]
        fn logup_lookup_milestone_roundtrip() {
            $register();
            $crate::shared::logup_lookup_milestone_roundtrip::<$field>();
        }
        #[test]
        fn logup_lookup_hash_sweep_roundtrip() {
            $register();
            $crate::shared::logup_lookup_hash_sweep_roundtrip::<$field>();
        }
        #[test]
        fn multi_challenge_binding_roundtrip() {
            $register();
            $crate::shared::multi_challenge_binding_roundtrip::<$field>();
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
        fn tampered_public_input_is_rejected() {
            $register();
            $crate::shared::tampered_public_input_is_rejected::<$field>();
        }
        #[test]
        fn mismatched_public_input_binding_is_rejected() {
            $register();
            $crate::shared::mismatched_public_input_binding_is_rejected::<$field>();
        }
        #[test]
        fn two_public_inputs_binding_mismatch_is_rejected() {
            $register();
            $crate::shared::two_public_inputs_binding_mismatch_is_rejected::<$field>();
        }
        #[test]
        fn tampered_challenge_is_rejected() {
            $register();
            $crate::shared::tampered_challenge_is_rejected::<$field>();
        }
        #[test]
        fn logup_non_member_is_rejected() {
            $register();
            $crate::shared::logup_non_member_is_rejected::<$field>();
        }
        #[test]
        fn logup_wrong_multiplicity_is_rejected() {
            $register();
            $crate::shared::logup_wrong_multiplicity_is_rejected::<$field>();
        }
    };
}
