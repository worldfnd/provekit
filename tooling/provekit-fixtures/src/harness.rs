//! Field-generic prove→verify roundtrip over a synthetic R1CS.
//!
//! The runners mirror the prover/verifier instance binding exactly
//! (`hash_public_inputs` → `ext_to_bytes_le`, the scheme domain separator, and
//! the field-determined transcript sponge), so a proof produced here verifies
//! through the same checks as one from a frontend. Engine registration is the
//! caller's responsibility (it is field-specific), not the harness's.

use {
    anyhow::{ensure, Result},
    ark_ff::One,
    ark_std::rand::distributions::{Distribution, Standard},
    provekit_common::{
        Base, Ext, FieldHash, HashConfig, PublicInputs, PublicInputsHash, WhirR1CSProof,
        WhirR1CSScheme, R1CS,
    },
    provekit_prover::WhirR1CSProver,
    provekit_verifier::WhirR1CSVerifier,
    std::time::{Duration, Instant},
    whir::{
        algebra::embedding::Embedding,
        transcript::{ProverState, VerifierMessage},
    },
};

/// Instance-binding hash and Merkle/sponge configuration for the fixtures.
///
/// SHA-256 is deterministic and resolves to WHIR's built-in hash engine, so a
/// roundtrip needs no field-specific hash-engine setup.
const HASH: HashConfig = HashConfig::Sha256;

/// Single-commitment prove (no challenge phase): commits the full witness as
/// `w1` and produces a proof. Does not check satisfaction — a proof is produced
/// even for a non-satisfying witness, leaving rejection to the verifier.
pub fn prove<P>(
    r1cs: &R1CS<Base<P>>,
    full_witness: Vec<Base<P>>,
    public_inputs: &PublicInputs<Base<P>>,
) -> Result<(WhirR1CSScheme<P>, WhirR1CSProof)>
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    let scheme = WhirR1CSScheme::<P>::new_for_r1cs(
        r1cs,
        full_witness.len(), // w1_size: the whole witness, no challenge phase
        0,
        Vec::new(),
        !public_inputs.is_empty(),
        HASH,
    );

    let instance = public_inputs.hash_bytes::<P>(HASH);
    let ds = scheme.create_domain_separator().instance(&instance);
    let mut merlin = ProverState::new(&ds, P::transcript_sponge(HASH));

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

/// Prove then verify the resulting proof, returning an error if either step
/// fails.
pub fn prove_and_verify<P>(
    r1cs: &R1CS<Base<P>>,
    witness: Vec<Base<P>>,
    public_inputs: &PublicInputs<Base<P>>,
) -> Result<()>
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    let (scheme, proof) = prove::<P>(r1cs, witness, public_inputs)?;
    scheme.verify(&proof, public_inputs, r1cs)
}

/// Prove→verify a dual-commitment (`num_challenges > 0`) instance: commit `w1`,
/// draw the challenges, call `build_w2` to fill `w2`, commit `w2`, then verify.
///
/// The w1/w2 split is `w1.len()`. `build_w2(challenges, w1)` returns the full
/// `w2` and must place each challenge at its offset. Requires `Base == Ext`
/// (challenges are drawn in the extension field, stored in base witnesses); the
/// `Embedding<Target = Base<P>>` bound enforces it.
pub fn prove_and_verify_with_challenge<P>(
    r1cs: &R1CS<Base<P>>,
    w1: Vec<Base<P>>,
    challenge_offsets: Vec<usize>,
    hash: HashConfig,
    build_w2: impl FnOnce(&[Base<P>], &[Base<P>]) -> Result<Vec<Base<P>>>,
) -> Result<()>
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    let public = PublicInputs::from_vec(Vec::new());
    dual_commit_challenge::<P>(r1cs, w1, challenge_offsets, &public, hash, build_w2, false)
}

/// As [`prove_and_verify_with_challenge`], but with public inputs: the proof
/// must satisfy both the challenge binding and the public-input binding
/// (`witness[1 + i] == public_inputs[i]`). `w1` must carry the public values at
/// indices `1..=public_inputs.len()`.
pub fn prove_and_verify_with_challenge_and_public<P>(
    r1cs: &R1CS<Base<P>>,
    w1: Vec<Base<P>>,
    challenge_offsets: Vec<usize>,
    public_inputs: &PublicInputs<Base<P>>,
    hash: HashConfig,
    build_w2: impl FnOnce(&[Base<P>], &[Base<P>]) -> Result<Vec<Base<P>>>,
) -> Result<()>
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    dual_commit_challenge::<P>(
        r1cs,
        w1,
        challenge_offsets,
        public_inputs,
        hash,
        build_w2,
        false,
    )
}

/// As [`prove_and_verify_with_challenge`], but corrupts the committed challenge
/// at its first offset. Returns the verifier's `Err`.
pub fn prove_with_tampered_challenge<P>(
    r1cs: &R1CS<Base<P>>,
    w1: Vec<Base<P>>,
    challenge_offsets: Vec<usize>,
    hash: HashConfig,
    build_w2: impl FnOnce(&[Base<P>], &[Base<P>]) -> Result<Vec<Base<P>>>,
) -> Result<()>
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    let public = PublicInputs::from_vec(Vec::new());
    dual_commit_challenge::<P>(r1cs, w1, challenge_offsets, &public, hash, build_w2, true)
}

/// Shared driver for the dual-commit path. `tamper_first` bumps the committed
/// challenge at its first offset to force a rejection.
#[allow(clippy::too_many_arguments)]
fn dual_commit_challenge<P>(
    r1cs: &R1CS<Base<P>>,
    w1: Vec<Base<P>>,
    challenge_offsets: Vec<usize>,
    public: &PublicInputs<Base<P>>,
    hash: HashConfig,
    build_w2: impl FnOnce(&[Base<P>], &[Base<P>]) -> Result<Vec<Base<P>>>,
    tamper_first: bool,
) -> Result<()>
where
    P: FieldHash,
    Standard: Distribution<Ext<P>>,
    P::Embedding: Embedding<Target = Base<P>>,
{
    // The w1/w2 split is w1's length.
    let w1_size = w1.len();
    let num_challenges = challenge_offsets.len();
    let scheme = WhirR1CSScheme::<P>::new_for_r1cs(
        r1cs,
        w1_size,
        num_challenges,
        challenge_offsets.clone(),
        !public.is_empty(),
        hash,
    );

    let num_witnesses = r1cs.num_witnesses();
    let num_constraints = r1cs.num_constraints();
    let w2_size = num_witnesses - w1_size;

    let instance = public.hash_bytes::<P>(hash);
    let ds = scheme.create_domain_separator().instance(&instance);
    let mut merlin = ProverState::new(&ds, P::transcript_sponge(hash));

    // Commit w1, then draw the challenges bound to it.
    let c1 = scheme.commit(
        &mut merlin,
        num_witnesses,
        num_constraints,
        w1.clone(),
        true,
    )?;

    // Draw challenges as base-field elements (a no-op under `Base == Ext`).
    let challenges: Vec<Base<P>> = merlin.verifier_message_vec(num_challenges);
    let mut w2 = build_w2(&challenges, &w1)?;
    ensure!(
        w2.len() == w2_size,
        "build_w2 returned {} elements, expected w2_size {w2_size}",
        w2.len(),
    );
    // Each challenge must land at its declared offset, or binding is meaningless.
    for (&offset, challenge) in challenge_offsets.iter().zip(&challenges) {
        ensure!(
            w2.get(offset) == Some(challenge),
            "build_w2 must place the challenge at offset {offset}",
        );
    }
    if tamper_first {
        if let Some(&offset) = challenge_offsets.first() {
            w2[offset] += <Base<P>>::one();
        }
    }

    let mut full_witness = w1;
    full_witness.extend_from_slice(&w2);

    let c2 = scheme.commit(&mut merlin, num_witnesses, num_constraints, w2, false)?;
    let proof = scheme.prove_noir(merlin, r1cs.clone(), vec![c1, c2], full_witness, public)?;
    scheme.verify(&proof, public, r1cs)
}

/// Time a dual-commit (`num_challenges > 0`) prove from a precomputed witness,
/// returning the elapsed proving time.
///
/// The challenges are drawn directly from the transcript (the frontend draws
/// them inside its witness solver) so the path is field-agnostic. This is a
/// timing probe only: `w2` is the witness tail rather than a challenge-derived
/// commitment, so the resulting proof is not expected to verify.
pub fn time_dual_commit_prove<P>(
    r1cs: &R1CS<Base<P>>,
    full_witness: Vec<Base<P>>,
    w1_size: usize,
    num_challenges: usize,
) -> Result<Duration>
where
    P: FieldHash,
    Standard: Distribution<Ext<P>> + Distribution<Base<P>>,
{
    ensure!(
        w1_size <= r1cs.num_witnesses() && r1cs.num_witnesses() <= full_witness.len(),
        "witness too short for the split: w1_size={w1_size}, num_witnesses={}, \
         full_witness.len()={}",
        r1cs.num_witnesses(),
        full_witness.len(),
    );
    // Offsets are relative to the w2 commitment polynomial (index 0), matching
    // the frontend's `(0..num_challenges)` convention — not absolute indices
    // into the full witness.
    let challenge_offsets: Vec<usize> = (0..num_challenges).collect();
    let scheme = WhirR1CSScheme::<P>::new_for_r1cs(
        r1cs,
        w1_size,
        num_challenges,
        challenge_offsets,
        false,
        HASH,
    );

    let num_witnesses = r1cs.num_witnesses();
    let num_constraints = r1cs.num_constraints();
    let w1 = full_witness[..w1_size].to_vec();
    let w2 = full_witness[w1_size..num_witnesses].to_vec();
    let public: PublicInputs<Base<P>> = PublicInputs::from_vec(Vec::new());
    let instance = public.hash_bytes::<P>(HASH);
    let ds = scheme.create_domain_separator().instance(&instance);

    // Clone outside the timer — `prove_noir` consumes it, but the copy is not
    // proving work.
    let r1cs_owned = r1cs.clone();

    let start = Instant::now();
    let mut merlin = ProverState::new(&ds, P::transcript_sponge(HASH));
    let c1 = scheme.commit(&mut merlin, num_witnesses, num_constraints, w1, true)?;
    let _challenges: Vec<Ext<P>> = merlin.verifier_message_vec(num_challenges);
    let c2 = scheme.commit(&mut merlin, num_witnesses, num_constraints, w2, false)?;
    scheme.prove_noir(merlin, r1cs_owned, vec![c1, c2], full_witness, &public)?;
    Ok(start.elapsed())
}
