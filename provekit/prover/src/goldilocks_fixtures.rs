//! Hand-built R1CS fixtures, runnable under `bn254` or `goldilocks`.
//!
//! Goldilocks gates out the compiler, so `R1CS::new` + `add_constraint` is the
//! only way to build one. Fixtures are plain-arithmetic (`num_challenges = 0`),
//! hash pinned to SHA-256 (no Skyscraper under goldilocks). Only
//! `goldilocks_field_size_is_192_bits` is field-gated.

use {
    crate::whir_r1cs::WhirR1CSProver,
    ark_ff::{One, UniformRand},
    ark_std::rand::{rngs::StdRng, Rng, SeedableRng},
    provekit_common::{
        register_ntt, FieldElement, HashConfig, PublicInputs, TranscriptSponge, WhirR1CSProof,
        WhirR1CSScheme, WhirR1CSSchemeBuilder, R1CS,
    },
    provekit_verifier::whir_r1cs::WhirR1CSVerifier,
    std::time::{Duration, Instant},
    whir::transcript::{ProverState, VerifierMessage},
};

const HASH: HashConfig = HashConfig::Sha256;

/// WHIR witness-domain floor (`MIN_WHIR_NUM_VARIABLES`): prover work is flat at
/// or below `2^13` on both axes.
const FOLD_FLOOR: usize = 8192;

/// `(A·w) * (B·w) = C·w` for every row (the bn254-gated oracle is unavailable).
fn satisfies(r1cs: &R1CS, w: &[FieldElement]) -> bool {
    (0..r1cs.num_constraints()).all(|row| {
        let a: FieldElement = r1cs.a().iter_row(row).map(|(col, v)| v * w[col]).sum();
        let b: FieldElement = r1cs.b().iter_row(row).map(|(col, v)| v * w[col]).sum();
        let c: FieldElement = r1cs.c().iter_row(row).map(|(col, v)| v * w[col]).sum();
        a * b == c
    })
}

/// `w[i]^2 = w[i+1]` chain: `depth` constraints, `depth + 2` witnesses, `x`
/// public. The size knob — `depth + 2 > 2^13` crosses the fold floor.
fn squaring_chain(x: u64, depth: usize) -> (R1CS, Vec<FieldElement>) {
    let mut r1cs = R1CS::new();
    r1cs.add_witnesses(depth + 2);
    r1cs.num_public_inputs = 1;
    let one = FieldElement::one();
    let mut w = vec![one, FieldElement::from(x)];
    for i in 1..=depth {
        r1cs.add_constraint(&[(one, i)], &[(one, i)], &[(one, i + 1)]);
        let sq = w[i] * w[i];
        w.push(sq);
    }
    (r1cs, w)
}

/// `p0 * p1 = z` with two public inputs — exercises the binding loop at `N ≥ 2`
/// (PR #321 class), unreachable with one input.
fn two_public_inputs(p0: u64, p1: u64) -> (R1CS, Vec<FieldElement>) {
    let mut r1cs = R1CS::new();
    r1cs.add_witnesses(4);
    r1cs.num_public_inputs = 2;
    let one = FieldElement::one();
    r1cs.add_constraint(&[(one, 1)], &[(one, 2)], &[(one, 3)]);
    let (a, b) = (FieldElement::from(p0), FieldElement::from(p1));
    let w = vec![one, a, b, a * b];
    (r1cs, w)
}

/// `count` random `(coeff, col)` terms over `[0, cols)` (`count` may be 0).
fn random_terms(rng: &mut StdRng, cols: usize, count: usize) -> Vec<(FieldElement, usize)> {
    (0..count)
        .map(|_| {
            let coeff = FieldElement::from(rng.gen_range(1u64..=7));
            let col = rng.gen_range(0..cols);
            (coeff, col)
        })
        .collect()
}

/// A random 1–3 term linear combination.
fn random_lc(rng: &mut StdRng, cols: usize) -> Vec<(FieldElement, usize)> {
    let count = rng.gen_range(1..=3usize.min(cols));
    random_terms(rng, cols, count)
}

/// `Σ coeff·w[col]` (duplicate columns sum, matching `add_constraint`).
fn eval_lc(terms: &[(FieldElement, usize)], w: &[FieldElement]) -> FieldElement {
    terms.iter().map(|&(coeff, col)| coeff * w[col]).sum()
}

/// `num_gates` multiply gates over `num_inputs` random inputs, satisfiable by
/// construction; each gate's output holds `(A·w)·(B·w)`. First input is public.
fn random_satisfiable(seed: u64, num_inputs: usize, num_gates: usize) -> (R1CS, Vec<FieldElement>) {
    assert!(
        num_inputs >= 1,
        "need at least one input to expose as public"
    );
    let mut rng = StdRng::seed_from_u64(seed);
    let mut r1cs = R1CS::new();
    let total = 1 + num_inputs + num_gates;
    r1cs.add_witnesses(total);
    r1cs.num_public_inputs = 1;
    let one = FieldElement::one();

    let mut w = Vec::with_capacity(total);
    w.push(one);
    for _ in 0..num_inputs {
        w.push(FieldElement::rand(&mut rng));
    }
    for g in 0..num_gates {
        let out = 1 + num_inputs + g; // == current w.len()
        let a_row = random_lc(&mut rng, out);
        let b_row = random_lc(&mut rng, out);
        let product = eval_lc(&a_row, &w) * eval_lc(&b_row, &w);
        w.push(product);
        r1cs.add_constraint(&a_row, &b_row, &[(one, out)]);
    }
    (r1cs, w)
}

/// Satisfiable synthetic R1CS of a target size + density, to proxy a real
/// circuit's (structural) prover cost. Density ≈ `complete_age_check`:
/// ~2.5/1/1.5 non-zeros per A/B/C row. `num_public_inputs = 0`.
fn sized_r1cs(
    num_witnesses: usize,
    num_constraints: usize,
    seed: u64,
) -> (R1CS, Vec<FieldElement>) {
    assert!(
        num_witnesses > num_constraints + 1,
        "need room for input witnesses"
    );
    let num_inputs = num_witnesses - num_constraints - 1;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut r1cs = R1CS::new();
    r1cs.add_witnesses(num_witnesses);
    r1cs.num_public_inputs = 0;
    r1cs.reserve_constraints(num_constraints, num_constraints * 5);
    let one = FieldElement::one();

    let mut w = Vec::with_capacity(num_witnesses);
    w.push(one);
    for _ in 0..num_inputs {
        // `from(u64)`, not `rand`: field-independent RNG → identical structure
        // across fields.
        w.push(FieldElement::from(rng.gen::<u64>()));
    }
    for g in 0..num_constraints {
        let out = 1 + num_inputs + g; // == current w.len()
        let na = rng.gen_range(1..=4usize); // A ~2.5/row
        let a_row = random_terms(&mut rng, out, na);
        let b_row = random_terms(&mut rng, out, 1); // B 1/row
        let nc = rng.gen_range(0..=1usize); // C ~1.5/row
        let extra = random_terms(&mut rng, out, nc);
        // pick `out` so C·w = out + Σ(extra·w) == (A·w)·(B·w)
        let out_val = eval_lc(&a_row, &w) * eval_lc(&b_row, &w) - eval_lc(&extra, &w);
        w.push(out_val);
        let mut c_row = vec![(one, out)];
        c_row.extend(extra);
        r1cs.add_constraint(&a_row, &b_row, &c_row);
    }
    (r1cs, w)
}

/// Single-commitment prove (no challenge phase).
fn prove(
    r1cs: &R1CS,
    full_witness: Vec<FieldElement>,
    public_inputs: &PublicInputs,
) -> anyhow::Result<(WhirR1CSScheme, WhirR1CSProof)> {
    register_ntt();
    let scheme = WhirR1CSScheme::new_for_r1cs(
        r1cs,
        full_witness.len(), // w1_size: everything in w1, num_challenges = 0
        0,
        vec![],
        true,
        HASH,
    )?;

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

/// Prove then verify, asserting both succeed.
fn prove_and_verify(r1cs: &R1CS, witness: Vec<FieldElement>, public_inputs: &PublicInputs) {
    let (scheme, proof) = prove(r1cs, witness, public_inputs).expect("proving failed");
    scheme
        .verify(&proof, public_inputs, r1cs)
        .expect("verification failed");
}

#[test]
fn oracle_accepts_satisfying_and_rejects_broken() {
    let (r1cs, w) = squaring_chain(3, 6);
    assert!(satisfies(&r1cs, &w));

    let mut broken = w.clone();
    let last = broken.len() - 1;
    broken[last] += FieldElement::one();
    assert!(!satisfies(&r1cs, &broken));
}

#[test]
fn squaring_chain_small_roundtrip() {
    let (r1cs, w) = squaring_chain(3, 8); // depth 8: m = 13 floor
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(satisfies(&r1cs, &w));
    prove_and_verify(&r1cs, w, &public_inputs);
}

#[test]
fn two_public_inputs_roundtrip() {
    let (r1cs, w) = two_public_inputs(6, 7);
    let public_inputs = PublicInputs::from_vec(vec![w[1], w[2]]);
    assert!(satisfies(&r1cs, &w));
    prove_and_verify(&r1cs, w, &public_inputs);
}

/// Blinding-room bump: 8192 = `2^13` witnesses bump `m: 13 -> 14` via the
/// `(2^m - w1_size) < 4·m_0` padding check, not floor-crossing.
#[test]
fn blinding_bump_roundtrip() {
    let depth = FOLD_FLOOR - 2;
    let (r1cs, w) = squaring_chain(2, depth);
    assert_eq!(r1cs.num_witnesses(), FOLD_FLOOR);

    let scheme = WhirR1CSScheme::new_for_r1cs(&r1cs, w.len(), 0, vec![], true, HASH)
        .expect("scheme construction");
    assert_eq!(scheme.m, 14);

    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(satisfies(&r1cs, &w));
    prove_and_verify(&r1cs, w, &public_inputs);
}

/// `≥ 2^14` scale check (m = 15, m_0 = 14): past the fold floor. ~0.13s
/// release, runs in CI.
#[test]
fn milestone_2pow14_roundtrip() {
    let depth = 16_384;
    let (r1cs, w) = squaring_chain(2, depth);
    assert!(r1cs.num_witnesses() >= 16_384 && r1cs.num_constraints() >= 16_384);
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(satisfies(&r1cs, &w));
    prove_and_verify(&r1cs, w, &public_inputs);
}

// Three distinct rejection paths. `prove` never checks satisfaction (always
// returns a proof), so `.expect()` keeps the verify-rejection assert live.

/// Path 1 — R1CS satisfaction: a broken witness must not verify.
#[test]
fn corrupted_witness_is_rejected() {
    let (r1cs, mut w) = squaring_chain(3, 8);
    let last = w.len() - 1;
    w[last] += FieldElement::one();
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(!satisfies(&r1cs, &w));

    let (scheme, proof) = prove(&r1cs, w, &public_inputs)
        .expect("prover produces a proof even for a non-satisfying witness");
    assert!(scheme.verify(&proof, &public_inputs, &r1cs).is_err());
}

/// Path 2 — instance binding: a proof must not verify against public inputs
/// substituted after proving.
#[test]
fn tampered_public_input_is_rejected() {
    let (r1cs, w) = squaring_chain(3, 8);
    let public_inputs = PublicInputs::from_vec(vec![w[1]]);
    assert!(satisfies(&r1cs, &w));
    let (scheme, proof) = prove(&r1cs, w, &public_inputs).expect("proving failed");

    let tampered = PublicInputs::from_vec(vec![FieldElement::from(999u64)]);
    assert!(scheme.verify(&proof, &tampered, &r1cs).is_err());
}

/// Path 3 — public-input binding (PR #321): `witness[1] != public[0]` must not
/// verify though the R1CS is satisfied. Unlike path 2, prove and verify agree
/// on the wrong input, so the binding is what rejects.
#[test]
fn mismatched_public_input_binding_is_rejected() {
    let (r1cs, w) = squaring_chain(3, 8);
    assert!(satisfies(&r1cs, &w));

    let wrong = PublicInputs::from_vec(vec![w[1] + FieldElement::one()]);
    let (scheme, proof) =
        prove(&r1cs, w, &wrong).expect("proving succeeds; the binding is checked at verify time");
    assert!(scheme.verify(&proof, &wrong, &r1cs).is_err());
}

/// PR #321 at `N = 2`: corrupting only the second public input must still
/// reject (the binding loop is non-trivial here, unlike `N = 1`).
#[test]
fn two_public_inputs_binding_mismatch_is_rejected() {
    let (r1cs, w) = two_public_inputs(6, 7);
    assert!(satisfies(&r1cs, &w));

    let wrong = PublicInputs::from_vec(vec![w[1], w[2] + FieldElement::one()]);
    let (scheme, proof) =
        prove(&r1cs, w, &wrong).expect("proving succeeds; the binding is checked at verify time");
    assert!(scheme.verify(&proof, &wrong, &r1cs).is_err());
}

/// Per seed: the instance proves+verifies, and a perturbed output breaks
/// satisfaction.
#[test]
fn random_satisfiable_proves_and_perturbation_rejects() {
    for seed in 0..8u64 {
        let (r1cs, w) = random_satisfiable(seed, 4, 8);
        assert!(satisfies(&r1cs, &w), "seed {seed}: must satisfy its R1CS");

        let mut broken = w.clone();
        *broken.last_mut().unwrap() += FieldElement::one();
        assert!(
            !satisfies(&r1cs, &broken),
            "seed {seed}: perturbation must break a constraint"
        );

        let public_inputs = PublicInputs::from_vec(vec![w[1]]);
        let (scheme, proof) = prove(&r1cs, w, &public_inputs).expect("proving failed");
        assert!(
            scheme.verify(&proof, &public_inputs, &r1cs).is_ok(),
            "seed {seed}: honest proof must verify"
        );
    }
}

/// Goldilocks must be the ~192-bit cubic extension (clears the 128-bit floor).
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

// Proving-time benchmark: a synthetic R1CS sized to `complete_age_check`. Cost
// is structural, so same-size proxies real proving time. `#[ignore]`d; run
// under each field and compare the printed durations.

/// `complete_age_check`: 711,664 constraints · 1,247,227 witnesses · w1 ≈ 50%
/// (m = 20) · 118 challenges · ~3.55M non-zeros · 0 public inputs.
const AGE_CHECK_WITNESSES: usize = 1_247_227;
const AGE_CHECK_CONSTRAINTS: usize = 711_664;
const AGE_CHECK_W1: usize = 620_627;
const AGE_CHECK_CHALLENGES: usize = 118;

/// Same shape at m ≈ 16 — fast smoke for the dual-commit path.
const SCALED_WITNESSES: usize = 90_000;
const SCALED_CONSTRAINTS: usize = 51_000;
const SCALED_W1: usize = 45_000;

/// Time a dual-commit (`num_challenges > 0`) prove from a precomputed witness.
/// We draw the challenges directly (the real flow does it inside the gated
/// solver) so the path is field-agnostic. Timing-only: w2 is the witness tail,
/// not challenge-derived, so it won't verify; it also omits the subdominant w2
/// solve (LogUp inversion), so absolutes slightly under-count (ratio
/// unaffected).
fn time_dual_commit_prove(
    r1cs: &R1CS,
    full_witness: Vec<FieldElement>,
    w1_size: usize,
    num_challenges: usize,
) -> Duration {
    register_ntt();
    let challenge_offsets: Vec<usize> = (w1_size..w1_size + num_challenges).collect();
    let scheme = WhirR1CSScheme::new_for_r1cs(
        r1cs,
        w1_size,
        num_challenges,
        challenge_offsets,
        false,
        HASH,
    )
    .expect("scheme construction");

    let num_witnesses = r1cs.num_witnesses();
    let num_constraints = r1cs.num_constraints();
    let w1 = full_witness[..w1_size].to_vec();
    let w2 = full_witness[w1_size..num_witnesses].to_vec();
    let public = PublicInputs::from_vec(vec![]);
    let instance = public.hash_bytes(HASH);
    let ds = scheme.create_domain_separator().instance(&instance);

    // Clone outside the timer — `prove_noir` consumes it, but the copy isn't
    // proving work.
    let r1cs_owned = r1cs.clone();

    let start = Instant::now();
    let mut merlin = ProverState::new(&ds, TranscriptSponge::from_config(HASH));
    let c1 = scheme
        .commit(&mut merlin, num_witnesses, num_constraints, w1, true)
        .expect("commit w1");
    // Challenge draws (the real flow does these in `solve_witness_vec`).
    let _challenges: Vec<FieldElement> = merlin.verifier_message_vec(num_challenges);
    let c2 = scheme
        .commit(&mut merlin, num_witnesses, num_constraints, w2, false)
        .expect("commit w2");
    scheme
        .prove_noir(merlin, r1cs_owned, vec![c1, c2], full_witness, &public)
        .expect("prove");
    start.elapsed()
}

/// Build, validate, time, and print one sized bench.
fn run_sized_bench(
    label: &str,
    witnesses: usize,
    constraints: usize,
    w1: usize,
    challenges: usize,
) {
    let field = if cfg!(feature = "bn254") {
        "bn254"
    } else {
        "goldilocks"
    };
    let (r1cs, w) = sized_r1cs(witnesses, constraints, 0x0a6e_c4ec);
    // Validate the generator (cheap, outside the timer).
    assert!(
        satisfies(&r1cs, &w),
        "[{label}] generated R1CS must be satisfiable"
    );
    let nnz = r1cs.a().iter().count() + r1cs.b().iter().count() + r1cs.c().iter().count();
    let dur = time_dual_commit_prove(&r1cs, w, w1, challenges);
    println!(
        "[{label}] field={field} witnesses={} constraints={} w1={w1} challenges={challenges} \
         nnz={nnz} prove={dur:?}",
        r1cs.num_witnesses(),
        r1cs.num_constraints(),
    );
}

#[test]
#[ignore = "scaled (m~16) smoke for the dual-commit benchmark path; run with --nocapture"]
fn bench_age_check_sized_scaled() {
    run_sized_bench(
        "scaled",
        SCALED_WITNESSES,
        SCALED_CONSTRAINTS,
        SCALED_W1,
        AGE_CHECK_CHALLENGES,
    );
}

#[test]
#[ignore = "full complete_age_check-sized proving-time benchmark; run --release --nocapture"]
fn bench_age_check_sized_full() {
    run_sized_bench(
        "age-check",
        AGE_CHECK_WITNESSES,
        AGE_CHECK_CONSTRAINTS,
        AGE_CHECK_W1,
        AGE_CHECK_CHALLENGES,
    );
}
