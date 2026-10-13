//! Readable tests for ProveKit's joint opening integration.
//!
//! The recording backend tests data routing only.
//! It does not implement a cryptographic opening and never verifies a proof.

use {
    anyhow::{bail, Result},
    ark_ff::Zero,
    provekit_backend_bn254::{Bn254Field, FieldElement, TranscriptSponge},
    provekit_common::{
        FieldHash, HashConfig, JointOpeningBackend, JointOpeningLayout, PublicInputs,
        PublicInputsHash, UnavailableJointOpening, WhirR1CSProof, WhirR1CSScheme,
        WitnessCommitmentMode, WitnessOpeningMode, R1CS,
    },
    provekit_fixtures::builders::{challenge_with_public_input, multi_challenge_inverses_w2},
    provekit_prover::{
        prove_from_alphas_ctx_with_joint_backend, prove_noir_with_joint_backend,
        ProveFromAlphasCtx, WhirR1CSCommitment, WhirR1CSProver,
    },
    provekit_verifier::verify_with_joint_backend,
    std::cell::{Cell, RefCell},
    whir::{
        algebra::{embedding::Identity, linear_form::LinearForm},
        protocols::{
            params::Mode,
            zook::{
                Commitment, CommittedWitness, FinalClaim, ProtocolConfig as ZookConfig, ProverClaim,
            },
        },
        transcript::{ProverState, VerifierMessage, VerifierState},
    },
};

type Scheme = WhirR1CSScheme<Bn254Field>;
type SourceConfig = ZookConfig<Identity<FieldElement>>;

fn field(value: u64) -> FieldElement {
    FieldElement::from(value)
}

/// The matrix equation is `w[1] * w[3] = w[2]`, or `3 * 4 = 12`.
fn multiplication_r1cs() -> R1CS<FieldElement> {
    let mut r1cs = R1CS::new();
    r1cs.num_public_inputs = 1;
    r1cs.add_witnesses(5);
    r1cs.add_constraint(&[(field(1), 1)], &[(field(1), 3)], &[(field(1), 2)]);
    r1cs
}

fn scheme(opening_mode: WitnessOpeningMode) -> Scheme {
    Scheme::new_for_r1cs(
        &multiplication_r1cs(),
        3,
        1,
        vec![0],
        true,
        HashConfig::Sha256,
        WitnessCommitmentMode::Standard,
    )
    .unwrap()
    .with_witness_opening(opening_mode)
}

fn transcript(
    scheme: &Scheme,
    public_inputs: &PublicInputs<FieldElement>,
) -> ProverState<TranscriptSponge> {
    let instance = public_inputs.hash_bytes::<Bn254Field>(scheme.hash_config);
    let ds = scheme.create_domain_separator().instance(&instance);
    ProverState::new(&ds, Bn254Field::transcript_sponge(scheme.hash_config))
}

fn empty_context() -> ProveFromAlphasCtx<Bn254Field> {
    ProveFromAlphasCtx {
        alphas:           [vec![], vec![], vec![]],
        blinding_eval:    field(0),
        blinding_weights: vec![],
        commitments:      vec![],
        spark_row:        None,
    }
}

/// Commit both real source witnesses in their original order.
/// The fixed second witness tests routing and does not claim challenge
/// consistency.
fn routing_context(
    scheme: &Scheme,
    merlin: &mut ProverState<TranscriptSponge>,
) -> ProveFromAlphasCtx<Bn254Field> {
    let w1 = scheme
        .commit(merlin, 5, 1, vec![field(1), field(3), field(12)], true)
        .unwrap();
    let _stage_challenge: FieldElement = merlin.verifier_message();
    let w2 = scheme
        .commit(merlin, 5, 1, vec![field(4), field(9)], false)
        .unwrap();
    ProveFromAlphasCtx {
        alphas:           [
            vec![field(0), field(1), field(0), field(0), field(0)],
            vec![field(0), field(0), field(0), field(1), field(0)],
            vec![field(0), field(0), field(1), field(0), field(0)],
        ],
        // A zero form honestly opens the separate blinding commitment to zero.
        blinding_eval:    field(0),
        blinding_weights: vec![field(0); 4 * scheme.m_0],
        commitments:      vec![w1, w2],
        spark_row:        Some(vec![field(7)]),
    }
}

#[derive(Clone, Copy, Default)]
enum RecordingResult {
    #[default]
    CompletePoint,
    MissingSelector,
    MissingCoefficient,
    Error,
}

#[derive(Clone, Copy, Default)]
enum VerifierResult {
    #[default]
    SentinelError,
    MissingSelector,
    MissingCoefficient,
    WrongContribution,
}

#[derive(Clone)]
struct RecordedOpening {
    source_mode: Mode,
    source_size: usize,
    layout:      JointOpeningLayout,
    forms:       Vec<Vec<FieldElement>>,
    values:      Vec<FieldElement>,
    point:       Vec<FieldElement>,
}

/// This backend returns test data, not a cryptographic opening.
#[derive(Default)]
struct RecordingBackend {
    calls:                 Cell<usize>,
    verifier_calls:        Cell<usize>,
    recorded:              RefCell<Option<RecordedOpening>>,
    recorded_verification: RefCell<Option<RecordedOpening>>,
    result:                RecordingResult,
    verifier_result:       VerifierResult,
}

impl JointOpeningBackend<Bn254Field> for RecordingBackend {
    fn validate(&self, source: &SourceConfig, layout: JointOpeningLayout) -> Result<()> {
        layout.validate_source_config(source)
    }

    fn prove(
        &self,
        _transcript: &mut ProverState<TranscriptSponge>,
        source: &SourceConfig,
        layout: JointOpeningLayout,
        _witnesses: [CommittedWitness<Identity<FieldElement>>; 2],
        forms: &[&dyn LinearForm<FieldElement>],
        values: &[FieldElement],
    ) -> Result<ProverClaim<FieldElement>> {
        self.calls.set(self.calls.get() + 1);
        layout.validate_claims(forms, values)?;
        if matches!(self.result, RecordingResult::Error) {
            bail!("Recording backend opening error");
        }

        let coefficients = forms
            .iter()
            .map(|form| {
                let mut vector = vec![field(0); layout.size()];
                form.accumulate(&mut vector, field(1));
                vector
            })
            .collect();
        let mut point = vec![field(0); layout.num_variables()];
        point[0] = field(2);
        if matches!(self.result, RecordingResult::MissingSelector) {
            point.remove(0);
        }
        *self.recorded.borrow_mut() = Some(RecordedOpening {
            source_mode: source.security().mode,
            source_size: source.tuning().vector_size,
            layout,
            forms: coefficients,
            values: values.to_vec(),
            point: point.clone(),
        });

        let mut rlc_coefficients = vec![field(1); forms.len()];
        if matches!(self.result, RecordingResult::MissingCoefficient) {
            rlc_coefficients.pop();
        }
        Ok(ProverClaim {
            evaluation_point: point,
            rlc_coefficients,
        })
    }

    fn verify(
        &self,
        _transcript: &mut VerifierState<'_, TranscriptSponge>,
        source: &SourceConfig,
        layout: JointOpeningLayout,
        _commitments: [Commitment; 2],
        forms: &[&dyn LinearForm<FieldElement>],
        values: &[FieldElement],
    ) -> Result<FinalClaim<FieldElement>> {
        self.verifier_calls.set(self.verifier_calls.get() + 1);
        layout.validate_claims(forms, values)?;
        let coefficients = forms
            .iter()
            .map(|form| {
                let mut vector = vec![field(0); layout.size()];
                form.accumulate(&mut vector, field(1));
                vector
            })
            .collect();
        let mut point = vec![field(0); layout.num_variables()];
        point[0] = field(2);
        *self.recorded_verification.borrow_mut() = Some(RecordedOpening {
            source_mode: source.security().mode,
            source_size: source.tuning().vector_size,
            layout,
            forms: coefficients,
            values: values.to_vec(),
            point: point.clone(),
        });

        if matches!(self.verifier_result, VerifierResult::SentinelError) {
            bail!("The recording backend never verifies a proof");
        }
        let form_sum: FieldElement = forms.iter().map(|form| form.mle_evaluate(&point)).sum();
        let mut rlc_coefficients = vec![field(1); forms.len()];
        match self.verifier_result {
            VerifierResult::MissingSelector => {
                point.remove(0);
            }
            VerifierResult::MissingCoefficient => {
                rlc_coefficients.pop();
            }
            VerifierResult::WrongContribution => {}
            VerifierResult::SentinelError => unreachable!(),
        }
        // Every returned final claim deliberately fails a ProveKit check.
        Ok(FinalClaim {
            evaluation_point: point,
            initial_claim_scale: field(1),
            linear_forms_contribution: form_sum + field(1),
            rlc_coefficients,
        })
    }
}

#[test]
fn opening_mode_survives_scheme_json_and_postcard_round_trips() {
    for opening_mode in [WitnessOpeningMode::Separate, WitnessOpeningMode::Joint] {
        let original = scheme(opening_mode);
        let json = serde_json::to_string(&original).unwrap();
        let from_json: Scheme = serde_json::from_str(&json).unwrap();
        assert_eq!(from_json, original);

        let postcard = postcard::to_allocvec(&original).unwrap();
        let from_postcard: Scheme = postcard::from_bytes(&postcard).unwrap();
        assert_eq!(from_postcard, original);
    }
}

#[test]
fn old_json_without_an_opening_mode_is_rejected_explicitly() {
    let mut json = serde_json::to_value(scheme(WitnessOpeningMode::Separate)).unwrap();
    json.as_object_mut().unwrap().remove("witness_opening");
    let error = serde_json::from_value::<Scheme>(json).unwrap_err();
    assert!(error.to_string().contains("witness_opening"));
}

#[test]
fn joint_and_separate_modes_produce_different_transcript_challenges() {
    let separate = scheme(WitnessOpeningMode::Separate);
    let joint = separate
        .clone()
        .with_witness_opening(WitnessOpeningMode::Joint);
    let public = PublicInputs::from_vec(vec![field(3)]);

    // Fiat-Shamir challenges depend on the transcript, not the prover's private
    // RNG.
    let separate_challenge: FieldElement = transcript(&separate, &public).verifier_message();
    let repeated_challenge: FieldElement = transcript(&separate, &public).verifier_message();
    let joint_challenge: FieldElement = transcript(&joint, &public).verifier_message();
    assert_eq!(separate_challenge, repeated_challenge);
    assert_ne!(separate_challenge, joint_challenge);
}

#[test]
fn unavailable_backend_rejects_joint_and_keeps_existing_openings_available() {
    let unavailable = UnavailableJointOpening;
    let separate = scheme(WitnessOpeningMode::Separate);
    assert!(separate.validate_joint_backend(&unavailable).is_ok());

    let joint = separate.with_witness_opening(WitnessOpeningMode::Joint);
    let error = joint.validate_joint_backend(&unavailable).unwrap_err();
    assert!(error
        .to_string()
        .contains("Joint witness opening is unavailable"));

    let single = Scheme::new_for_r1cs(
        &multiplication_r1cs(),
        5,
        0,
        vec![],
        true,
        HashConfig::Sha256,
        WitnessCommitmentMode::Standard,
    )
    .unwrap()
    .with_witness_opening(WitnessOpeningMode::Joint);
    assert!(single.validate_joint_backend(&unavailable).is_ok());
}

#[test]
fn an_empty_commitment_list_returns_an_error_before_indexing() {
    let backend = RecordingBackend::default();
    let public = PublicInputs::new();
    for mode in [WitnessOpeningMode::Separate, WitnessOpeningMode::Joint] {
        let scheme = scheme(mode);
        let result = prove_from_alphas_ctx_with_joint_backend(
            &scheme,
            transcript(&scheme, &public),
            empty_context(),
            &public,
            &backend,
        );
        assert!(result.is_err());
    }
    assert_eq!(backend.calls.get(), 0);
}

#[test]
fn a_two_stage_scheme_rejects_one_or_three_commitments() {
    let scheme = scheme(WitnessOpeningMode::Joint);
    let public = PublicInputs::from_vec(vec![field(3)]);
    let backend = RecordingBackend::default();

    for count in [1, 3] {
        let mut merlin = transcript(&scheme, &public);
        let mut ctx = routing_context(&scheme, &mut merlin);
        if count == 1 {
            ctx.commitments.truncate(1);
        } else {
            // This duplicate tests count validation before any opening starts.
            let second = &ctx.commitments[1];
            ctx.commitments.push(WhirR1CSCommitment {
                witness:    second.witness.clone(),
                polynomial: second.polynomial.clone(),
                blinding:   None,
            });
        }

        let error =
            prove_from_alphas_ctx_with_joint_backend(&scheme, merlin, ctx, &public, &backend)
                .err()
                .expect("A two-stage scheme requires two commitments");
        assert!(format!("{error:#}").contains("commitment"), "{error:#}");
    }
    assert_eq!(backend.calls.get(), 0);
}

#[test]
fn joint_pipeline_calls_one_backend_with_three_matrix_and_two_binding_claims() {
    let scheme = scheme(WitnessOpeningMode::Joint);
    let public = PublicInputs::from_vec(vec![field(3)]);
    let backend = RecordingBackend::default();
    let mut merlin = transcript(&scheme, &public);
    let ctx = routing_context(&scheme, &mut merlin);
    let (_routing_payload, spark) =
        prove_from_alphas_ctx_with_joint_backend(&scheme, merlin, ctx, &public, &backend)
            .expect("The recording backend checks routing only");

    assert_eq!(backend.calls.get(), 1);
    let recorded = backend.recorded.borrow().as_ref().unwrap().clone();
    let block_size = scheme.domain_size();
    assert_eq!(recorded.source_size, block_size);
    assert_eq!(recorded.layout.size(), 2 * block_size);
    assert_eq!(recorded.forms.len(), 5);
    assert!(recorded
        .forms
        .iter()
        .all(|form| form.len() == 2 * block_size));

    // A selects 3 from w1. B selects 4 from w2. C selects 12 from w1.
    assert_eq!(&recorded.values[..3], &[field(3), field(4), field(12)]);
    assert_eq!(recorded.values[0] * recorded.values[1], recorded.values[2]);
    assert_eq!(recorded.forms[0][1], field(1));
    assert_eq!(recorded.forms[1][block_size], field(1));
    assert_eq!(recorded.forms[2][2], field(1));
    for (form, selected_index) in recorded.forms[..3].iter().zip([1, block_size, 2]) {
        for (index, coefficient) in form.iter().enumerate() {
            assert_eq!(
                *coefficient,
                if index == selected_index {
                    field(1)
                } else {
                    field(0)
                }
            );
        }
    }

    // Public binding gives 1 + 3*x on the first block.
    let x = recorded.forms[3][1];
    assert_eq!(recorded.values[3], field(1) + field(3) * x);
    assert!(recorded.forms[3][block_size..].iter().all(Zero::is_zero));
    // Challenge binding gives 4 at offset 0 of the second block.
    assert_eq!(recorded.values[4], field(4));
    assert!(recorded.forms[4][..block_size].iter().all(Zero::is_zero));
    assert_eq!(recorded.forms[4][block_size], field(1));

    let spark = spark.expect("SPARK query was requested");
    assert_eq!(spark.row, vec![field(7)]);
    assert_eq!(spark.queries.len(), 1);
    let query = &spark.queries[0];
    assert_eq!(query.col, recorded.point);
    assert_eq!(query.col.len(), scheme.m + 1);
    assert_eq!(query.col[0], field(2));
    // At beta=0, A and C are zero. The selector 2 multiplies B's second block.
    assert_eq!(query.claimed_a, field(0));
    assert_eq!(query.claimed_b, field(2));
    assert_eq!(query.claimed_c, field(0));
}

#[test]
fn joint_pipeline_rejects_backend_points_without_the_selector() {
    assert_bad_backend_result(RecordingResult::MissingSelector, "point has");
}

#[test]
fn joint_pipeline_rejects_backend_results_with_a_missing_claim_coefficient() {
    assert_bad_backend_result(RecordingResult::MissingCoefficient, "coefficient count");
}

#[test]
fn joint_pipeline_preserves_backend_opening_errors() {
    assert_bad_backend_result(RecordingResult::Error, "Recording backend opening error");
}

fn assert_bad_backend_result(result: RecordingResult, expected_error: &str) {
    let scheme = scheme(WitnessOpeningMode::Joint);
    let public = PublicInputs::from_vec(vec![field(3)]);
    let backend = RecordingBackend {
        result,
        ..RecordingBackend::default()
    };
    let mut merlin = transcript(&scheme, &public);
    let ctx = routing_context(&scheme, &mut merlin);
    let error = prove_from_alphas_ctx_with_joint_backend(&scheme, merlin, ctx, &public, &backend)
        .err()
        .expect("A malformed backend result must fail");
    assert!(format!("{error:#}").contains(expected_error), "{error:#}");
    assert_eq!(backend.calls.get(), 1);
}

#[test]
fn verifier_rejects_an_unavailable_backend_before_reading_a_proof() {
    let scheme = scheme(WitnessOpeningMode::Joint);
    let proof = WhirR1CSProof {
        narg_string: vec![],
        hints: vec![],
        #[cfg(debug_assertions)]
        pattern: vec![],
    };
    let error = verify_with_joint_backend(
        &scheme,
        &proof,
        &PublicInputs::from_vec(vec![field(3)]),
        &multiplication_r1cs(),
        &UnavailableJointOpening,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("Joint witness opening is unavailable"));
}

/// Produce a complete outer transcript with correct constraint witnesses.
/// The recording backend supplies no cryptographic joint opening payload.
fn full_outer_routing_fixture(
    backend: &RecordingBackend,
    public_witness: u64,
    change_challenge: bool,
    witness_mode: WitnessCommitmentMode,
) -> (
    Scheme,
    WhirR1CSProof,
    PublicInputs<FieldElement>,
    R1CS<FieldElement>,
) {
    let (r1cs, mut w1, offsets) = challenge_with_public_input::<FieldElement>(3);
    w1[1] = field(public_witness);
    let public = PublicInputs::from_vec(vec![field(3)]);
    let scheme = Scheme::new_for_r1cs(
        &r1cs,
        w1.len(),
        offsets.len(),
        offsets,
        true,
        HashConfig::Sha256,
        witness_mode,
    )
    .unwrap()
    .with_witness_opening(WitnessOpeningMode::Joint);
    scheme.validate_joint_backend(backend).unwrap();
    let mut merlin = transcript(&scheme, &public);
    let c1 = scheme
        .commit(
            &mut merlin,
            r1cs.num_witnesses(),
            r1cs.num_constraints(),
            w1.clone(),
            true,
        )
        .unwrap();
    let mut challenges: Vec<FieldElement> = merlin.verifier_message_vec(scheme.num_challenges);
    if change_challenge {
        challenges[0] += field(1);
    }
    let w2 = multi_challenge_inverses_w2(&challenges, &w1).unwrap();
    let c2 = scheme
        .commit(
            &mut merlin,
            r1cs.num_witnesses(),
            r1cs.num_constraints(),
            w2.clone(),
            false,
        )
        .unwrap();
    let full_witness = w1.into_iter().chain(w2).collect();
    let (routing_payload, spark) = prove_noir_with_joint_backend(
        &scheme,
        merlin,
        r1cs.clone(),
        vec![c1, c2],
        full_witness,
        &public,
        false,
        backend,
    )
    .expect("The recording backend tests the complete outer transcript only");
    assert!(spark.is_none());
    (scheme, routing_payload, public, r1cs)
}

#[test]
fn both_modes_reach_one_verifier_call_with_the_same_forms_and_values() {
    for witness_mode in [
        WitnessCommitmentMode::Standard,
        WitnessCommitmentMode::ZeroKnowledge,
    ] {
        let backend = RecordingBackend::default();
        let (scheme, routing_payload, public, r1cs) =
            full_outer_routing_fixture(&backend, 3, false, witness_mode);
        let error = verify_with_joint_backend(&scheme, &routing_payload, &public, &r1cs, &backend)
            .expect_err("The recording backend never verifies a proof");
        assert!(format!("{error:#}").contains("The recording backend never verifies a proof"));
        assert_eq!(backend.calls.get(), 1);
        assert_eq!(backend.verifier_calls.get(), 1);

        let prover = backend.recorded.borrow().as_ref().unwrap().clone();
        let verifier = backend
            .recorded_verification
            .borrow()
            .as_ref()
            .unwrap()
            .clone();
        assert_eq!(prover.source_mode, Mode::from(witness_mode));
        assert_eq!(prover.source_mode, verifier.source_mode);
        assert_eq!(prover.layout, verifier.layout);
        assert_eq!(prover.source_size, verifier.source_size);
        assert_eq!(prover.forms, verifier.forms);
        assert_eq!(prover.values, verifier.values);
        assert_eq!(verifier.values.len(), 5);
    }
}

#[test]
fn verifier_rejects_a_missing_selector_in_the_backend_final_point() {
    assert_bad_verifier_result(VerifierResult::MissingSelector, "point has");
}

#[test]
fn verifier_rejects_a_missing_backend_final_claim_coefficient() {
    assert_bad_verifier_result(VerifierResult::MissingCoefficient, "coefficient count");
}

#[test]
fn verifier_checks_the_combined_forms_at_the_backend_final_point() {
    assert_bad_verifier_result(
        VerifierResult::WrongContribution,
        "Joint WHIR final-claim check failed",
    );
}

fn assert_bad_verifier_result(verifier_result: VerifierResult, expected_error: &str) {
    let backend = RecordingBackend {
        verifier_result,
        ..RecordingBackend::default()
    };
    let (scheme, routing_payload, public, r1cs) =
        full_outer_routing_fixture(&backend, 3, false, WitnessCommitmentMode::Standard);
    let error = verify_with_joint_backend(&scheme, &routing_payload, &public, &r1cs, &backend)
        .expect_err("Every test final claim fails a ProveKit check");
    assert!(format!("{error:#}").contains(expected_error), "{error:#}");
    assert_eq!(backend.verifier_calls.get(), 1);
}

#[test]
fn verifier_rejects_a_wrong_public_witness_before_the_joint_backend() {
    let backend = RecordingBackend::default();
    let (scheme, routing_payload, public, r1cs) =
        full_outer_routing_fixture(&backend, 4, false, WitnessCommitmentMode::Standard);
    let error = verify_with_joint_backend(&scheme, &routing_payload, &public, &r1cs, &backend)
        .expect_err("The witness contains 4, but the public input is 3");
    assert!(
        format!("{error:#}").to_lowercase().contains("public"),
        "{error:#}"
    );
    assert_eq!(backend.verifier_calls.get(), 0);
}

#[test]
fn verifier_rejects_a_changed_challenge_before_the_joint_backend() {
    let backend = RecordingBackend::default();
    let (scheme, routing_payload, public, r1cs) =
        full_outer_routing_fixture(&backend, 3, true, WitnessCommitmentMode::Standard);
    let error = verify_with_joint_backend(&scheme, &routing_payload, &public, &r1cs, &backend)
        .expect_err("The witness challenge differs from the transcript challenge");
    assert!(
        format!("{error:#}").to_lowercase().contains("challenge"),
        "{error:#}"
    );
    assert_eq!(backend.verifier_calls.get(), 0);
}
