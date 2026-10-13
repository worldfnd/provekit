//! Acceptance tests for the real two-witness WHIR backend.
//!
//! The normal WHIR pin lacks this API. Enable `whir_pair_backend` only with
//! the compatible WHIR branch patched into the workspace. This adapter is an
//! integration fixture, not the default production backend.
#![allow(unexpected_cfgs)]
#![cfg(whir_pair_backend)]

use {
    anyhow::Result,
    ark_ff::{AdditiveGroup, Field},
    ark_std::rand::distributions::{Distribution, Standard},
    provekit_backend_bn254::Bn254Field,
    provekit_backend_goldilocks::{GoldilocksEfField, GoldilocksField},
    provekit_common::{
        Base, Ext, FieldHash, HashConfig, JointLinearForm, JointOpeningBackend, JointOpeningLayout,
        PrefixCovector, PublicInputs, PublicInputsHash, WhirR1CSScheme, WitnessCommitmentMode,
        WitnessOpeningMode,
    },
    provekit_fixtures::builders::{challenge_with_public_input, multi_challenge_inverses_w2},
    provekit_prover::{prove_noir_with_joint_backend, WhirR1CSProver},
    provekit_verifier::verify_with_joint_backend,
    whir::{
        algebra::{
            embedding::Embedding,
            fields::{Field64, Field64_3},
            linear_form::LinearForm,
        },
        buffer::Buffer,
        protocols::{
            params::{FoldingFactor, Mode, PowBudget, RateSchedule, SecuritySpec, TuningSpec},
            zook::{Commitment, CommittedWitness, FinalClaim, ProtocolConfig, ProverClaim},
        },
        transcript::{
            codecs::Empty, DomainSeparator, Proof, ProverState, VerifierMessage, VerifierState,
        },
    },
};

const HASH: HashConfig = HashConfig::Sha256;

struct WhirPairBackend;

impl<P: FieldHash> JointOpeningBackend<P> for WhirPairBackend
where
    Standard: Distribution<Ext<P>>,
{
    fn validate(
        &self,
        source: &ProtocolConfig<P::Embedding>,
        layout: JointOpeningLayout,
    ) -> Result<()> {
        layout.validate_source_config(source)?;
        source
            .validate_pair()
            .map_err(|_| anyhow::anyhow!("Invalid pair parameters"))?;
        Ok(())
    }

    fn prove(
        &self,
        transcript: &mut ProverState<P::Sponge>,
        source: &ProtocolConfig<P::Embedding>,
        layout: JointOpeningLayout,
        witnesses: [CommittedWitness<P::Embedding>; 2],
        forms: &[&dyn LinearForm<Ext<P>>],
        values: &[Ext<P>],
    ) -> Result<ProverClaim<Ext<P>>> {
        layout.validate_source_config(source)?;
        layout.validate_claims(forms, values)?;
        source
            .prove_pair(transcript, witnesses, forms, values)
            .map_err(|_| anyhow::anyhow!("Pair opening failed"))
    }

    fn verify(
        &self,
        transcript: &mut VerifierState<'_, P::Sponge>,
        source: &ProtocolConfig<P::Embedding>,
        layout: JointOpeningLayout,
        commitments: [Commitment; 2],
        forms: &[&dyn LinearForm<Ext<P>>],
        values: &[Ext<P>],
    ) -> Result<FinalClaim<Ext<P>>> {
        layout.validate_source_config(source)?;
        layout.validate_claims(forms, values)?;
        source
            .verify_pair(transcript, commitments, forms, values)
            .map_err(|_| anyhow::anyhow!("Invalid pair opening"))
    }
}

fn check_full_r1cs<P>(mode: WitnessCommitmentMode)
where
    P: FieldHash,
    P::Embedding: Embedding<Target = Base<P>>,
    Standard: Distribution<Ext<P>>,
{
    P::register();
    // The witness is [1, 3 | c, 1/c]. The constraints are 3*1=3 and c*(1/c)=1.
    let (r1cs, left, offsets) = challenge_with_public_input::<Base<P>>(3);
    let public = PublicInputs::from_vec(vec![Base::<P>::from(3)]);
    let scheme = WhirR1CSScheme::<P>::new_for_r1cs(&r1cs, left.len(), 1, offsets, true, HASH, mode)
        .unwrap()
        .with_witness_opening(WitnessOpeningMode::Joint);
    scheme.validate_joint_backend(&WhirPairBackend).unwrap();
    assert_eq!(scheme.whir_witness.security().target_security_bits, 128);
    let instance = public.hash_bytes::<P>(HASH);
    let ds = scheme.create_domain_separator().instance(&instance);
    let mut prover = ProverState::new(&ds, P::transcript_sponge(HASH));
    let first = scheme
        .commit(&mut prover, 4, 2, left.clone(), true)
        .unwrap();
    let challenges: Vec<Base<P>> = prover.verifier_message_vec(1);
    let right = multi_challenge_inverses_w2(&challenges, &left).unwrap();
    assert_eq!(right[0] * right[1], Base::<P>::ONE);
    let second = scheme
        .commit(&mut prover, 4, 2, right.clone(), false)
        .unwrap();
    let mut full_witness = left;
    full_witness.extend(right);
    let (proof, queries) = prove_noir_with_joint_backend(
        &scheme,
        prover,
        r1cs.clone(),
        vec![first, second],
        full_witness,
        &public,
        true,
        &WhirPairBackend,
    )
    .unwrap();
    verify_with_joint_backend(&scheme, &proof, &public, &r1cs, &WhirPairBackend).unwrap();

    // One combined matrix query keeps the selector and every source coordinate.
    let queries = queries.unwrap();
    assert_eq!(queries.queries.len(), 1);
    assert_eq!(queries.queries[0].col.len(), scheme.m + 1);

    let wrong_public = PublicInputs::from_vec(vec![Base::<P>::from(4)]);
    assert!(
        verify_with_joint_backend(&scheme, &proof, &wrong_public, &r1cs, &WhirPairBackend,)
            .is_err()
    );
    let mut truncated = proof.clone();
    truncated.narg_string.pop();
    assert!(
        verify_with_joint_backend(&scheme, &truncated, &public, &r1cs, &WhirPairBackend,).is_err()
    );
}

#[test]
fn bn254_joint_r1cs_proof_binds_public_inputs_and_stage_challenges() {
    for mode in [
        WitnessCommitmentMode::Standard,
        WitnessCommitmentMode::ZeroKnowledge,
    ] {
        check_full_r1cs::<Bn254Field>(mode);
    }
}

#[test]
fn extension_leaf_joint_r1cs_proof_binds_public_inputs_and_stage_challenges() {
    // Existing R1CS challenge slots store one field element, so this path uses
    // Identity<Field64_3>. The next test exercises Basefield<Field64_3> directly.
    for mode in [
        WitnessCommitmentMode::Standard,
        WitnessCommitmentMode::ZeroKnowledge,
    ] {
        check_full_r1cs::<GoldilocksEfField>(mode);
    }
}

#[test]
fn base_field_witnesses_open_genuine_extension_claims_through_the_adapter() {
    for mode in [Mode::Standard, Mode::ZeroKnowledge] {
        check_base_field_pair(mode);
    }
}

fn check_base_field_pair(mode: Mode) {
    type P = GoldilocksField;
    type F = Field64_3;
    P::register();
    let n = 256;
    let source = ProtocolConfig::<<P as provekit_common::ProofField>::Embedding>::derive(
        SecuritySpec::new(128)
            .with_mode(mode)
            .with_pow_budget(PowBudget::per_slot(10))
            .with_hash(HASH.engine_id()),
        TuningSpec {
            vector_size:           n,
            starting_log_inv_rate: 2,
            folding_factor:        FoldingFactor::Constant(2),
            rate_schedule:         RateSchedule::Stepping,
        },
    )
    .unwrap();
    let layout = JointOpeningLayout::new(n).unwrap();
    let e = F::new(Field64::ZERO, Field64::ONE, Field64::ZERO);
    let forms = [
        JointLinearForm::new(
            PrefixCovector::new([2, 3, 4, 0].map(F::from).to_vec(), n),
            PrefixCovector::new([11, 13].map(F::from).to_vec(), n),
        ),
        JointLinearForm::new(
            PrefixCovector::new(vec![F::ZERO, e + F::ONE], n),
            PrefixCovector::new(vec![e], n),
        ),
    ];
    let refs: Vec<&dyn LinearForm<F>> = forms.iter().map(|form| form as _).collect();
    // Left [1,2,3] gives 20. Right [5,7] gives 146. The total is 166.
    // The second claim is (e+1)*2 + e*5 = 7e+2, with e outside the base field.
    let values = [F::from(166), e * F::from(7) + F::from(2)];
    assert_ne!(values[1].c1, Field64::ZERO);
    let mut left = vec![Field64::ZERO; n];
    left[..3].copy_from_slice(&[1, 2, 3].map(Field64::from));
    let mut right = vec![Field64::ZERO; n];
    right[..2].copy_from_slice(&[5, 7].map(Field64::from));
    let ds = DomainSeparator::protocol(&"provekit-real-pair-adapter").instance(&Empty);
    let mut prover = ProverState::new(&ds, P::transcript_sponge(HASH));
    let first = source.commit(&mut prover, Buffer::from(left));
    let challenge: F = prover.verifier_message();
    let second = source.commit(&mut prover, Buffer::from(right));
    let result = <WhirPairBackend as JointOpeningBackend<P>>::prove(
        &WhirPairBackend,
        &mut prover,
        &source,
        layout,
        [first, second],
        &refs,
        &values,
    )
    .unwrap();
    prover.prover_message(&F::from(987));
    let proof = prover.proof();

    let verify = |proof: &Proof, values: &[F]| -> Result<()> {
        let mut verifier = VerifierState::new(&ds, proof, P::transcript_sponge(HASH));
        let first = source
            .receive_commitment(&mut verifier)
            .map_err(|_| anyhow::anyhow!("first commitment"))?;
        let received: F = verifier.verifier_message();
        assert_eq!(received, challenge);
        let second = source
            .receive_commitment(&mut verifier)
            .map_err(|_| anyhow::anyhow!("second commitment"))?;
        let final_claim = <WhirPairBackend as JointOpeningBackend<P>>::verify(
            &WhirPairBackend,
            &mut verifier,
            &source,
            layout,
            [first, second],
            &refs,
            values,
        )?;
        layout.validate_final_claim(&final_claim, forms.len())?;
        assert_eq!(final_claim.evaluation_point, result.evaluation_point);
        final_claim
            .verify(&refs)
            .map_err(|_| anyhow::anyhow!("final form check"))?;
        let trailing: F = verifier
            .prover_message()
            .map_err(|_| anyhow::anyhow!("trailing value"))?;
        assert_eq!(trailing, F::from(987));
        verifier
            .check_eof()
            .map_err(|_| anyhow::anyhow!("trailing bytes"))?;
        Ok(())
    };
    verify(&proof, &values).unwrap();
    let mut false_values = values;
    false_values[1] += F::ONE;
    assert!(verify(&proof, &false_values).is_err());
}
