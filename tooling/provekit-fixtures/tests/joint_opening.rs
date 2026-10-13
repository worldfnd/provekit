//! Joint opening acceptance tests through the production prover and verifier.

use {
    ark_ff::{AdditiveGroup, Field},
    ark_std::rand::distributions::{Distribution, Standard},
    provekit_backend_bn254::{spark::SparkQueryBatch, Bn254Field, FieldElement},
    provekit_backend_goldilocks::{GoldilocksEfField, GoldilocksField},
    provekit_common::{
        Base, Ext, FieldHash, HashConfig, JointLinearForm, PrefixCovector, PublicInputs,
        PublicInputsHash, WhirR1CSScheme, WitnessCommitmentMode,
    },
    provekit_fixtures::builders::{
        challenge_with_public_input, multi_challenge_inverses_w2, two_public_inputs,
    },
    provekit_prover::{SparkQueryData, WhirR1CSProver},
    provekit_spark::{
        preprocess_spark, SparkMatrix, SparkProverContext, SparkProverScheme, SparkVerifierScheme,
    },
    provekit_verifier::WhirR1CSVerifier,
    whir::{
        algebra::{
            embedding::Embedding,
            fields::{Field64, Field64_3},
            linear_form::LinearForm,
        },
        buffer::Buffer,
        protocols::{
            params::{FoldingFactor, Mode, PowBudget, RateSchedule, SecuritySpec, TuningSpec},
            zook::ProtocolConfig,
        },
        transcript::{
            codecs::Empty, DomainSeparator, Proof, ProverState, VerificationResult,
            VerifierMessage, VerifierState,
        },
    },
};

const HASH: HashConfig = HashConfig::Sha256;

#[derive(Clone, Copy)]
enum Change {
    None,
    PublicWitness,
    StageChallenge,
}

fn check_full_r1cs<P>(mode: WitnessCommitmentMode, change: Change) -> SparkQueryData<P>
where
    P: FieldHash,
    P::Embedding: Embedding<Target = Base<P>>,
    Standard: Distribution<Ext<P>>,
{
    P::register();
    // The witness is [1, 3 | c, 1/c]. The constraints are 3*1=3 and c*(1/c)=1.
    let (mut r1cs, mut left, offsets) = challenge_with_public_input::<Base<P>>(3);
    // Eight constraints also meet SPARK's minimum matrix dimensions.
    let one = Base::<P>::ONE;
    for _ in 1..4 {
        r1cs.add_constraint(&[(one, 1)], &[(one, 0)], &[(one, 1)]);
        r1cs.add_constraint(&[(one, 2)], &[(one, 3)], &[(one, 0)]);
    }
    if matches!(change, Change::PublicWitness) {
        left[1] += Base::<P>::ONE;
    }
    let public = PublicInputs::from_vec(vec![Base::<P>::from(3)]);
    let scheme =
        WhirR1CSScheme::<P>::new_for_r1cs(&r1cs, left.len(), 1, offsets, true, HASH, mode).unwrap();
    scheme.validate_joint_opening().unwrap();
    assert_eq!(scheme.whir_witness.security().target_security_bits, 128);
    let instance = public.hash_bytes::<P>(HASH);
    let ds = scheme.create_domain_separator().instance(&instance);
    let mut prover = ProverState::new(&ds, P::transcript_sponge(HASH));
    let first = scheme
        .commit(&mut prover, 4, r1cs.num_constraints(), left.clone(), true)
        .unwrap();
    let mut challenges: Vec<Base<P>> = prover.verifier_message_vec(1);
    if matches!(change, Change::StageChallenge) {
        challenges[0] += Base::<P>::ONE;
    }
    let right = multi_challenge_inverses_w2(&challenges, &left).unwrap();
    assert_eq!(right[0] * right[1], Base::<P>::ONE);
    let second = scheme
        .commit(&mut prover, 4, r1cs.num_constraints(), right.clone(), false)
        .unwrap();
    let mut full_witness = left;
    full_witness.extend(right);
    let (proof, queries) = scheme
        .prove_noir_with_spark(
            prover,
            r1cs.clone(),
            vec![first, second],
            full_witness,
            &public,
        )
        .unwrap();

    // One matrix query keeps the selector and every source coordinate.
    assert_eq!(queries.queries.len(), 1);
    assert_eq!(queries.queries[0].col.len(), scheme.m + 1);
    let result = scheme.verify(&proof, &public, &r1cs);
    match change {
        Change::None => result.unwrap(),
        Change::PublicWitness | Change::StageChallenge => {
            let expected = match change {
                Change::PublicWitness => "public",
                _ => "challenge",
            };
            let error = result.unwrap_err();
            assert!(
                format!("{error:#}").to_lowercase().contains(expected),
                "{error:#}"
            );
            return queries;
        }
    }

    let wrong_public = PublicInputs::from_vec(vec![Base::<P>::from(4)]);
    assert!(scheme.verify(&proof, &wrong_public, &r1cs).is_err());
    let mut truncated = proof;
    truncated.narg_string.pop();
    assert!(scheme.verify(&truncated, &public, &r1cs).is_err());
    queries
}

#[test]
fn bn254_joint_r1cs_proof_binds_public_inputs_and_stage_challenges() {
    for mode in [
        WitnessCommitmentMode::Standard,
        WitnessCommitmentMode::ZeroKnowledge,
    ] {
        check_spark(check_full_r1cs::<Bn254Field>(mode, Change::None));
    }
}

fn check_spark(queries: SparkQueryData<Bn254Field>) {
    let n = 1usize << (queries.queries[0].col.len() - 1);
    let columns = 2 * n;
    let (mut rows, mut cols) = (Vec::new(), Vec::new());
    // SPARK uses the block matrix [A B; 0 C] over the two padded witnesses.
    for i in 0..4 {
        let a = 2 * i;
        let b = a + 1;
        for (row, col) in [
            (a, 1),
            (b, n),
            (a, columns),
            (b, columns + n + 1),
            (8 + a, columns + 1),
            (8 + b, columns),
        ] {
            rows.push(row);
            cols.push(col);
        }
    }
    let mut values = vec![FieldElement::ONE; rows.len()];
    rows.resize(32, 0);
    cols.resize(32, 0);
    values.resize(32, FieldElement::ZERO);
    let matrix = SparkMatrix::new(rows, cols, values, 16, 2 * columns);
    let (setup, witnesses) = preprocess_spark(&matrix, HASH);
    let context = SparkProverContext {
        matrix,
        witnesses,
        setup,
    };
    let scheme = SparkProverScheme {
        whir_configs:      context.setup.whir_configs.clone(),
        matrix_dimensions: context.setup.matrix_dimensions.clone(),
    };
    let batch = SparkQueryBatch::from(queries);
    let proof = scheme.prove(&context, &batch).unwrap();
    SparkVerifierScheme
        .verify(proof, &context.setup, &batch)
        .unwrap();
}

#[test]
fn extension_leaf_joint_r1cs_proof_binds_public_inputs_and_stage_challenges() {
    // Existing R1CS challenge slots store one field element, so this path uses
    // Identity<Field64_3>. The next test exercises Basefield<Field64_3> directly.
    for mode in [
        WitnessCommitmentMode::Standard,
        WitnessCommitmentMode::ZeroKnowledge,
    ] {
        check_full_r1cs::<GoldilocksEfField>(mode, Change::None);
    }
}

#[test]
fn base_field_witnesses_open_genuine_extension_claims_with_provekit_forms() {
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
    let ds = DomainSeparator::protocol(&"provekit-joint-forms").instance(&Empty);
    let mut prover = ProverState::new(&ds, P::transcript_sponge(HASH));
    let first = source.commit(&mut prover, Buffer::from(left));
    let challenge: F = prover.verifier_message();
    let second = source.commit(&mut prover, Buffer::from(right));
    let result = source
        .prove_pair(&mut prover, [first, second], &refs, &values)
        .unwrap();
    prover.prover_message(&F::from(987));
    let proof = prover.proof();

    let verify = |proof: &Proof, values: &[F]| -> VerificationResult<()> {
        let mut verifier = VerifierState::new(&ds, proof, P::transcript_sponge(HASH));
        let first = source.receive_commitment(&mut verifier)?;
        let received: F = verifier.verifier_message();
        assert_eq!(received, challenge);
        let second = source.receive_commitment(&mut verifier)?;
        let final_claim = source.verify_pair(&mut verifier, [first, second], &refs, values)?;
        assert_eq!(final_claim.evaluation_point, result.evaluation_point);
        final_claim.verify(&refs)?;
        let trailing: F = verifier.prover_message()?;
        assert_eq!(trailing, F::from(987));
        verifier.check_eof()
    };
    verify(&proof, &values).unwrap();
    let mut false_values = values;
    false_values[1] += F::ONE;
    assert!(verify(&proof, &false_values).is_err());
}

#[test]
fn joint_proofs_reject_incorrect_public_witnesses_and_stage_challenges() {
    for mode in [
        WitnessCommitmentMode::Standard,
        WitnessCommitmentMode::ZeroKnowledge,
    ] {
        for change in [Change::PublicWitness, Change::StageChallenge] {
            check_full_r1cs::<Bn254Field>(mode, change);
        }
    }
}

fn bn254_scheme() -> WhirR1CSScheme<Bn254Field> {
    type P = Bn254Field;
    P::register();
    let (r1cs, left, offsets) = challenge_with_public_input::<Base<P>>(3);
    WhirR1CSScheme::<P>::new_for_r1cs(
        &r1cs,
        left.len(),
        1,
        offsets,
        true,
        HASH,
        WitnessCommitmentMode::Standard,
    )
    .unwrap()
}

#[test]
fn joint_preflight_checks_source_size_and_challenge_and_commitment_counts() {
    let scheme = bn254_scheme();
    scheme.validate_joint_opening().unwrap();
    scheme.validate_witness_commitment_count(2).unwrap();
    for count in [0, 1, 3] {
        assert!(scheme.validate_witness_commitment_count(count).is_err());
    }
    let mut wrong_size = scheme.clone();
    wrong_size.m += 1;
    assert!(wrong_size
        .validate_joint_opening()
        .unwrap_err()
        .to_string()
        .contains("source size"));
    let mut wrong_count = scheme;
    wrong_count.num_challenges += 1;
    assert!(wrong_count
        .validate_joint_opening()
        .unwrap_err()
        .to_string()
        .contains("Challenge count"));
}

#[test]
fn single_stage_proofs_open_one_witness() {
    type P = Bn254Field;
    P::register();
    let (r1cs, witness) = two_public_inputs::<Base<P>>(6, 7);
    let public = PublicInputs::from_vec(vec![witness[1], witness[2]]);
    for mode in [
        WitnessCommitmentMode::Standard,
        WitnessCommitmentMode::ZeroKnowledge,
    ] {
        let scheme =
            WhirR1CSScheme::<P>::new_for_r1cs(&r1cs, witness.len(), 0, vec![], true, HASH, mode)
                .unwrap();
        scheme.validate_joint_opening().unwrap();
        let instance = public.hash_bytes::<P>(HASH);
        let ds = scheme.create_domain_separator().instance(&instance);
        let mut prover = ProverState::new(&ds, P::transcript_sponge(HASH));
        let committed = scheme
            .commit(
                &mut prover,
                r1cs.num_witnesses(),
                r1cs.num_constraints(),
                witness.clone(),
                true,
            )
            .unwrap();
        let proof = scheme
            .prove_noir(
                prover,
                r1cs.clone(),
                vec![committed],
                witness.clone(),
                &public,
            )
            .unwrap();
        scheme.verify(&proof, &public, &r1cs).unwrap();
    }
}
