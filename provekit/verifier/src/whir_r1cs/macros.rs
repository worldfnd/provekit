use {
    super::prepare_statement_for_witness_verifier,
    anyhow::{ensure, Context, Result},
    ark_std::{One, Zero},
    provekit_common::{
        utils::sumcheck::{calculate_eq, eval_cubic_poly},
        FieldElement, WhirR1CSProof, WhirR1CSScheme,
    },
    tracing::instrument,
    whir::{
        poly_utils::multilinear::MultilinearPoint,
        whir::{
            committer::{reader::ParsedCommitment, CommitmentReader},
            parameters::WhirConfig as GenericWhirConfig,
            statement::Statement,
            utils::HintDeserialize,
            verifier::Verifier,
        },
    },
};

pub struct DataFromSumcheckVerifier {
    pub r:                 Vec<FieldElement>,
    pub alpha:             Vec<FieldElement>,
    pub last_sumcheck_val: FieldElement,
}

macro_rules! impl_verifier_for_hash {
    ($name:ident, $merkle_config:ty, $sponge:ty, $pow:ty) => {
        paste::paste! {
            pub mod [<$name:lower _verifier>] {
                use super::*;
                use provekit_common::hash::{$merkle_config, $sponge, $pow};
                use provekit_common::utils::sumcheck::SumcheckIOPattern;
                use provekit_common::witness::WitnessIOPattern;
                use spongefish::codecs::arkworks_algebra::{FieldToUnitDeserialize, UnitToField};
                use spongefish::{DomainSeparator, VerifierState};
                use whir::whir::domainsep::WhirDomainSeparator;

                pub type WhirConfig = GenericWhirConfig<FieldElement, $merkle_config, $pow>;
                pub type IOPattern = DomainSeparator<$sponge, FieldElement>;

                fn build_whir_config(num_variables: usize, batch_size: usize) -> WhirConfig {
                    use whir::{
                        ntt::RSDefault,
                        parameters::{
                            default_max_pow, DeduplicationStrategy, FoldingFactor,
                            MerkleProofStrategy, MultivariateParameters, ProtocolParameters,
                            SoundnessType,
                        },
                    };
                    use std::sync::Arc;

                    const MIN_WHIR_NUM_VARIABLES: usize = 12;
                    let nv = num_variables.max(MIN_WHIR_NUM_VARIABLES);
                    let mv_params = MultivariateParameters::new(nv);
                    let whir_params = ProtocolParameters {
                        initial_statement: true,
                        security_level: 128,
                        pow_bits: default_max_pow(nv, 1),
                        folding_factor: FoldingFactor::Constant(4),
                        leaf_hash_params: Default::default(),
                        two_to_one_params: Default::default(),
                        soundness_type: SoundnessType::ConjectureList,
                        _pow_parameters: Default::default(),
                        starting_log_inv_rate: 1,
                        batch_size,
                        deduplication_strategy: DeduplicationStrategy::Disabled,
                        merkle_proof_strategy: MerkleProofStrategy::Uncompressed,
                    };
                    let reed_solomon = Arc::new(RSDefault);
                    let basefield_reed_solomon = reed_solomon.clone();
                    GenericWhirConfig::new(reed_solomon, basefield_reed_solomon, mv_params, whir_params)
                }

                #[instrument(skip_all)]
                pub fn create_io_pattern(scheme: &WhirR1CSScheme) -> IOPattern {
                    use provekit_common::utils::next_power_of_two;

                    let whir_witness = build_whir_config(scheme.m, 2);
                    // Must match r1cs-compiler: next_power_of_two(4 * m_0) + 1, batch_size = 2
                    let whir_for_hiding_spartan = build_whir_config(next_power_of_two(4 * scheme.m_0) + 1, 2);

                    let mut io = IOPattern::new("\u{1F32A}\u{FE0F}");

                    if scheme.num_challenges > 0 {
                        let num_witnesses = 2;
                        let num_ood_constraints = num_witnesses * whir_witness.committment_ood_samples;
                        let num_statement_constraints = 6;
                        let num_constraints_total = num_ood_constraints + num_statement_constraints;

                        io = io
                            .commit_statement(&whir_witness)
                            .add_logup_challenges(scheme.num_challenges)
                            .commit_statement(&whir_witness)
                            .add_rand(scheme.m_0)
                            .commit_statement(&whir_for_hiding_spartan)
                            .add_zk_sumcheck_polynomials(scheme.m_0)
                            .add_whir_proof(&whir_for_hiding_spartan)
                            .hint("claimed_evaluations_1")
                            .hint("claimed_evaluations_2")
                            .add_whir_batch_proof(&whir_witness, num_witnesses, num_constraints_total);
                    } else {
                        io = io
                            .commit_statement(&whir_witness)
                            .add_rand(scheme.m_0)
                            .commit_statement(&whir_for_hiding_spartan)
                            .add_zk_sumcheck_polynomials(scheme.m_0)
                            .add_whir_proof(&whir_for_hiding_spartan)
                            .hint("claimed_evaluations")
                            .add_whir_proof(&whir_witness);
                    }

                    io
                }

                #[instrument(skip_all)]
                pub fn verify(scheme: &WhirR1CSScheme, proof: &WhirR1CSProof) -> Result<()> {
                    let io = create_io_pattern(scheme);
                    let mut arthur = io.to_verifier_state(&proof.transcript);

                    let whir_witness = build_whir_config(scheme.m, 2);
                    let whir_for_hiding_spartan = build_whir_config(
                        provekit_common::utils::next_power_of_two(4 * scheme.m_0) + 1,
                        2,
                    );

                    let commitment_reader = CommitmentReader::new(&whir_witness);
                    let parsed_commitment_1 = commitment_reader.parse_commitment(&mut arthur)?;

                    let parsed_commitment_2 = if scheme.num_challenges > 0 {
                        let mut _logup_challenges = vec![FieldElement::zero(); scheme.num_challenges];
                        arthur.fill_challenge_scalars(&mut _logup_challenges)?;
                        Some(commitment_reader.parse_commitment(&mut arthur)?)
                    } else {
                        None
                    };

                    let data_from_sumcheck_verifier =
                        run_sumcheck_verifier(&mut arthur, scheme.m_0, &whir_for_hiding_spartan)
                            .context("while verifying sumcheck")?;

                    let (az_at_alpha, bz_at_alpha, cz_at_alpha) =
                        if let Some(parsed_commitment_2) = parsed_commitment_2 {
                            let sums_1: (Vec<FieldElement>, Vec<FieldElement>) = arthur.hint()?;
                            let sums_2: (Vec<FieldElement>, Vec<FieldElement>) = arthur.hint()?;

                            let whir_sums_1: ([FieldElement; 3], [FieldElement; 3]) =
                                (sums_1.0.try_into().unwrap(), sums_1.1.try_into().unwrap());
                            let whir_sums_2: ([FieldElement; 3], [FieldElement; 3]) =
                                (sums_2.0.try_into().unwrap(), sums_2.1.try_into().unwrap());

                            let statement_1 = prepare_statement_for_witness_verifier::<3>(
                                scheme.m,
                                &parsed_commitment_1,
                                &whir_sums_1,
                            );
                            let statement_2 = prepare_statement_for_witness_verifier::<3>(
                                scheme.m,
                                &parsed_commitment_2,
                                &whir_sums_2,
                            );

                            run_whir_pcs_batch_verifier(
                                &mut arthur,
                                &whir_witness,
                                &[parsed_commitment_1, parsed_commitment_2],
                                &[statement_1, statement_2],
                            )
                            .context("while verifying WHIR batch proof")?;

                            (
                                whir_sums_1.0[0] + whir_sums_2.0[0],
                                whir_sums_1.0[1] + whir_sums_2.0[1],
                                whir_sums_1.0[2] + whir_sums_2.0[2],
                            )
                        } else {
                            let sums: (Vec<FieldElement>, Vec<FieldElement>) = arthur.hint()?;
                            let whir_sums: ([FieldElement; 3], [FieldElement; 3]) =
                                (sums.0.try_into().unwrap(), sums.1.try_into().unwrap());

                            let statement = prepare_statement_for_witness_verifier::<3>(
                                scheme.m,
                                &parsed_commitment_1,
                                &whir_sums,
                            );

                            run_whir_pcs_verifier(
                                &mut arthur,
                                &parsed_commitment_1,
                                &whir_witness,
                                &statement,
                            )
                            .context("while verifying WHIR proof")?;

                            (whir_sums.0[0], whir_sums.0[1], whir_sums.0[2])
                        };

                    ensure!(
                        data_from_sumcheck_verifier.last_sumcheck_val
                            == (az_at_alpha * bz_at_alpha - cz_at_alpha)
                                * calculate_eq(
                                    &data_from_sumcheck_verifier.r,
                                    &data_from_sumcheck_verifier.alpha
                                ),
                        "last sumcheck value does not match"
                    );

                    Ok(())
                }

                #[instrument(skip_all)]
                fn run_sumcheck_verifier(
                    arthur: &mut VerifierState<$sponge, FieldElement>,
                    m_0: usize,
                    whir_for_spartan_blinding_config: &WhirConfig,
                ) -> Result<DataFromSumcheckVerifier> {
                    let mut r = vec![FieldElement::zero(); m_0];
                    let _ = arthur.fill_challenge_scalars(&mut r);

                    let commitment_reader = CommitmentReader::new(whir_for_spartan_blinding_config);
                    let parsed_commitment = commitment_reader.parse_commitment(arthur)?;

                    let mut sum_g_buf = [FieldElement::zero()];
                    arthur.fill_next_scalars(&mut sum_g_buf)?;

                    let mut rho_buf = [FieldElement::zero()];
                    arthur.fill_challenge_scalars(&mut rho_buf)?;
                    let rho = rho_buf[0];

                    let mut saved_val_for_sumcheck_equality_assertion = rho * sum_g_buf[0];

                    let mut alpha = vec![FieldElement::zero(); m_0];

                    for item in alpha.iter_mut().take(m_0) {
                        let mut hhat_i = [FieldElement::zero(); 4];
                        let mut alpha_i = [FieldElement::zero(); 1];
                        let _ = arthur.fill_next_scalars(&mut hhat_i);
                        let _ = arthur.fill_challenge_scalars(&mut alpha_i);
                        *item = alpha_i[0];
                        let hhat_i_at_zero = eval_cubic_poly(hhat_i, FieldElement::zero());
                        let hhat_i_at_one = eval_cubic_poly(hhat_i, FieldElement::one());
                        ensure!(
                            saved_val_for_sumcheck_equality_assertion == hhat_i_at_zero + hhat_i_at_one,
                            "Sumcheck equality assertion failed"
                        );
                        saved_val_for_sumcheck_equality_assertion = eval_cubic_poly(hhat_i, alpha_i[0]);
                    }

                    let mut values_of_polynomial_sums = [FieldElement::zero(); 2];
                    let _ = arthur.fill_next_scalars(&mut values_of_polynomial_sums);

                    let statement_verifier = prepare_statement_for_witness_verifier::<1>(
                        whir_for_spartan_blinding_config.mv_parameters.num_variables,
                        &parsed_commitment,
                        &([values_of_polynomial_sums[0]], [values_of_polynomial_sums[1]]),
                    );

                    run_whir_pcs_verifier(
                        arthur,
                        &parsed_commitment,
                        whir_for_spartan_blinding_config,
                        &statement_verifier,
                    )
                    .context("while verifying WHIR")?;

                    let f_at_alpha =
                        saved_val_for_sumcheck_equality_assertion - rho * values_of_polynomial_sums[0];

                    Ok(DataFromSumcheckVerifier {
                        r,
                        alpha,
                        last_sumcheck_val: f_at_alpha,
                    })
                }

                #[instrument(skip_all)]
                fn run_whir_pcs_verifier(
                    arthur: &mut VerifierState<$sponge, FieldElement>,
                    parsed_commitment: &ParsedCommitment<FieldElement, FieldElement>,
                    params: &WhirConfig,
                    statement_verifier: &Statement<FieldElement>,
                ) -> Result<(MultilinearPoint<FieldElement>, Vec<FieldElement>)> {
                    let verifier = Verifier::new(params);
                    let (folding_randomness, deferred) = verifier
                        .verify(arthur, parsed_commitment, statement_verifier)
                        .context("while verifying WHIR")?;
                    Ok((folding_randomness, deferred))
                }

                #[instrument(skip_all)]
                fn run_whir_pcs_batch_verifier(
                    arthur: &mut VerifierState<$sponge, FieldElement>,
                    params: &WhirConfig,
                    parsed_commitments: &[ParsedCommitment<FieldElement, FieldElement>],
                    statements: &[Statement<FieldElement>],
                ) -> Result<(MultilinearPoint<FieldElement>, Vec<FieldElement>)> {
                    let verifier = Verifier::new(params);
                    let (folding_randomness, deferred) = verifier
                        .verify_batch(arthur, parsed_commitments, statements)
                        .context("while verifying batch WHIR")?;
                    Ok((folding_randomness, deferred))
                }
            }
        }
    };
}

impl_verifier_for_hash!(
    Skyscraper,
    SkyscraperMerkleConfig,
    SkyscraperSponge,
    SkyscraperPoW
);
impl_verifier_for_hash!(Sha2, Sha2MerkleConfig, Sha2Sponge, Sha2PoW);
impl_verifier_for_hash!(Sha3, Sha3MerkleConfig, Sha3Sponge, Sha3PoW);
impl_verifier_for_hash!(Blake3, Blake3MerkleConfig, Blake3Sponge, Blake3PoW);
