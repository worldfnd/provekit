use {
    crate::{
        skyscraper::{SkyscraperMerkleConfig, SkyscraperPoW, SkyscraperSponge},
        utils::{
            next_power_of_two, pad_to_power_of_two, serde_ark, serde_hex,
            sumcheck::{
                calculate_eq, calculate_evaluations_over_boolean_hypercube_for_eq,
                calculate_external_row_of_r1cs_matrices, calculate_witness_bounds, eval_qubic_poly,
                sumcheck_fold_map_reduce, SumcheckIOPattern,
            },
            HALF,
        },
        FieldElement, R1CS,
    }, anyhow::{ensure, Context, Result}, ark_ff::UniformRand, ark_std::{One, Zero}, serde::{Deserialize, Serialize}, spongefish::{
        codecs::arkworks_algebra::{FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField},
        DomainSeparator, ProverState, VerifierState,
    }, std::fmt::{Debug, Formatter}, tracing::{info, instrument, warn}, whir::{
        parameters::{
            default_max_pow, FoldType, FoldingFactor, MultivariateParameters as GenericMultivariateParameters, ProtocolParameters as GenericWhirParameters, SoundnessType
        },
        poly_utils::{coeffs::CoefficientList, evals::EvaluationsList},
        whir::{
            committer::{reader::ParsedCommitment, CommitmentReader, CommitmentWriter, Witness},
            domainsep::WhirDomainSeparator,
            parameters::WhirConfig as GenericWhirConfig,
            prover::Prover,
            statement::{
                Statement, StatementVerifier as GenericStatementVerifier, VerifierWeights, Weights,
            },
            verifier::Verifier,
            WhirProof as GenericWhirProof,
        },
    }
};

pub type MultivariateParameters = GenericMultivariateParameters<FieldElement>;
pub type WhirParameters = GenericWhirParameters<SkyscraperMerkleConfig, SkyscraperPoW>;
pub type WhirConfig = GenericWhirConfig<FieldElement, SkyscraperMerkleConfig, SkyscraperPoW>;
pub type WhirProof = GenericWhirProof<SkyscraperMerkleConfig, FieldElement>;
pub type IOPattern = DomainSeparator<SkyscraperSponge, FieldElement>;
pub type StatementVerifier = GenericStatementVerifier<FieldElement>;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct WhirR1CSScheme {
    pub m:           usize,
    pub m_0:         usize,
    pub whir_config: WhirConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhirR1CSProof {
    #[serde(with = "serde_hex")]
    pub transcript: Vec<u8>,

    pub whir_proof: WhirProof,

    // TODO: Derive from transcript
    #[serde(with = "serde_ark")]
    pub whir_query_answer_sums: [FieldElement; 3],
}

struct DataFromSumcheckVerifier {
    r:                 Vec<FieldElement>,
    alpha:             Vec<FieldElement>,
    last_sumcheck_val: FieldElement,
}

impl WhirR1CSScheme {
    pub fn new_for_r1cs(r1cs: &R1CS) -> Self {
        Self::new_for_size(r1cs.witnesses, r1cs.constraints)
    }

    pub fn new_for_size(witnesses: usize, constraints: usize) -> Self {
        // m is equal to ceiling(log(number of variables in constraint system)). It is
        // equal to the log of the width of the matrices.
        let m = next_power_of_two(witnesses);

        // m_0 is equal to ceiling(log(number_of_constraints)). It is equal to the
        // number of variables in the multilinear polynomial we are running our sumcheck
        // on.
        let m_0 = next_power_of_two(constraints);

        // Whir parameters
        let mv_params = MultivariateParameters::new(m);
        let whir_params = WhirParameters{
            initial_statement:     true,
            security_level:        128,
            pow_bits:              default_max_pow(m, 1),
            folding_factor:        FoldingFactor::Constant(4),
            leaf_hash_params:      (),
            two_to_one_params:     (),
            soundness_type:        SoundnessType::ConjectureList,
            fold_optimisation:     FoldType::ProverHelps,
            _pow_parameters:       Default::default(),
            starting_log_inv_rate: 1,
            batch_size:            2,
        };
        let whir_config = WhirConfig::new(mv_params, whir_params);

        Self {
            m,
            m_0,
            whir_config,
        }
    }

    #[instrument(skip_all)]
    pub fn prove(&self, r1cs: &R1CS, witness: Vec<FieldElement>) -> Result<WhirR1CSProof> {
        ensure!(
            witness.len() == r1cs.witnesses,
            "Unexpected witness length for R1CS instance"
        );
        ensure!(
            r1cs.witnesses <= 1 << self.m,
            "R1CS witness length exceeds scheme capacity"
        );
        ensure!(
            r1cs.constraints <= 1 << self.m_0,
            "R1CS constraints exceed scheme capacity"
        );

        // Set up transcript
        let io: IOPattern = create_io_pattern(self.m_0, &self.whir_config);
        let mut merlin = io.to_prover_state();

        let z = pad_to_power_of_two(witness);
        let poly = EvaluationsList::new(z);
        let polynomial = poly.to_coeffs();

        let mut store = Vec::<FieldElement>::with_capacity(polynomial.num_coeffs());
        let mut rng = ark_std::rand::thread_rng();
        (0..(polynomial.num_coeffs()))
            .into_iter()
            .for_each(|_| store.push(FieldElement::rand(&mut rng)));

        let polynomial_rand = CoefficientList::new(store);
        let committer = CommitmentWriter::new(self.whir_config.clone());
        let hidden_witness = committer
            .commit_batch(&mut merlin, &[polynomial, polynomial_rand])
            .expect("WHIR prover failed to commit");

        let hidden_witness_coeffs = hidden_witness.batched_poly().coeffs();
        // First round of sumcheck to reduce R1CS to a batch weighted evaluation of the
        // witness
        let (merlin, alpha) = run_sumcheck_prover(r1cs, hidden_witness_coeffs, merlin, self.m_0);

        // Compute weights from R1CS instance
        let alphas = calculate_external_row_of_r1cs_matrices(&alpha, r1cs);

        // Compute WHIR weighted batch opening proof
        let (whir_proof, merlin, whir_query_answer_sums) =
            run_whir_pcs_prover(hidden_witness, &self.whir_config, merlin, self.m, alphas);

        let transcript = merlin.narg_string().to_vec();

        Ok(WhirR1CSProof {
            transcript,
            whir_proof,
            whir_query_answer_sums,
        })
    }

    #[instrument(skip_all)]
    #[allow(unused)] // TODO: Fix implementation
    pub fn verify(&self, proof: &WhirR1CSProof) -> Result<()> {
        // Set up transcript
        let io = create_io_pattern(self.m_0, &self.whir_config);
        let mut arthur = io.to_verifier_state(&proof.transcript);

        // Compute statement verifier
        let mut statement_verifier =
            StatementVerifier::from_statement(&Statement::<FieldElement>::new(self.m));
        for claimed_sum in &proof.whir_query_answer_sums {
            statement_verifier
                .add_constraint(VerifierWeights::linear(self.m, None), claimed_sum.clone());
        }
        
        let commitment_reader = CommitmentReader::new(&self.whir_config);
        let parsed_commitment = commitment_reader.parse_commitment(&mut arthur).unwrap();

        let data_from_sumcheck_verifier =
            run_sumcheck_verifier(&mut arthur, self.m_0).context("while verifying sumcheck")?;
        run_whir_pcs_verifier(
            &mut arthur,
            &self.whir_config,
            &proof.whir_proof,
            &statement_verifier,
            &parsed_commitment,
        )
        .context("while verifying WHIR proof")?;

        //Check the Spartan sumcheck relation.
        ensure!(
            data_from_sumcheck_verifier.last_sumcheck_val
                == (proof.whir_query_answer_sums[0] * proof.whir_query_answer_sums[1]
                    - proof.whir_query_answer_sums[2])
                    * calculate_eq(
                        &data_from_sumcheck_verifier.r,
                        &data_from_sumcheck_verifier.alpha
                    ),
            "last sumcheck value does not match"
        );

        // TODO: Verify evaluation of sparse matrices in random point.

        Ok(())
    }
}

// TODO: Implement Debug for WhirConfig and derive.
impl Debug for WhirR1CSScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhirR1CSScheme")
            .field("m", &self.m)
            .field("m_0", &self.m_0)
            .finish()
    }
}

#[instrument(skip_all)]
pub fn run_sumcheck_prover(
    r1cs: &R1CS,
    z: &[FieldElement],
    mut merlin: ProverState<SkyscraperSponge, FieldElement>,
    m_0: usize,
) -> (
    ProverState<SkyscraperSponge, FieldElement>,
    Vec<FieldElement>,
) {
    let mut saved_val_for_sumcheck_equality_assertion = FieldElement::zero();
    // r is the combination randomness from the 2nd item of the interaction phase
    let mut r = vec![FieldElement::zero(); m_0];
    merlin
        .fill_challenge_scalars(&mut r)
        .expect("Failed to extract challenge scalars from Merlin");

    // let a = sum_fhat_1, b = sum_fhat_2, c = sum_fhat_3 for brevity
    let ((mut a, mut b, mut c), mut eq) = rayon::join(
        || calculate_witness_bounds(r1cs, z),
        || calculate_evaluations_over_boolean_hypercube_for_eq(&r),
    );

    let mut alpha = Vec::<FieldElement>::with_capacity(m_0);

    let mut fold = None;

    for _ in 0..m_0 {
        // Here hhat_i_at_x represents hhat_i(x). hhat_i(x) is the qubic sumcheck
        // polynomial sent by the prover.
        let [hhat_i_at_0, hhat_i_at_em1, hhat_i_at_inf_over_x_cube] =
            sumcheck_fold_map_reduce([&mut a, &mut b, &mut c, &mut eq], fold, |[a, b, c, eq]| {
                [
                    // Evaluation at 0
                    eq.0 * (a.0 * b.0 - c.0),
                    // Evaluation at -1
                    (eq.0 + eq.0 - eq.1)
                        * ((a.0 + a.0 - a.1) * (b.0 + b.0 - b.1) - (c.0 + c.0 - c.1)),
                    // Evaluation at infinity
                    (eq.1 - eq.0) * (a.1 - a.0) * (b.1 - b.0),
                ]
            });
        if fold.is_some() {
            a.truncate(a.len() / 2);
            b.truncate(b.len() / 2);
            c.truncate(c.len() / 2);
            eq.truncate(eq.len() / 2);
        }

        let mut hhat_i_coeffs = [FieldElement::zero(); 4];

        hhat_i_coeffs[0] = hhat_i_at_0;
        hhat_i_coeffs[2] = HALF
            * (saved_val_for_sumcheck_equality_assertion + hhat_i_at_em1
                - hhat_i_at_0
                - hhat_i_at_0
                - hhat_i_at_0);
        hhat_i_coeffs[3] = hhat_i_at_inf_over_x_cube;
        hhat_i_coeffs[1] = saved_val_for_sumcheck_equality_assertion
            - hhat_i_coeffs[0]
            - hhat_i_coeffs[0]
            - hhat_i_coeffs[3]
            - hhat_i_coeffs[2];

        assert_eq!(
            saved_val_for_sumcheck_equality_assertion,
            hhat_i_coeffs[0]
                + hhat_i_coeffs[0]
                + hhat_i_coeffs[1]
                + hhat_i_coeffs[2]
                + hhat_i_coeffs[3]
        );

        let _ = merlin.add_scalars(&hhat_i_coeffs[..]);
        let mut alpha_i_wrapped_in_vector = [FieldElement::zero()];
        let _ = merlin.fill_challenge_scalars(&mut alpha_i_wrapped_in_vector);
        let alpha_i = alpha_i_wrapped_in_vector[0];
        alpha.push(alpha_i);

        fold = Some(alpha_i);

        saved_val_for_sumcheck_equality_assertion = eval_qubic_poly(&hhat_i_coeffs, &alpha_i);
    }
    (merlin, alpha)
}

#[instrument(skip_all)]
pub fn run_whir_pcs_prover(
    hidden_witness: Witness<FieldElement, SkyscraperMerkleConfig>,
    params: &WhirConfig,
    mut merlin: ProverState<SkyscraperSponge, FieldElement>,
    m: usize,
    alphas: [Vec<FieldElement>; 3],
) -> (
    WhirProof,
    ProverState<SkyscraperSponge, FieldElement>,
    [FieldElement; 3],
) {
    info!("WHIR Parameters: {params}");

    if !params.check_pow_bits() {
        warn!("More PoW bits required than specified.");
    }

    let batched_poly = hidden_witness.batched_poly();
    let poly_batched = EvaluationsList::from(batched_poly.clone());


    let mut statement = Statement::<FieldElement>::new(m);

    let sums: [FieldElement; 3] = alphas.map(|alpha| {
        let weight = Weights::linear(EvaluationsList::new(pad_to_power_of_two(alpha)));
        let sum = weight.weighted_sum(&poly_batched);
        statement.add_constraint(weight, sum);
        sum
    });

    let prover = Prover(params.clone());
    let proof = prover
        .prove(&mut merlin, statement, hidden_witness)
        .expect("WHIR prover failed to generate a proof");

    (proof, merlin, sums)
}

#[instrument(skip_all)]
pub fn run_sumcheck_verifier(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    m_0: usize,
) -> Result<DataFromSumcheckVerifier> {
    // r is the combination randomness from the 2nd item of the interaction phase
    let mut r = vec![FieldElement::zero(); m_0];
    let _ = arthur.fill_challenge_scalars(&mut r);

    let mut saved_val_for_sumcheck_equality_assertion = FieldElement::zero();

    let mut alpha = vec![FieldElement::zero(); m_0];

    for i in 0..m_0 {
        let mut hhat_i = [FieldElement::zero(); 4];
        let mut alpha_i = [FieldElement::zero(); 1];
        let _ = arthur.fill_next_scalars(&mut hhat_i);
        let _ = arthur.fill_challenge_scalars(&mut alpha_i);
        alpha[i] = alpha_i[0];
        let hhat_i_at_zero = eval_qubic_poly(&hhat_i, &FieldElement::zero());
        let hhat_i_at_one = eval_qubic_poly(&hhat_i, &FieldElement::one());
        ensure!(
            saved_val_for_sumcheck_equality_assertion == hhat_i_at_zero + hhat_i_at_one,
            "Sumcheck equality assertion failed"
        );
        saved_val_for_sumcheck_equality_assertion = eval_qubic_poly(&hhat_i, &alpha_i[0]);
    }

    Ok(DataFromSumcheckVerifier {
        r,
        alpha,
        last_sumcheck_val: saved_val_for_sumcheck_equality_assertion,
    })
}

#[instrument(skip_all)]
pub fn run_whir_pcs_verifier(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    params: &WhirConfig,
    proof: &WhirProof,
    statement_verifier: &StatementVerifier,
    parsed_commitment: &ParsedCommitment<FieldElement, FieldElement>,
) -> Result<()> {
    let verifier = Verifier::new(&params);
    // let verifier = Verifier::new(&params);
   
    verifier
        .verify(arthur, parsed_commitment, &statement_verifier, &proof)
        .context("while verifying WHIR")?;

    Ok(())
}

#[instrument(skip_all)]
pub fn create_io_pattern(m_0: usize, whir_params: &WhirConfig) -> IOPattern {
    IOPattern::new("🌪️")
        .commit_statement(&whir_params)
        .add_rand(m_0)
        .add_sumcheck_polynomials(m_0)
        .add_whir_proof(&whir_params)
}
