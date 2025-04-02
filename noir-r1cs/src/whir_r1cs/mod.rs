pub mod skyscraper;
pub mod sumcheck_utils;
pub mod utils;
pub mod whir_utils;

use {
    self::skyscraper::{SkyscraperMerkleConfig, SkyscraperPoW, SkyscraperSponge},
    crate::{
        prover::{
            create_io_pattern, run_sumcheck_prover, run_sumcheck_verifier, run_whir_pcs_prover,
            run_whir_pcs_verifier,
        },
        FieldElement, R1CS,
    },
    anyhow::{ensure, Context, Result},
    spongefish::DomainSeparator,
    std::fmt::{Debug, Formatter},
    tracing::instrument,
    utils::{calculate_eq, calculate_external_row_of_r1cs_matrices, next_power_of_two},
    whir::{
        parameters::{
            default_max_pow, FoldType, FoldingFactor,
            MultivariateParameters as GenericMultivariateParameters, SoundnessType,
            WhirParameters as GenericWhirParameters,
        },
        whir::{
            parameters::WhirConfig as GenericWhirConfig,
            statement::{Statement, StatementVerifier as GenericStatementVerifier},
            WhirProof as GenericWhirProof,
        },
    },
};

pub type MultivariateParameters = GenericMultivariateParameters<FieldElement>;
pub type WhirParameters = GenericWhirParameters<SkyscraperMerkleConfig, SkyscraperPoW>;
pub type WhirConfig = GenericWhirConfig<FieldElement, SkyscraperMerkleConfig, SkyscraperPoW>;
pub type WhirProof = GenericWhirProof<SkyscraperMerkleConfig, FieldElement>;
pub type IOPattern = DomainSeparator<SkyscraperSponge, FieldElement>;
pub type StatementVerifier = GenericStatementVerifier<FieldElement>;

#[derive(Clone)]
pub struct WhirR1CSScheme {
    m:           usize,
    m_0:         usize,
    whir_config: WhirConfig,
}

pub struct WhirR1CSProof {
    transcript: Vec<u8>,
    whir_proof: WhirProof,
    alpha: Vec<FieldElement>,
    r: Vec<FieldElement>,
    last_sumcheck_val: FieldElement,
    whir_query_answer_sums: [FieldElement; 3],
    statement: Statement<FieldElement>,
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
        let whir_params = WhirParameters {
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
        let io = create_io_pattern(self.m_0, &self.whir_config);
        let merlin = io.to_prover_state();

        // First round of sumcheck to reduce R1CS to a batch weighted evaluation of the
        // witness
        let (merlin, alpha, r, last_sumcheck_val) =
            run_sumcheck_prover(r1cs, &witness, merlin, self.m_0);

        // Compute weights from R1CS instance
        let alphas = calculate_external_row_of_r1cs_matrices(&alpha, r1cs);

        // Compute WHIR weighted batch opening proof
        let (whir_proof, merlin, whir_query_answer_sums, statement) =
            run_whir_pcs_prover(witness, &self.whir_config, merlin, self.m, alphas);

        let transcript = merlin.narg_string().to_vec();

        Ok(WhirR1CSProof {
            transcript,
            whir_proof,
            alpha,
            r,
            last_sumcheck_val,
            whir_query_answer_sums,
            statement,
        })
    }

    #[instrument(skip_all)]
    pub fn verify(&self, proof: &WhirR1CSProof) -> Result<()> {
        // Set up transcript
        let io = create_io_pattern(self.m_0, &self.whir_config);
        let mut arthur = io.to_verifier_state(&proof.transcript);

        // Compute statement verifier
        let statement_verifier = StatementVerifier::from_statement(&proof.statement);

        run_sumcheck_verifier(&mut arthur, self.m_0).context("while verifying sumcheck")?;
        run_whir_pcs_verifier(
            &mut arthur,
            &self.whir_config,
            &proof.whir_proof,
            &statement_verifier,
        )
        .context("while verifying WHIR proof")?;

        ensure!(
            proof.last_sumcheck_val
                == (proof.whir_query_answer_sums[0] * proof.whir_query_answer_sums[1]
                    - proof.whir_query_answer_sums[2])
                    * calculate_eq(&proof.r, &proof.alpha),
            "last sumcheck value does not match"
        );
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
