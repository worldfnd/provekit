//! Crate for implementing and benchmarking the protocol described in WHIR paper
//! appendix A
use {
    crate::{
        whir_r1cs::{
            skyscraper::{SkyscraperMerkleConfig, SkyscraperPoW, SkyscraperSponge},
            sumcheck_utils::{update_boolean_hypercube_values, SumcheckIOPattern},
            utils::{
                calculate_evaluations_over_boolean_hypercube_for_eq, calculate_witness_bounds,
                eval_qubic_poly, pad_to_power_of_two, HALF,
            },
        },
        FieldElement, R1CS,
    },
    anyhow::{ensure, Context as _, Result},
    ark_std::{One, Zero},
    itertools::izip,
    spongefish::{
        codecs::arkworks_algebra::{FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField},
        DomainSeparator, ProverState, VerifierState,
    },
    tracing::instrument,
    whir::{
        poly_utils::evals::EvaluationsList,
        whir::{
            committer::{CommitmentReader, CommitmentWriter},
            domainsep::WhirDomainSeparator,
            parameters::WhirConfig,
            prover::Prover,
            statement::{Statement, StatementVerifier, Weights},
            verifier::Verifier,
            WhirProof,
        },
    },
};

#[rustfmt::skip]
/*
pub fn main() {
    let args = parse_cli_args();
    let (r1cs, z) = deserialize_r1cs_and_z(&args.input_file_path);
    // m is equal to ceiling(log(number of variables in constraint system)). It is
    // equal to the log of the width of the matrices.
    let m = next_power_of_two(z.len());
    // m_0 is equal to ceiling(log(number_of_constraints)). It is equal to the
    // number of variables in the multilinear polynomial we are running our sumcheck
    // on.
    let m_0 = next_power_of_two(r1cs.num_constraints);
    let whir_params = generate_whir_params(m, args);

    let now = std::time::Instant::now();
    let io = create_io_pattern(m_0, &whir_params);

    let merlin = io.to_prover_state();
    let (merlin, alpha, r, last_sumcheck_val) = run_sumcheck_prover(&r1cs, &z, merlin, m_0);
    let alphas = calculate_external_row_of_r1cs_matrices(&alpha, &r1cs);
    let (proof, merlin, whir_params, io, whir_query_answer_sums, statement) =
        run_whir_pcs_prover(io, z, whir_params, merlin, m, alphas);
    eprintln!("Whir Prover: {} ms", now.elapsed().as_millis());

    let statement_verifier = StatementVerifier::<FieldElement>::from_statement(&statement);
    write_proof_bytes_to_file(&proof);
    write_gnark_parameters_to_file(
        &whir_params,
        &merlin,
        &io,
        whir_query_answer_sums.clone(),
        m_0,
        m,
    );

    let arthur = io.to_verifier_state(merlin.narg_string());
    let arthur = run_sumcheck_verifier(m_0, arthur);
    run_whir_pcs_verifier(whir_params, proof, arthur, statement_verifier);
    assert_eq!(
        last_sumcheck_val,
        (whir_query_answer_sums[0] * whir_query_answer_sums[1] - whir_query_answer_sums[2])
            * calculate_eq(&r, &alpha)
    );
}
*/

#[instrument(skip_all)]
pub fn run_sumcheck_prover(
    r1cs: &R1CS,
    z: &[FieldElement],
    mut merlin: ProverState<SkyscraperSponge, FieldElement>,
    m_0: usize,
) -> (
    ProverState<SkyscraperSponge, FieldElement>,
    Vec<FieldElement>,
    Vec<FieldElement>,
    FieldElement,
) {
    // let a = sum_fhat_1, b = sum_fhat_2, c = sum_fhat_3 for brevity
    let (mut a, mut b, mut c) = calculate_witness_bounds(r1cs, z);
    let mut saved_val_for_sumcheck_equality_assertion = FieldElement::zero();
    // r is the combination randomness from the 2nd item of the interaction phase
    let mut r = vec![FieldElement::zero(); m_0];
    merlin
        .fill_challenge_scalars(&mut r)
        .expect("Failed to extract challenge scalars from Merlin");
    let mut eq = calculate_evaluations_over_boolean_hypercube_for_eq(&r);
    let mut alpha = Vec::<FieldElement>::with_capacity(m_0);
    for _ in 0..m_0 {
        // Here hhat_i_at_x represents hhat_i(x). hhat_i(x) is the qubic sumcheck
        // polynomial sent by the prover.
        let mut hhat_i_at_0 = FieldElement::zero();
        let mut hhat_i_at_em1 = FieldElement::zero();
        let mut hhat_i_at_inf_over_x_cube = FieldElement::zero();

        let (a0, a1) = a.split_at(a.len() / 2);
        let (b0, b1) = b.split_at(b.len() / 2);
        let (c0, c1) = c.split_at(c.len() / 2);
        let (eq0, eq1) = eq.split_at(eq.len() / 2);

        izip!(
            a0.iter().zip(a1),
            b0.iter().zip(b1),
            c0.iter().zip(c1),
            eq0.iter().zip(eq1)
        )
        .for_each(|(a, b, c, eq)| {
            hhat_i_at_0 += *eq.0 * (a.0 * b.0 - c.0);
            hhat_i_at_em1 +=
                (eq.0 + eq.0 - eq.1) * ((a.0 + a.0 - a.1) * (b.0 + b.0 - b.1) - (c.0 + c.0 - c.1));
            hhat_i_at_inf_over_x_cube += (eq.1 - eq.0) * (a.1 - a.0) * (b.1 - b.0);
        });

        let mut hhat_i_coeffs = vec![FieldElement::zero(); 4];

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

        let _ = merlin.add_scalars(&vec![
            hhat_i_coeffs[0],
            hhat_i_coeffs[1],
            hhat_i_coeffs[2],
            hhat_i_coeffs[3],
        ]);
        let mut alpha_i_wrapped_in_vector = vec![FieldElement::zero()];
        let _ = merlin.fill_challenge_scalars(&mut alpha_i_wrapped_in_vector);
        let alpha_i = alpha_i_wrapped_in_vector[0];
        alpha.push(alpha_i);
        eq = update_boolean_hypercube_values(eq, alpha_i);
        a = update_boolean_hypercube_values(a, alpha_i);
        b = update_boolean_hypercube_values(b, alpha_i);
        c = update_boolean_hypercube_values(c, alpha_i);
        saved_val_for_sumcheck_equality_assertion = eval_qubic_poly(&hhat_i_coeffs, &alpha_i);
    }
    (merlin, alpha, r, saved_val_for_sumcheck_equality_assertion)
}

#[instrument(skip_all)]
pub fn run_whir_pcs_prover(
    io: DomainSeparator<SkyscraperSponge, FieldElement>,
    z: Vec<FieldElement>,
    params: &WhirConfig<FieldElement, SkyscraperMerkleConfig, SkyscraperPoW>,
    mut merlin: ProverState<SkyscraperSponge, FieldElement>,
    m: usize,
    alphas: [Vec<FieldElement>; 3],
) -> (
    WhirProof<SkyscraperMerkleConfig, FieldElement>,
    ProverState<SkyscraperSponge, FieldElement>,
    DomainSeparator<SkyscraperSponge, FieldElement>,
    [FieldElement; 3],
    Statement<FieldElement>,
) {
    println!("=========================================");
    println!("Running Prover - Whir Commitment");
    println!("{}", params);

    if !params.check_pow_bits() {
        println!("WARN: More PoW bits required than specified.");
    }

    let z = pad_to_power_of_two(z);
    let poly = EvaluationsList::new(z);
    let polynomial = poly.to_coeffs();

    let committer = CommitmentWriter::new(params.clone());
    let witness = committer
        .commit(&mut merlin, polynomial)
        .expect("WHIR prover failed to commit");

    let mut statement = Statement::<FieldElement>::new(m);

    let sums: [FieldElement; 3] = alphas.map(|alpha| {
        let weight = Weights::linear(EvaluationsList::new(pad_to_power_of_two(alpha)));
        let sum = weight.weighted_sum(&poly);
        statement.add_constraint(weight, sum);
        sum
    });

    let prover = Prover(params.clone());
    let proof = prover
        .prove(&mut merlin, statement.clone(), witness)
        .expect("WHIR prover failed to generate a proof");

    (proof, merlin, io, sums, statement)
}

#[instrument(skip_all)]
pub fn run_sumcheck_verifier(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    m_0: usize,
) -> Result<()> {
    // r is the combination randomness from the 2nd item of the interaction phase
    let mut r = vec![FieldElement::zero(); m_0];
    let _ = arthur.fill_challenge_scalars(&mut r);

    let mut saved_val_for_sumcheck_equality_assertion = FieldElement::zero();

    for i in 0..m_0 {
        let mut hhat_i = vec![FieldElement::zero(); 4];
        let mut alpha_i = vec![FieldElement::zero(); 1];
        let _ = arthur.fill_next_scalars(&mut hhat_i);
        let _ = arthur.fill_challenge_scalars(&mut alpha_i);
        let hhat_i_at_zero = eval_qubic_poly(&hhat_i, &FieldElement::zero());
        let hhat_i_at_one = eval_qubic_poly(&hhat_i, &FieldElement::one());
        ensure!(
            saved_val_for_sumcheck_equality_assertion == hhat_i_at_zero + hhat_i_at_one,
            "Sumcheck equality assertion failed"
        );
        saved_val_for_sumcheck_equality_assertion = eval_qubic_poly(&hhat_i, &alpha_i[0]);
    }
    Ok(())
}

#[instrument(skip_all)]
pub fn run_whir_pcs_verifier(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    params: &WhirConfig<FieldElement, SkyscraperMerkleConfig, SkyscraperPoW>,
    proof: &WhirProof<SkyscraperMerkleConfig, FieldElement>,
    statement_verifier: &StatementVerifier<FieldElement>,
) -> Result<()> {
    let commitment_reader = CommitmentReader::new(&params);
    let verifier = Verifier::new(&params);
    // let verifier = Verifier::new(&params);
    let parsed_commitment = commitment_reader.parse_commitment(arthur).unwrap();

    verifier
        .verify(arthur, &parsed_commitment, &statement_verifier, &proof)
        .context("while verifying WHIR")?;

    Ok(())
}

#[instrument(skip_all)]
pub fn create_io_pattern(
    m_0: usize,
    whir_params: &WhirConfig<FieldElement, SkyscraperMerkleConfig, SkyscraperPoW>,
) -> DomainSeparator<SkyscraperSponge, FieldElement> {
    DomainSeparator::<SkyscraperSponge, FieldElement>::new("🌪️")
        .add_rand(m_0)
        .add_sumcheck_polynomials(m_0)
        .commit_statement(&whir_params)
        .add_whir_proof(&whir_params)
}
