#![allow(dead_code)]
//! Crate for implementing and benchmarking the protocol described in WHIR paper appendix A

use ark_std::Zero;
use nimue::{Merlin, Arthur};
use nimue::IOPattern;
use nimue::plugins::ark::FieldReader;
use nimue::plugins::ark::FieldChallenges;
use nimue::plugins::ark::FieldWriter;
use prover::skyscraper::{
    skyscraper::SkyscraperSponge, 
    skyscraper_pow::SkyscraperPoW,
    skyscraper_for_whir::SkyscraperMerkleConfig,
};
use whir::{
    crypto::fields::Field256,
    poly_utils::{coeffs::CoefficientList, MultilinearPoint},
    whir::{
        committer::Committer,
        iopattern::WhirIOPattern,
        parameters::WhirConfig, prover::Prover,
        verifier::Verifier, 
        Statement,
    },
    
};
use prover::utils::*;
use prover::whir_utils::*;
use prover::sumcheck_utils::*;
use whir::whir::WhirProof;
use itertools::izip;

fn calculate_matrices_on_external_row(alpha: &Vec<Field256>, r1cs: &R1CS) -> (Vec<Field256>, Vec<Field256>, Vec<Field256>) {
    let eq_alpha = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
    let mut alpha_a = vec![Field256::from(0); r1cs.num_variables];
    let mut alpha_b = vec![Field256::from(0); r1cs.num_variables];
    let mut alpha_c = vec![Field256::from(0); r1cs.num_variables];
    for cell in &r1cs.a {
        alpha_a[cell.signal] += eq_alpha[cell.constraint] * cell.value;
    }
    for cell in &r1cs.b {
        alpha_b[cell.signal] += eq_alpha[cell.constraint] * cell.value;
    }
    for cell in &r1cs.c {
        alpha_c[cell.signal] += eq_alpha[cell.constraint] * cell.value;
    }
    (alpha_a, alpha_b, alpha_c)
}

fn main() {
    // m is equal to ceiling(log(number_of_constraints)). It is equal to the number of variables in the multilinear polynomial we are running our sumcheck on.
    let (r1cs, witness) = parse_matrices_and_witness("./prover/r1cs_sample_bigger.json");
    let (sum_fhat_1, sum_fhat_2, sum_fhat_3, z, m) = calculate_witness_bounds(&r1cs, witness);
    let (whir_args, whir_params) = parse_args(z.len());
    
    let io = IOPattern::<SkyscraperSponge, Field256>::new("🌪️")
        .add_rand(m)
        .add_sumcheck_polynomials(m)
        .commit_statement(&whir_params)
        .add_whir_proof(&whir_params)
        .clone();
    
    let merlin = io.to_merlin();
    let (merlin, alpha) = run_sumcheck_prover(sum_fhat_1, sum_fhat_2, sum_fhat_3, merlin, m);
    let (a_alpha, b_alpha, c_alpha) = calculate_matrices_on_external_row(&alpha, &r1cs);
    let (proof, merlin, statement, whir_params, io) = run_whir_pcs_prover(whir_args, io, z, whir_params, merlin);
    let arthur = io.to_arthur(merlin.transcript());
    let arthur = run_sumcheck_verifier(m, arthur);
    run_whir_pcs_verifier(whir_params, proof, arthur, statement);
}

fn run_sumcheck_prover(
    // let a = sum_fhat_1, b = sum_fhat_2, c = sum_fhat_3 for brevity
    mut a: Vec<Field256>,
    mut b: Vec<Field256>,
    mut c: Vec<Field256>,
    mut merlin: Merlin<SkyscraperSponge, Field256>,
    m: usize,
) -> (Merlin<SkyscraperSponge, Field256>, Vec<Field256>) {
    println!("=========================================");
    println!("Running Prover - Sumcheck");
    let mut saved_val_for_sumcheck_equality_assertion = Field256::zero();
    // r is the combination randomness from the 2nd item of the interaction phase 
    let mut r = vec![Field256::from(0); m];
    let _ = merlin.fill_challenge_scalars(&mut r);
    let mut eq = calculate_evaluations_over_boolean_hypercube_for_eq(&r);
    let mut alpha = Vec::<Field256>::with_capacity(m);
    for i in 0..m {        
        // hhat_i_at_x = hhat_i(x). hhat_i(x) is the qubic sumcheck polynomial sent by the prover.
        let mut hhat_i_at_0 = Field256::from(0);
        let mut hhat_i_at_em1 = Field256::from(0);
        let mut hhat_i_at_inf = Field256::from(0);
        
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
            hhat_i_at_em1 += (eq.0 + eq.0 - eq.1) * ((a.0 + a.0 - a.1) * (b.0 + b.0 - b.1) - (c.0 + c.0 - c.1));
            hhat_i_at_inf += (eq.1 - eq.0) * (a.1 - a.0) * (b.1 - b.0);
        });

        let mut hhat_i_coeffs = vec![Field256::from(0); 4];
        hhat_i_coeffs[0] = hhat_i_at_0;
        hhat_i_coeffs[2] = HALF * (hhat_i_at_em1 - hhat_i_at_0 - hhat_i_at_0 - hhat_i_at_0);
        hhat_i_coeffs[3] = hhat_i_at_inf;
        hhat_i_coeffs[1] = saved_val_for_sumcheck_equality_assertion - hhat_i_coeffs[0] - hhat_i_coeffs[0] - hhat_i_coeffs[3] - hhat_i_coeffs[2];

        let _ = merlin.add_scalars(&vec![hhat_i_coeffs[0], hhat_i_coeffs[1], hhat_i_coeffs[2], hhat_i_coeffs[3]]);
        let mut alpha_i_wrapped_in_vector = vec![Field256::from(0)];
        let _ = merlin.fill_challenge_scalars(&mut alpha_i_wrapped_in_vector);
        let alpha_i = alpha_i_wrapped_in_vector[0];
        alpha.push(alpha_i);
        eq = update_boolean_hypercube_values(eq, alpha_i);
        a = update_boolean_hypercube_values(a, alpha_i);
        b = update_boolean_hypercube_values(b, alpha_i);
        c = update_boolean_hypercube_values(c, alpha_i);
        saved_val_for_sumcheck_equality_assertion = eval_qubic_poly(&hhat_i_coeffs, &alpha_i);
        println!("Prover Sumcheck: Round {i} Completed");
    }
    (merlin, alpha)
}

fn run_whir_pcs_prover(
    args: Args, 
    io: IOPattern::<SkyscraperSponge, Field256>, 
    z: Vec<Field256>, 
    params: WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW>, 
    mut merlin: Merlin<SkyscraperSponge, Field256>, 
) -> (
    WhirProof<SkyscraperMerkleConfig, Field256>, 
    Merlin<SkyscraperSponge, Field256>,
    Statement<Field256>,
    WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW>, 
    IOPattern::<SkyscraperSponge, Field256>, 
) {   
    println!("=========================================");
    println!("Running Prover - Whir Commitment");
    println!("{}", params);
    if !params.check_pow_bits() {
        println!("WARN: more PoW bits required than what specified.");
    }

    // In appendix a, fhat_z is combination of fhat_v and fhat_w. We should only commit to fhat_w. But for now, we are committing to fhat_z.
    let fhat_z = CoefficientList::new(z);

    let points: Vec<_> = (0..args.num_evaluations)
        .map(|i| MultilinearPoint(vec![Field256::from(i as u64); args.num_variables]))
        .collect();
    let evaluations = points
        .iter()
        .map(|point| fhat_z.evaluate_at_extension(point))
        .collect();

    let computed_evals: Vec<Field256> = (0..(1<<args.num_variables))
        .map(|i| {
            let mut bits = Vec::with_capacity(args.num_variables);
            for j in 0..args.num_variables {
                bits.push(if ((i >> j) & 1) == 1 { Field256::from(1) } else { Field256::from(0) });
            }
            bits.reverse();
            let point = MultilinearPoint(bits);
            fhat_z.evaluate_at_extension(&point)
        })
        .collect();

    println!("{:?}", computed_evals);

    let statement = Statement {
        points,
        evaluations,
    };

    let committer = Committer::new(params.clone());
    
    let witness = committer.commit(&mut merlin, fhat_z).unwrap();

    let prover = Prover(params.clone());

    let proof = prover
        .prove(&mut merlin, statement.clone(), witness)
        .unwrap();
    
    (proof, merlin, statement, params, io)
}

fn run_sumcheck_verifier(
    m: usize,
    mut arthur: Arthur<SkyscraperSponge, Field256>,
) -> Arthur<SkyscraperSponge, Field256> {
    println!("=========================================");
    println!("Running Verifier - Sumcheck");
    // r is the combination randomness from the 2nd item of the interaction phase 
    let mut r = vec![Field256::from(0); m];
    let _ = arthur.fill_challenge_scalars(&mut r);

    let mut saved_val_for_sumcheck_equality_assertion = Field256::from(0);

    for i in 0..m {
        let mut hhat_i = vec![Field256::from(0); 4];
        let mut alpha_i = vec![Field256::from(0); 1];
        let _ = arthur.fill_next_scalars(&mut hhat_i);
        let _ = arthur.fill_challenge_scalars(&mut alpha_i);
        let hhat_i_at_zero = eval_qubic_poly(&hhat_i, &Field256::from(0));
        let hhat_i_at_one = eval_qubic_poly(&hhat_i, &Field256::from(1));
        assert_eq!(saved_val_for_sumcheck_equality_assertion, hhat_i_at_zero + hhat_i_at_one);
        saved_val_for_sumcheck_equality_assertion = eval_qubic_poly(&hhat_i, &alpha_i[0]);
        println!("Verfier Sumcheck: Round {i} Completed");

    }
    arthur
}

fn run_whir_pcs_verifier(
    params: WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW>, 
    proof: WhirProof<SkyscraperMerkleConfig, Field256>,
    mut arthur: Arthur<SkyscraperSponge, Field256>,
    statement: Statement<Field256>,
) { 
    println!("=========================================");
    println!("Running Verifier - Whir Commitment ");
    let verifier = Verifier::new(params);
    verifier.verify(&mut arthur, &statement, &proof).unwrap();
}


