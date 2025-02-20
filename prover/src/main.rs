#![allow(dead_code)]
//! Crate for implementing and benchmarking the protocol described in WHIR paper appendix A

use ark_ff::Field;
use ark_std::Zero;
use clap::Parser;
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
    parameters::*,
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
fn main() {
    // m is equal to ceiling(log(number_of_constraints)). It is equal to the number of variables in the multilinear polynomial we are running our sumcheck on.
    let (sum_fhat_1, sum_fhat_2, sum_fhat_3, z, m) = extract_witness_and_witness_bound("./prover/r1cs_sample_bigger.json");
    let (whir_args, whir_params) = get_args_and_params(z.len());
    
    let io = IOPattern::<SkyscraperSponge, Field256>::new("🌪️")
        .add_rand(m)
        .add_sumcheck_polynomials(m)
        .commit_statement(&whir_params)
        .add_whir_proof(&whir_params)
        .clone();
    
    let mut merlin = io.to_merlin();
    let merlin = run_sumcheck_prover(sum_fhat_1, sum_fhat_2, sum_fhat_3, merlin, m);
    let (proof, merlin, statement, whir_params, io) = run_whir_pcs_prover(whir_args, io, z, whir_params, merlin, m);
    
    let mut arthur = io.to_arthur(merlin.transcript());
    let arthur = run_sumcheck_verifier(m, arthur);
    run_whir_pcs_verifier(whir_params, proof, arthur, statement);
}

fn run_sumcheck_prover(
    mut a: Vec<Field256>,
    mut b: Vec<Field256>,
    mut c: Vec<Field256>,
    mut merlin: Merlin<SkyscraperSponge, Field256>,
    m: usize,
) -> Merlin<SkyscraperSponge, Field256> {
    let mut sum = Field256::zero();
    // r is the combination randomness from the 2nd item of the interaction phase 
    let mut r = vec![Field256::from(0); m];
    let _ = merlin.fill_challenge_scalars(&mut r);
    let mut eq = calculate_evaluations_over_boolean_hypercube_for_eq(r);

    for i in 0..next_power_of_two(a.len()) {
        println!("---------------- For iteration {:?} ----------------", i);
        println!("A: {:?}", a);
        println!("B: {:?}", b); 
        println!("C: {:?}", c);
        println!("EQ: {:?}", eq);
        
        let mut eval_at_0 = Field256::from(0);
        let mut eval_at_em1 = Field256::from(0);
        let mut eval_at_inf = Field256::from(0);
        
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
            eval_at_0 += *eq.0 * (a.0 * b.0 - c.0);
            eval_at_em1 += (eq.0 + eq.0 - eq.1) * ((a.0 + a.0 - a.1) * (b.0 + b.0 - b.1) - (c.0 + c.0 - c.1));
            eval_at_inf += (eq.1 - eq.0) * (a.1 - a.0) * (b.1 - b.0);
        });

        let p0 = eval_at_0;
        let p2 = HALF * (eval_at_em1 - eval_at_0 - eval_at_0 - eval_at_0);
        let p3 = eval_at_inf;
        let p1 = sum - p0 - p0 - p3 - p2;

        let _ = merlin.add_scalars(&vec![p0, p1, p2, p3]);
        let mut r = vec![Field256::from(0)];
        let _ = merlin.fill_challenge_scalars(&mut r);

        eq = update_boolean_hypercube_values_with_r(eq, r[0]);
        a = update_boolean_hypercube_values_with_r(a, r[0]);
        b = update_boolean_hypercube_values_with_r(b, r[0]);
        c = update_boolean_hypercube_values_with_r(c, r[0]);
        
        println!("Eval at 0: {:?}", p0);
        println!("Eval at 1: {:?}", p0 + p1 + p2 + p3);
        println!("Supposed sum: {:?}", sum);
        sum = p0 + r[0] * (p1 + r[0] * (p2 + r[0] * p3));
        println!("Actual sum: {:?}", p0 + p0 + p1 + p2 + p3); 
    }
    println!("Eval at rand: {:?}", sum);
    merlin
}

fn run_whir_pcs_prover(
    args: Args, 
    io: IOPattern::<SkyscraperSponge, Field256>, 
    witness: Vec<Field256>, 
    params: WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW>, 
    mut merlin: Merlin<SkyscraperSponge, Field256>, 
    log_constraints: usize
) -> (
    WhirProof<SkyscraperMerkleConfig, Field256>, 
    Merlin<SkyscraperSponge, Field256>,
    Statement<Field256>,
    WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW>, 
    IOPattern::<SkyscraperSponge, Field256>, 
) {   
    println!("=========================================");
    println!("Whir (PCS) 🌪️");
    println!("{}", params);
    if !params.check_pow_bits() {
        println!("WARN: more PoW bits required than what specified.");
    }

    // In appendix a, fhat_z is combination of fhat_v and fhat_w. But our input "witness" already combines these two.
    let fhat_z = CoefficientList::new(witness);

    let points: Vec<_> = (0..args.num_evaluations)
        .map(|i| MultilinearPoint(vec![Field256::from(i as u64); args.num_variables]))
        .collect();
    let evaluations = points
        .iter()
        .map(|point| fhat_z.evaluate_at_extension(point))
        .collect();

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
    log_constraints: usize,
    mut arthur: Arthur<SkyscraperSponge, Field256>,
) -> Arthur<SkyscraperSponge, Field256> {
    // r is the combination randomness from the 2nd item of the interaction phase 
    let mut r = vec![Field256::from(0); log_constraints];
    let _ = arthur.fill_challenge_scalars(&mut r);

    let mut prev_sum = Field256::from(0);

    for _ in 0..log_constraints {
        let mut sp = vec![Field256::from(0); 4];
        let mut r = vec![Field256::from(0); 1];
        let _ = arthur.fill_next_scalars(&mut sp);
        let _ = arthur.fill_challenge_scalars(&mut r);
        let eval_at_zero = eval_qubic_poly(&sp, &Field256::from(0));
        let eval_at_one = eval_qubic_poly(&sp, &Field256::from(1));
        assert_eq!(prev_sum, eval_at_zero + eval_at_one);
        prev_sum = eval_qubic_poly(&sp, &r[0]);
    }
    arthur
}

fn run_whir_pcs_verifier(
    params: WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW>, 
    proof: WhirProof<SkyscraperMerkleConfig, Field256>,
    mut arthur: Arthur<SkyscraperSponge, Field256>,
    statement: Statement<Field256>,
) { 
    let verifier = Verifier::new(params);
    verifier.verify(&mut arthur, &statement, &proof).unwrap();
}


