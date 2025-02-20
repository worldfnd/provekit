#![allow(dead_code)]
//! Crate for implementing and benchmarking the protocol described in WHIR paper appendix A

use ark_ff::Field;
use ark_std::Zero;
use clap::Parser;
use nimue::Merlin;
use nimue::IOPattern;
use nimue::plugins::ark::FieldReader;
use nimue::plugins::ark::FieldChallenges;
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

fn main() {
    let (witness_bound_a, witness_bound_b, witness_bound_c, witness) = extract_witness_and_witness_bound("./prover/r1cs_sample_bigger.json");
    let (args, params) = get_args_and_params(witness.len());
    
    let log_constraints = next_power_of_two(witness_bound_a.len());
    let io = IOPattern::<SkyscraperSponge, Field256>::new("🌪️")
        .add_rand(log_constraints)
        .add_sumcheck_polynomials(log_constraints)
        .commit_statement(&params)
        .add_whir_proof(&params)
        .clone();
    
    let mut merlin = io.to_merlin();
    let mut rand = vec![Field256::from(0); log_constraints];
    let _ = merlin.fill_challenge_scalars(&mut rand);
    let eq = evaluations_over_boolean_hypercube_for_eq(rand);

    let merlin = prove_sumcheck(witness_bound_a, witness_bound_b, witness_bound_c, eq, Field256::zero(), merlin);
    let (proof, merlin, statement, params, io) = run_whir_pcs_prover(args, io, witness, params, merlin, log_constraints);
    run_whir_pcs_verifier(params, io, proof, merlin, log_constraints, statement);
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
)

{   
    

    println!("=========================================");
    println!("Whir (PCS) 🌪️");
    println!("{}", params);
    if !params.check_pow_bits() {
        println!("WARN: more PoW bits required than what specified.");
    }

    let polynomial = CoefficientList::new(witness);

    let points: Vec<_> = (0..args.num_evaluations)
        .map(|i| MultilinearPoint(vec![Field256::from(i as u64); args.num_variables]))
        .collect();
    let evaluations = points
        .iter()
        .map(|point| polynomial.evaluate_at_extension(point))
        .collect();

    let statement = Statement {
        points,
        evaluations,
    };

    let committer = Committer::new(params.clone());
    
    let witness = committer.commit(&mut merlin, polynomial).unwrap();

    let prover = Prover(params.clone());

    let proof = prover
        .prove(&mut merlin, statement.clone(), witness)
        .unwrap();
    
    (proof, merlin, statement, params, io)
}

fn run_whir_pcs_verifier(
    params: WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW>, 
    io: IOPattern::<SkyscraperSponge, Field256>,
    proof: WhirProof<SkyscraperMerkleConfig, Field256>,
    merlin: Merlin<SkyscraperSponge, Field256>,
    log_constraints: usize,
    statement: Statement<Field256>,
) {
    let verifier = Verifier::new(params);
    
    let mut arthur = io.to_arthur(merlin.transcript());
    
    let mut temporary = vec![Field256::from(0); log_constraints];
    let _ = arthur.fill_challenge_scalars(&mut temporary);
    
    let mut prev_sum = Field256::from(0);
    
    for _ in 0..log_constraints {
        let mut sp = vec![Field256::from(0); 4];
        let mut r = vec![Field256::from(0); 1];
        let _ = arthur.fill_next_scalars(&mut sp);
        let _ = arthur.fill_challenge_scalars(&mut r);
        // assert_eq!(prev_sum, )
        let eval_at_zero = eval_qubic_poly(&sp, &Field256::from(0));
        let eval_at_one = eval_qubic_poly(&sp, &Field256::from(1));
        assert_eq!(prev_sum, eval_at_zero + eval_at_one);
        prev_sum = eval_qubic_poly(&sp, &r[0]);
        // println!("{:?}", val);
    }

    verifier.verify(&mut arthur, &statement, &proof).unwrap();
}


