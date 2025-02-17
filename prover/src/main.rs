#![allow(dead_code)]
//! Crate for implementing and benchmarking the protocol described in WHIR paper appendix A

use ark_ff::Field;
use ark_std::{Zero, One};
use ark_std::ops::Mul;
use ark_crypto_primitives::merkle_tree::Config;
use clap::Parser;
use nimue::plugins::ark::FieldIOPattern;
use nimue::Arthur;
use nimue::Merlin;
use whir::whir::iopattern::DigestIOPattern;
use std::fs::File;
use nimue::IOPattern;
use nimue::plugins::ark::{FieldReader, FieldWriter};
use nimue::plugins::ark::FieldChallenges;
use prover::{
    skyscraper::SkyscraperSponge, 
    skyscraper::uint_to_field, 
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
use itertools::izip;
use prover::utils::{
    stringvec_to_fieldvec,
    pad_to_power_of_two,
    next_power_of_two,
    calculate_witness_bound,
    evaluations_over_boolean_hypercube_for_eq,
    R1CSWithWitness,
    HALF,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'l', long, default_value = "100")]
    security_level: usize,

    #[arg(short = 'p', long)]
    pow_bits: Option<usize>,

    #[arg(short = 'd', long, default_value = "20")]
    num_variables: usize,

    #[arg(short = 'e', long = "evaluations", default_value = "1")]
    num_evaluations: usize,

    #[arg(short = 'r', long, default_value = "1")]
    rate: usize,

    #[arg(short = 'k', long = "fold", default_value = "4")]
    folding_factor: usize,

    #[arg(long = "sec", default_value = "ConjectureList")]
    soundness_type: SoundnessType,

    #[arg(long = "fold_type", default_value = "ProverHelps")]
    fold_optimisation: FoldType,
}

fn update(mut f: Vec<Field256>, r: Field256) -> Vec<Field256> {
    let sz = f.len();
    let (left, right) = f.split_at_mut(sz / 2);
    for i in 0..(left.len()) {
        // println!("Before {:?} {:?} {:?}", left[i], r, right[i]-left[i]);
        left[i] += r * (right[i]-left[i]);
        // println!("After {:?}", left[i]);
    }
    left.to_vec()
}

fn prove_sumcheck(
    mut a: Vec<Field256>,
    mut b: Vec<Field256>,
    mut c: Vec<Field256>,
    mut eq: Vec<Field256>,
    mut sum: Field256,
    mut merlin: Merlin<SkyscraperSponge, Field256>,
) -> Merlin<SkyscraperSponge, Field256> {
    let rand: Vec<Field256> = (2..16).into_iter().map(|x| {Field256::from(x)}).collect();

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

        merlin.add_scalars(&vec![p0, p1, p2, p3]);
        let mut r = vec![Field256::from(0)];
        merlin.fill_challenge_scalars(&mut r);

        eq = update(eq, r[0]);
        a = update(a, r[0]);
        b = update(b, r[0]);
        c = update(c, r[0]);
        
        println!("Eval at 0: {:?}", p0);
        println!("Eval at 1: {:?}", p0 + p1 + p2 + p3);
        println!("Supposed sum: {:?}", sum);
        sum = p0 + r[0] * (p1 + r[0] * (p2 + r[0] * p3));
        println!("Actual sum: {:?}", p0 + p0 + p1 + p2 + p3); 
    }
    println!("Eval at rand: {:?}", sum);
    merlin
}

pub trait RandIOPattern {
    fn add_rand(self, num_rand: usize) -> Self;
}

impl<IOPattern> RandIOPattern for IOPattern 
where 
    IOPattern: FieldIOPattern<Field256>
{
    fn add_rand(self, num_rand: usize) -> Self {
        self.challenge_scalars(num_rand, "rand")
    }
}

pub trait SumcheckIOPattern {
    fn add_sumcheck_polynomials(self, num_vars: usize) -> Self;
}

impl<IOPattern> SumcheckIOPattern for IOPattern 
where 
    IOPattern: FieldIOPattern<Field256>
{
    fn add_sumcheck_polynomials(mut self, num_vars: usize) -> Self {
        for _ in 0..num_vars {
            self = self.add_scalars(4, "Sumcheck Polynomials");
            self = self.challenge_scalars(1, "Sumcheck Random");
        }
        self
    }
}

fn main() {
    let file = File::open("./prover/r1cs_sample_bigger.json").expect("Failed to open file");
    let r1cs_with_witness: R1CSWithWitness = serde_json::from_reader(file).expect("Failed to parse JSON with Serde");
    let witness = stringvec_to_fieldvec(&r1cs_with_witness.witnesses[0]);
    let witness = pad_to_power_of_two(witness);

    let mut args = Args::parse();
    
    args.num_variables = next_power_of_two(witness.len());
    if args.pow_bits.is_none() {
        args.pow_bits = Some(default_max_pow(args.num_variables, args.rate));
    }

    let security_level = args.security_level;
    let pow_bits = args.pow_bits.unwrap();
    let num_variables = args.num_variables;
    let starting_rate = args.rate;
    let folding_factor = args.folding_factor;
    let fold_optimisation = args.fold_optimisation;
    let soundness_type = args.soundness_type;
    let num_evaluations = args.num_evaluations;

    if num_evaluations == 0 {
        println!("Warning: running as PCS but no evaluations specified.");
    }

    let mv_params = MultivariateParameters::<Field256>::new(num_variables);

    let whir_params = WhirParameters::<SkyscraperMerkleConfig, SkyscraperPoW> {
        initial_statement: true,
        security_level,
        pow_bits,
        folding_factor,
        leaf_hash_params: (),
        two_to_one_params: (),
        soundness_type,
        fold_optimisation,
        _pow_parameters: Default::default(),
        starting_log_inv_rate: starting_rate,
    };

    let params = WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW>::new(mv_params, whir_params);
    
    
    // println!("{:?}", io);

    
    let witness_bound_a = pad_to_power_of_two(calculate_witness_bound(r1cs_with_witness.a, &witness, r1cs_with_witness.num_constraints));
    let witness_bound_b = pad_to_power_of_two(calculate_witness_bound(r1cs_with_witness.b, &witness, r1cs_with_witness.num_constraints));
    let witness_bound_c = pad_to_power_of_two(calculate_witness_bound(r1cs_with_witness.c, &witness, r1cs_with_witness.num_constraints));


    let log_constraints = next_power_of_two(witness_bound_a.len());

    let io = IOPattern::<SkyscraperSponge, Field256>::new("🌪️")
    .add_rand(log_constraints)
    .add_sumcheck_polynomials(log_constraints)
    .commit_statement(&params)
    .add_whir_proof(&params)
    .clone();
    
    let mut merlin = io.to_merlin();
    let mut rand = vec![Field256::from(0); log_constraints];
    merlin.fill_challenge_scalars(&mut rand);
    let eq = evaluations_over_boolean_hypercube_for_eq(rand);

    let mut merlin = prove_sumcheck(witness_bound_a, witness_bound_b, witness_bound_c, eq, Field256::zero(), merlin);
    

    run_whir_pcs(args, io, witness, params, merlin, log_constraints);
}

fn eval_qubic_poly(poly: &Vec<Field256>, point: &Field256) -> Field256 {
    poly[0] + *point * (poly[1] + *point * (poly[2] + *point * poly[3]))
}

fn run_whir_pcs(args: Args, io: IOPattern::<SkyscraperSponge, Field256>, witness: Vec<Field256>, params: WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW>, mut merlin: Merlin<SkyscraperSponge, Field256>, log_constraints: usize) 
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

    let verifier = Verifier::new(params);
    
    let mut temporary = vec![Field256::from(0); log_constraints];
    let mut arthur = io.to_arthur(merlin.transcript());
    
    arthur.fill_challenge_scalars(&mut temporary);
    
    
    let mut prev_sum = Field256::from(0);
    
    for _ in 0..log_constraints {
        let mut sp = vec![Field256::from(0); 4];
        let mut r = vec![Field256::from(0); 1];
        arthur.fill_next_scalars(&mut sp);
        arthur.fill_challenge_scalars(&mut r);
        // assert_eq!(prev_sum, )
        let eval_at_zero = eval_qubic_poly(&sp, &Field256::from(0));
        let eval_at_one = eval_qubic_poly(&sp, &Field256::from(1));
        assert_eq!(prev_sum, eval_at_zero + eval_at_one);
        prev_sum = eval_qubic_poly(&sp, &r[0]);
        // println!("{:?}", val);
    }

    verifier.verify(&mut arthur, &statement, &proof).unwrap();
}


