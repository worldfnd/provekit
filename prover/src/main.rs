use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::{BigInt, FftField, Field};
use ark_serialize::CanonicalSerialize;
use ark_std::str::FromStr;
use ark_std::Zero;
use ark_std::ops::{Add, Mul};
use clap::Parser;
use std::time::Instant;
use std::fs::File;
use serde::Deserialize;
use nimue::{Arthur, IOPattern, Merlin};
use prover::{
    skyscraper::SkyscraperSponge, 
    skyscraper_pow::SkyscraperPoW,
    skyscraper_traits_for_whir::{
        SkyscraperCRH, 
        SkyscraperTwoToOne, 
        SkyscraperMerkleConfig,
    },
};
use ruint::aliases::U256;
use ruint_macro::uint;
use whir::{
    crypto::{
        fields::Field256,
        merkle_tree::{self, HashCounter},
    },
    parameters::*,
    poly_utils::{coeffs::CoefficientList, MultilinearPoint},
    whir::{
        committer::Witness, fs_utils::{DigestReader, DigestWriter}, iopattern::DigestIOPattern
    },
};
use std::io::BufReader;
use serde_json::Result;

#[derive(Deserialize)]
struct MatrixCell {
    constraint: u32,
    signal: u32,
    value: String,
}

#[derive(Deserialize)]
struct R1CSWithWitness {
    num_public: u32,
    num_variables: u32,
    num_constraints: u32,
    a: Vec<MatrixCell>,
    b: Vec<MatrixCell>,
    c: Vec<MatrixCell>,
    witnesses: Vec<Vec<String>>,
}


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

    #[arg(long = "reps", default_value = "1000")]
    verifier_repetitions: usize,

    #[arg(short = 'k', long = "fold", default_value = "4")]
    folding_factor: usize,

    #[arg(long = "sec", default_value = "ConjectureList")]
    soundness_type: SoundnessType,

    #[arg(long = "fold_type", default_value = "ProverHelps")]
    fold_optimisation: FoldType,
}

type PowStrategy = SkyscraperPoW;

fn calculate_witness_bound(matrix_cells: Vec<MatrixCell>, witness: &Vec<Field256>, num_constraints: u32)->Vec<Field256> {
    let mut witness_bound = vec![Field256::from(0); num_constraints as usize];
    for x in matrix_cells {
        let cell = Field256::from_str(&x.value).expect("Failed to create Field256 value from a string");
        let witness_cell = witness[x.signal as usize];
        witness_bound[x.constraint as usize] = witness_bound[x.constraint as usize].add(cell.mul(witness_cell));
    }
    witness_bound
}

fn stringvec_to_fieldvec(witness: &Vec<String>) -> Vec<Field256> {
    witness.iter().map(|x|{Field256::from_str(x).expect("Failed to create Field256 value from a string")}).collect()
}

fn next_power_of_two(n: usize) -> usize {
    let mut power = 1;
    let mut ans = 0;
    while power < n {
        power <<= 1;
        ans += 1;
    }
    ans
}


fn pad_to_power_of_two(mut witness: Vec<Field256>) -> Vec<Field256> {
    let target_len = next_power_of_two(witness.len());
    while witness.len() < 1<<target_len {
        witness.push(Field256::zero()); // Pad with zeros
    }
    witness
}

fn main() {
    let file = File::open("./prover/disclose_wrencher.json").expect("Failed to open file");
    let r1cs_with_witness: R1CSWithWitness = serde_json::from_reader(file).expect("Failed to parse JSON with Serde");
    let witness = stringvec_to_fieldvec(&r1cs_with_witness.witnesses[0]);
    let witness = pad_to_power_of_two(witness);
    let witness_bound_a = calculate_witness_bound(r1cs_with_witness.a, &witness, r1cs_with_witness.num_constraints);
    let witness_bound_b = calculate_witness_bound(r1cs_with_witness.b, &witness, r1cs_with_witness.num_constraints);
    let witness_bound_c = calculate_witness_bound(r1cs_with_witness.c, &witness, r1cs_with_witness.num_constraints);
    
    let mut args = Args::parse();
    args.num_variables = next_power_of_two(witness.len());
    if args.pow_bits.is_none() {
        args.pow_bits = Some(default_max_pow(args.num_variables, args.rate));
    }
    run_whir_pcs(args, witness);
}

fn run_whir_pcs(args: Args, witness: Vec<Field256>) 
{   
    use Field256 as F;
    use whir::whir::{
        committer::Committer, iopattern::WhirIOPattern, parameters::WhirConfig, prover::Prover,
        verifier::Verifier, whir_proof_size, Statement,
    };

    // Runs as a PCS
    let security_level = args.security_level;
    let pow_bits = args.pow_bits.unwrap();
    let num_variables = args.num_variables;
    let starting_rate = args.rate;
    let reps = args.verifier_repetitions;
    let folding_factor = args.folding_factor;
    let fold_optimisation = args.fold_optimisation;
    let soundness_type = args.soundness_type;
    let num_evaluations = args.num_evaluations;

    if num_evaluations == 0 {
        println!("Warning: running as PCS but no evaluations specified.");
    }

    let num_coeffs = 1 << num_variables;

    let mv_params = MultivariateParameters::<F>::new(num_variables);

    let whir_params = WhirParameters::<SkyscraperMerkleConfig, PowStrategy> {
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

    let params = WhirConfig::<F, SkyscraperMerkleConfig, PowStrategy>::new(mv_params, whir_params);

    let io = IOPattern::<SkyscraperSponge, F>::new("🌪️")
        .commit_statement(&params)
        .add_whir_proof(&params)
        .clone();

    let mut merlin = io.to_merlin();

    println!("=========================================");
    println!("Whir (PCS) 🌪️");
    println!("{}", params);
    if !params.check_pow_bits() {
        println!("WARN: more PoW bits required than what specified.");
    }

    use ark_ff::Field;
    let polynomial = CoefficientList::new(witness);

    let points: Vec<_> = (0..num_evaluations)
        .map(|i| MultilinearPoint(vec![F::from(i as u64); num_variables]))
        .collect();
    let evaluations = points
        .iter()
        .map(|point| polynomial.evaluate_at_extension(point))
        .collect();

    let statement = Statement {
        points,
        evaluations,
    };

    let whir_prover_time = Instant::now();

    let committer = Committer::new(params.clone());
    let witness = committer.commit(&mut merlin, polynomial).unwrap();

    let prover = Prover(params.clone());

    let proof = prover
        .prove(&mut merlin, statement.clone(), witness)
        .unwrap();

    println!("Prover time: {:.1?}", whir_prover_time.elapsed());
    println!(
        "Proof size: {:.1} KiB",
        whir_proof_size(merlin.transcript(), &proof) as f64 / 1024.0
    );

    // Just not to count that initial inversion (which could be precomputed)
    let verifier = Verifier::new(params);

    HashCounter::reset();
    let whir_verifier_time = Instant::now();
    for _ in 0..reps {
        let mut arthur = io.to_arthur(merlin.transcript());
        verifier.verify(&mut arthur, &statement, &proof).unwrap();
    }
    println!(
        "Verifier time: {:.1?}",
        whir_verifier_time.elapsed() / reps as u32
    );
    println!(
        "Average hashes: {:.1}k",
        (HashCounter::get() as f64 / reps as f64) / 1000.0
    );
}
