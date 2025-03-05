#![allow(dead_code)]
//! Crate for implementing and benchmarking the protocol described in WHIR paper appendix A
use ark_ff::Field;
use ark_std::Zero;
use ark_serialize::{CanonicalSerialize, Write};
use ark_poly::domain::EvaluationDomain;
use whir::poly_utils::evals::EvaluationsList;
use core::num;
use std::fs::File;
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
    },
    whir::statement::{Statement, StatementVerifier, Weights, VerifierWeights},
};
use prover::utils::*;
use prover::whir_utils::*;
use prover::whir_utils::GnarkConfig;
use prover::sumcheck_utils::*;
use whir::whir::WhirProof;
use itertools::izip;

fn calculate_external_row_of_r1cs_matrices(alpha: &Vec<Field256>, r1cs: &R1CS) -> (Vec<Field256>, Vec<Field256>, Vec<Field256>) {
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


// fn check_last_sumcheck(a: &Vec<Field256>, b: &Vec<Field256>, c: &Vec<Field256>, z: &Vec<Field256>, r: &Vec<Field256>, alpha: &Vec<Field256>) {
//     let a = calculate_dot_product(a, z);
//     let b = calculate_dot_product(b, z);
//     let c = calculate_dot_product(c, z);
//     let eq = calculate_eq(r, alpha);
// }

fn main() {
    // m is equal to ceiling(log(number_of_constraints)). It is equal to the number of variables in the multilinear polynomial we are running our sumcheck on.
    let (r1cs, witness) = parse_matrices_and_witness("./prover/disclose_wrencher.json");
    let (sum_fhat_1, sum_fhat_2, sum_fhat_3, mut z, m) = calculate_witness_bounds(&r1cs, witness);
    let (whir_args, whir_params) = parse_args(z.len());
    
    let io = IOPattern::<SkyscraperSponge, Field256>::new("🌪️")
        .add_rand(m)
        .add_sumcheck_polynomials(m)
        .commit_statement(&whir_params)
        .add_whir_proof(&whir_params)
        .clone();

    let merlin = io.to_merlin();
    let (merlin, alpha, r, last_sum) = run_sumcheck_prover(sum_fhat_1, sum_fhat_2, sum_fhat_3, merlin, m);
    // println!("Alpha: {:?}, r: {:?}", alpha, r);
    let (a_alpha, b_alpha, c_alpha) = calculate_external_row_of_r1cs_matrices(&alpha, &r1cs);
    
    // check_last_sumcheck(&a_alpha, &b_alpha, &c_alpha, &z, &r, &alpha);
    
    z = pad_to_power_of_two(z);
    let a_alpha = pad_to_power_of_two(a_alpha);
    let b_alpha = pad_to_power_of_two(b_alpha);
    let c_alpha = pad_to_power_of_two(c_alpha);
    let num_variables = next_power_of_two(z.len());
    let (proof, merlin, whir_params, io, sums) = run_whir_pcs_prover(whir_args, io, z, whir_params, merlin, num_variables, (a_alpha, b_alpha, c_alpha));
    
    let mut proof_bytes = vec![];
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    let mut file = File::create("proof").unwrap();
    file.write_all(&proof_bytes).expect("REASON");
    

    let gnark_config = GnarkConfig{
        n_rounds: whir_params.n_rounds(),
        rate: whir_params.starting_log_inv_rate,
        n_vars: whir_params.mv_parameters.num_variables,
        folding_factor: (0..whir_params.n_rounds())
            .map(|round| whir_params.folding_factor.at_round(round))
            .collect(),
        ood_samples: whir_params.round_parameters.iter().map(|x| x.ood_samples).collect(),
        num_queries: whir_params.round_parameters.iter().map(|x| x.num_queries).collect(),
        pow_bits: whir_params.round_parameters.iter().map(|x| x.pow_bits as i32).collect(),
        final_queries: whir_params.final_queries,
        final_pow_bits: whir_params.final_pow_bits as i32,
        final_folding_pow_bits: whir_params.final_folding_pow_bits as i32,
        domain_generator: format!("{}", whir_params.starting_domain.backing_domain.group_gen()),
        io_pattern: String::from_utf8(io.as_bytes().to_vec()).unwrap(),
        transcript: merlin.transcript().to_vec(),
        transcript_len: merlin.transcript().to_vec().len()
    };

    let mut file_params = File::create("params").unwrap();
    file_params.write_all(serde_json::to_string(&gnark_config).unwrap().as_bytes()).expect("REASON");
    let arthur = io.to_arthur(merlin.transcript());
    let arthur = run_sumcheck_verifier(m, arthur);
    run_whir_pcs_verifier(whir_params, proof, arthur, num_variables, sums.clone());
    assert_eq!(last_sum, (sums.0 * sums.1 - sums.2) * calculate_eq(&r, &alpha)); 
}

fn run_sumcheck_prover(
    // let a = sum_fhat_1, b = sum_fhat_2, c = sum_fhat_3 for brevity
    mut a: Vec<Field256>,
    mut b: Vec<Field256>,
    mut c: Vec<Field256>,
    mut merlin: Merlin<SkyscraperSponge, Field256>,
    m: usize,
) -> (Merlin<SkyscraperSponge, Field256>, Vec<Field256>, Vec<Field256>, Field256) {
    println!("=========================================");
    println!("Running Prover - Sumcheck");
    let mut saved_val_for_sumcheck_equality_assertion = Field256::zero();
    // r is the combination randomness from the 2nd item of the interaction phase 
    let mut r = vec![Field256::from(0); m];
    let _ = merlin.fill_challenge_scalars(&mut r);
    // let mut r = (m..2*m).map(|i| {Field256::from(i as u32)}).collect();
    let mut eq = calculate_evaluations_over_boolean_hypercube_for_eq(&r);
    // println!("EQ: {:?}", eq);
    let mut alpha = Vec::<Field256>::with_capacity(m);
    for _ in 0..m {        
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
        hhat_i_coeffs[2] = HALF * (saved_val_for_sumcheck_equality_assertion + hhat_i_at_em1 - hhat_i_at_0 - hhat_i_at_0 - hhat_i_at_0);
        hhat_i_coeffs[3] = hhat_i_at_inf;
        hhat_i_coeffs[1] = saved_val_for_sumcheck_equality_assertion - hhat_i_coeffs[0] - hhat_i_coeffs[0] - hhat_i_coeffs[3] - hhat_i_coeffs[2];
        
        assert_eq!(saved_val_for_sumcheck_equality_assertion, hhat_i_coeffs[0] + hhat_i_coeffs[0] + hhat_i_coeffs[1] + hhat_i_coeffs[2] + hhat_i_coeffs[3]);
        
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
    }
    (merlin, alpha, r, saved_val_for_sumcheck_equality_assertion)
}

fn run_whir_pcs_prover(
    args: Args, 
    io: IOPattern::<SkyscraperSponge, Field256>, 
    z: Vec<Field256>, 
    params: WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW>, 
    mut merlin: Merlin<SkyscraperSponge, Field256>, 
    num_variables: usize,
    alphas: (Vec<Field256>, Vec<Field256>, Vec<Field256>),
) -> (
    WhirProof<SkyscraperMerkleConfig, Field256>, 
    Merlin<SkyscraperSponge, Field256>,
    WhirConfig::<Field256, SkyscraperMerkleConfig, SkyscraperPoW>, 
    IOPattern::<SkyscraperSponge, Field256>, 
    (Field256, Field256, Field256),
) {   
    println!("=========================================");
    println!("Running Prover - Whir Commitment");
    println!("{}", params);
    if !params.check_pow_bits() {
        println!("WARN: more PoW bits required than what specified.");
    }

    // In appendix a, fhat_z is combination of fhat_v and fhat_w. We should only commit to fhat_w. But for now, we are committing to fhat_z.
    // let fhat_z = CoefficientList::new(z);

    let poly = EvaluationsList::new(z);
    let polynomial = poly.to_coeffs();
    
    let committer = Committer::new(params.clone());
    let witness = committer.commit(&mut merlin, polynomial).unwrap();
    let mut statement = Statement::<Field256>::new(num_variables);

    let linear_claim_weight_a = Weights::linear(EvaluationsList::new(alphas.0));
    let sum_a = linear_claim_weight_a.weighted_sum(&poly);
    statement.add_constraint(linear_claim_weight_a, sum_a);

    let linear_claim_weight_b = Weights::linear(EvaluationsList::new(alphas.1));
    let sum_b = linear_claim_weight_b.weighted_sum(&poly);
    statement.add_constraint(linear_claim_weight_b, sum_b);

    let linear_claim_weight_c = Weights::linear(EvaluationsList::new(alphas.2));
    let sum_c = linear_claim_weight_c.weighted_sum(&poly);
    statement.add_constraint(linear_claim_weight_c, sum_c);


    let prover = Prover(params.clone());

    let proof = prover
        .prove(&mut merlin, &mut statement.clone(), witness)
        .unwrap();
    
    (proof, merlin, params, io, (sum_a, sum_b, sum_c))
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
    num_variables: usize, 
    sums: (Field256, Field256, Field256),
) { 
    println!("=========================================");
    println!("Running Verifier - Whir Commitment ");
    let mut statement_verifier= StatementVerifier::<Field256>::new(num_variables);
    let linear_claim_weight_verifier = VerifierWeights::linear(num_variables, None);
    statement_verifier.add_constraint(linear_claim_weight_verifier.clone(), sums.0);
    statement_verifier.add_constraint(linear_claim_weight_verifier.clone(), sums.1);
    statement_verifier.add_constraint(linear_claim_weight_verifier.clone(), sums.2);
    let verifier = Verifier::new(params);
    verifier.verify(&mut arthur, &statement_verifier, &proof).unwrap();
}


