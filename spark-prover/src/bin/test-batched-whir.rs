use provekit_common::{FieldElement, IOPattern, WhirR1CSScheme};
use provekit_r1cs_compiler::WhirR1CSSchemeBuilder;
use whir::{poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint}, whir::{committer::{CommitmentReader, CommitmentWriter}, domainsep::WhirDomainSeparator, prover::Prover, statement::{Statement, Weights}, verifier::Verifier}};
use anyhow::Result;

fn main() -> Result<()> {
    const NUM_VARIABLES: usize = 5; // Change this

    let whir_config = WhirR1CSScheme::new_whir_config_for_size(NUM_VARIABLES, 2);
    let mut io = IOPattern::new("💥")
        .commit_statement(&whir_config)
        .add_whir_proof(&whir_config);
    let mut merlin = io.to_prover_state();

    let poly1 = EvaluationsList::new([FieldElement::from(1); 1<<NUM_VARIABLES].to_vec()).to_coeffs();
    let poly2 = EvaluationsList::new([FieldElement::from(2); 1<<NUM_VARIABLES].to_vec()).to_coeffs();
    let committer = CommitmentWriter::new(whir_config.clone());
    let witness = committer.commit_batch(&mut merlin, &[poly1, poly2]).expect("Failed to commit");

    println!("{:?}", witness.batched_poly());    

    // let actual_ans = witness.batched_poly().evaluate(&MultilinearPoint([FieldElement::from(0); 7].to_vec()));

    let mut statement = Statement::<FieldElement>::new(NUM_VARIABLES);
    
    let weight = Weights::linear(EvaluationsList::new([FieldElement::from(0); 1<<NUM_VARIABLES].to_vec()));

    let poly = EvaluationsList::from(witness.batched_poly().clone().to_extension());

    let sum = weight.weighted_sum(&poly);

    println!("Sum: {:?}", sum);

    statement.add_constraint(weight, sum);
    
    let prover = Prover(whir_config.clone());
    let proof = prover.prove(&mut merlin, statement.clone(), witness.clone())?;
    

    let mut arthur = io.to_verifier_state(merlin.narg_string());
    let commitment_reader = CommitmentReader::new(&whir_config);
    let commitment = commitment_reader.parse_commitment(&mut arthur)?;
    
    let claimed_ans = FieldElement::from(1) + FieldElement::from(2) * commitment.batching_randomness;

    // println!("{:?}", claimed_ans);
    // println!("{:?}", actual_ans);
    
    let verifier = Verifier::new(&whir_config);
    verifier.verify(&mut arthur, &commitment, &statement)?;

    Ok(())
}