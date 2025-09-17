use provekit_common::{FieldElement, IOPattern, WhirR1CSScheme};
use provekit_r1cs_compiler::WhirR1CSSchemeBuilder;
use whir::{poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint}, whir::{committer::{CommitmentReader, CommitmentWriter}, domainsep::WhirDomainSeparator, prover::Prover, statement::{Statement, Weights}, verifier::Verifier}};
use anyhow::Result;

fn main() -> Result<()> {
    let whir_config = WhirR1CSScheme::new_whir_config_for_size(6, 2);
    let mut io = IOPattern::new("💥")
        .commit_statement(&whir_config)
        .add_whir_proof(&whir_config);
    let mut merlin = io.to_prover_state();

    let poly1 = EvaluationsList::new([FieldElement::from(1); 64].to_vec()).to_coeffs();
    let poly2 = EvaluationsList::new([FieldElement::from(2); 64].to_vec()).to_coeffs();
    let committer = CommitmentWriter::new(whir_config.clone());
    let witness = committer.commit_batch(&mut merlin, &[poly1, poly2]).expect("Failed to commit");

    let mut statement = Statement::<FieldElement>::new(6);
    statement.add_constraint(Weights::evaluation(MultilinearPoint([FieldElement::from(0); 6].to_vec())), FieldElement::from(3));
    let prover = Prover(whir_config.clone());
    let proof = prover.prove(&mut merlin, statement.clone(), witness.clone())?;
    

    let mut arthur = io.to_verifier_state(merlin.narg_string());
    let commitment_reader = CommitmentReader::new(&whir_config);
    let commitment = commitment_reader.parse_commitment(&mut arthur)?;
    
    let claimed_ans = FieldElement::from(1) + FieldElement::from(2) * commitment.batching_randomness;
    let actual_ans = witness.batched_poly().evaluate(&MultilinearPoint([FieldElement::from(0); 6].to_vec()));
    
    let verifier = Verifier::new(&whir_config);
    verifier.verify(&mut arthur, &commitment, &statement)?;

    Ok(())
}