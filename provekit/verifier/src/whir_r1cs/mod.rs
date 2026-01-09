mod macros;

pub use macros::{blake3_verifier, sha2_verifier, sha3_verifier, skyscraper_verifier};
use {
    ark_std::Zero,
    provekit_common::FieldElement,
    whir::{
        poly_utils::evals::EvaluationsList,
        whir::{
            committer::reader::ParsedCommitment,
            statement::{Statement, Weights},
        },
    },
};

pub fn prepare_statement_for_witness_verifier<const N: usize>(
    m: usize,
    parsed_commitment: &ParsedCommitment<FieldElement, FieldElement>,
    whir_query_answer_sums: &([FieldElement; N], [FieldElement; N]),
) -> Statement<FieldElement> {
    let mut statement_verifier = Statement::<FieldElement>::new(m);
    for i in 0..whir_query_answer_sums.0.len() {
        let claimed_sum = whir_query_answer_sums.0[i]
            + whir_query_answer_sums.1[i] * parsed_commitment.batching_randomness;
        statement_verifier.add_constraint(
            Weights::linear(EvaluationsList::new(vec![FieldElement::zero(); 1 << m])),
            claimed_sum,
        );
    }
    statement_verifier
}
