pub mod constants;
pub mod types;
mod dlog;
mod commitment;
mod query;

use commitment::{generate_commitment, generate_query};
use dlog::verify_dlog_equality;
use query::{oprf_query, unblind_oprf_response};
use types::{OprfNullifierInputs, OprfNullifierOutputs};

pub fn main(inputs: OprfNullifierInputs) -> pub OprfNullifierOutputs {
    // Derive the query using Poseidon4
    let query = generate_query(inputs.query_inputs);

    // 1-3. Show that the original query was computed correctly
    let oprf_query_key = oprf_query(inputs.query_inputs, query);

    // 4. Check the dlog equality proof
    verify_dlog_equality(
        inputs.dlog_e,
        inputs.dlog_s,
        inputs.oprf_pk,
        oprf_query_key,
        inputs.oprf_response_blinded,
    );

    // 5. Unblind the OPRF response
    let unblinded_response = unblind_oprf_response(
        inputs.oprf_response_blinded,
        inputs.query_inputs.beta,
        query,
    );

    generate_commitment(
        query,
        unblinded_response,
        inputs.query_inputs.merkle_proof.mt_index,
        inputs.id_commitment_r,
    )
}
