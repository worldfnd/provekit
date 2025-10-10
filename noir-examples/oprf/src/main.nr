pub mod constants;
pub mod types;
mod dlog;
mod commitment;
mod query;

use commitment::{generate_commitment, generate_query};
use dlog::verify_dlog_equality;
use query::{oprf_query, verify_unblinding};
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

    // 5. Verify that the user unblinded correctly
    // This checks that: oprf_response * beta === oprf_response_blinded
    verify_unblinding(
        inputs.oprf_response,
        inputs.oprf_response_blinded,
        inputs.query_inputs.beta,
    );

    // Constrain public inputs to prevent optimizer from removing them
    // This is similar to Semaphore's approach but more efficient
    let _ = inputs.signal_hash * inputs.signal_hash;
    let _ = inputs.query_inputs.nonce * inputs.query_inputs.nonce;

    // Generate commitment and nullifier using the unblinded oprf_response
    generate_commitment(
        query,
        inputs.oprf_response,
        inputs.query_inputs.merkle_proof.mt_index,
        inputs.id_commitment_r,
    )
}
