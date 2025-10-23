use super::{
    commitment::{generate_commitment, generate_query},
    dlog::verify_dlog_equality,
    query::{oprf_query, verify_unblinding},
    types::{OprfNullifierInputs, OprfNullifierOutputs, PublicKey},
};

use babyjubjub::BabyJubJubPoint;

pub fn oprf_nullifier<let MAX_DEPTH: u32, let NUM_KEYS: u32>(
    cred_pk: PublicKey,
    current_time_stamp: u64,
    root: Field,
    depth: Field,
    rp_id: Field,
    action: Field,
    oprf_pk: PublicKey,
    nonce: Field,
    signal_hash: Field,
    inputs: OprfNullifierInputs<MAX_DEPTH, NUM_KEYS>,
) -> OprfNullifierOutputs {
    // Derive the query using Poseidon4
    let query = generate_query(inputs.query_inputs, rp_id, action);

    // Validate beta once and reuse the bits
    let beta_bits = BabyJubJubPoint::validate_scalar_field_with_bits(inputs.query_inputs.beta);

    // 1-3. Show that the original query was computed correctly
    let oprf_query_key = oprf_query(
        query,
        depth,
        root,
        cred_pk,
        current_time_stamp,
        inputs.query_inputs,
        beta_bits,
    );

    // 4. Check the dlog equality proof
    verify_dlog_equality(
        inputs.dlog_e,
        inputs.dlog_s,
        oprf_pk,
        oprf_query_key,
        inputs.oprf_response_blinded,
    );

    // 5. Verify that the user unblinded correctly
    // This checks that: oprf_response * beta === oprf_response_blinded
    verify_unblinding(
        inputs.oprf_response,
        inputs.oprf_response_blinded,
        beta_bits,
    );

    // Todo: check these are needed
    let _ = signal_hash * signal_hash;
    let _ = nonce * nonce;

    // Generate commitment and nullifier using the unblinded oprf_response
    generate_commitment(
        query,
        inputs.oprf_response,
        inputs.query_inputs.merkle_proof.mt_index,
        inputs.id_commitment_r,
    )
}
