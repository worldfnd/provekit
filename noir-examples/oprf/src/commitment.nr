use super::{
    constants::{DS_C, DS_N, DS_Q},
    types::{OprfNullifierOutputs, OprfQueryInputs, PublicKey},
};
use poseidon2::bn254::perm;

pub fn generate_commitment(
    query: Field,
    oprf_response: PublicKey,
    mt_index: Field,
    commitment_r: Field,
    expected_id_commitment: Field,
    nonce: Field,
    signal_hash: Field,
) -> OprfNullifierOutputs {
    let nullifier = generate_nullifier(query, oprf_response);
    let id_commitment = generate_id_commitment(mt_index, commitment_r);
    assert(
        (expected_id_commitment == 0) | (expected_id_commitment == id_commitment),
        "Identity commitment mismatch",
    );
    OprfNullifierOutputs {
        nullifier,
        nonce_squared: nonce * nonce,
        signal_hash_squared: signal_hash * signal_hash,
    }
}

fn generate_nullifier(query: Field, oprf_response: PublicKey) -> Field {
    let state = perm::x5_4([DS_N, query, oprf_response.x, oprf_response.y]);
    state[1]
}

fn generate_id_commitment(mt_index: Field, commitment_r: Field) -> Field {
    let state = perm::x5_3([DS_C, mt_index, commitment_r]);
    state[1]
}

pub fn generate_query<let MAX_DEPTH: u32, let NUM_KEYS: u32>(
    query: OprfQueryInputs<MAX_DEPTH, NUM_KEYS>,
    rp_id: Field,
    action: Field,
) -> Field {
    let state = perm::x5_4([DS_Q, query.merkle_proof.mt_index, rp_id, action]);
    state[1]
}
