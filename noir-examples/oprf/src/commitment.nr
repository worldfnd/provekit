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
) -> OprfNullifierOutputs {
    let nullifier = generate_nullifier(query, oprf_response);
    let id_commitment = generate_id_commitment(mt_index, commitment_r);
    OprfNullifierOutputs { nullifier, id_commitment }
}

fn generate_nullifier(query: Field, oprf_response: PublicKey) -> Field {
    let state = perm::x5_4([DS_N, query, oprf_response.x, oprf_response.y]);
    state[1]
}

fn generate_id_commitment(mt_index: Field, commitment_r: Field) -> Field {
    let state = perm::x5_3([DS_C, mt_index, commitment_r]);
    state[1]
}

pub fn generate_query(query: OprfQueryInputs) -> Field {
    let state = perm::x5_4(
        [DS_Q, query.merkle_proof.mt_index, query.rp_id, query.action],
    );
    state[1]
}
