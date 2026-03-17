use super::{constants::{DS_C, DS_N, DS_Q}, types::{OprfNullifierOutputs, OprfQueryInputs}};
use babyjubjub::BabyJubJubPoint;
use poseidon2::bn254::perm;

pub fn generate_commitment(
    query: Field,
    oprf_response: BabyJubJubPoint,
    mt_index: Field,
    commitment_r: Field,
) -> OprfNullifierOutputs {
    let nullifier = generate_nullifier(query, oprf_response);
    let id_commitment = generate_id_commitment(mt_index, commitment_r);
    OprfNullifierOutputs { nullifier, id_commitment }
}

fn generate_nullifier(query: Field, oprf_response: BabyJubJubPoint) -> Field {
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
