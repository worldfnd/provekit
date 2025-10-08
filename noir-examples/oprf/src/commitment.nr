use super::{
    constants::{DS_C, DS_N, DS_Q},
    types::{OprfNullifierOutputs, OprfQueryInputs, PublicKey},
};
use poseidon::poseidon2::Poseidon2;

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
    Poseidon2::hash([DS_N, query, oprf_response.x, oprf_response.y], 4)
}

fn generate_id_commitment(mt_index: Field, commitment_r: Field) -> Field {
    Poseidon2::hash([DS_C, mt_index, commitment_r], 3)
}

pub fn generate_query(query: OprfQueryInputs) -> Field {
    Poseidon2::hash(
        [DS_Q, query.merkle_proof.mt_index, query.rp_id, query.action],
        4,
    )
}
