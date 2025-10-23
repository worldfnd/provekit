use super::{
    constants::CREDENTIAL_DS,
    merkle_proof::{compute_merkle_root_poseidon2, merkle_leaf},
    types::{OprfQueryInputs, PublicKey},
};
use babyjubjub::{BabyJubJubPoint, hash_to_curve::encode};
use eddsa_poseidon2::verify_eddsa_poseidon2;
use poseidon2::bn254::perm;

fn check_credential_signature(
    s: Field,
    r: [Field; 2],
    pk: [Field; 2],
    credential_type_id: Field,
    user_id: Field,
    genesis_issued_at: Field,
    expires_at: u64,
    hashes: [Field; 2],
    current_time_stamp: u64,
) {
    // Check expiration first
    assert((current_time_stamp as u64) < (expires_at as u64), "Credential expired");

    // Calculate message hash
    let hash_inputs = [
        CREDENTIAL_DS,
        credential_type_id,
        user_id,
        genesis_issued_at,
        expires_at as Field,
        hashes[0],
        hashes[1],
        0,
    ];
    let hash_state = perm::x5_8(hash_inputs);
    let message = hash_state[1];

    // Verify EdDSA signature and assert directly
    assert(verify_eddsa_poseidon2(pk[0], pk[1], s, r, message), "Credential signature invalid");
}

pub fn oprf_query<let MAX_DEPTH: u32, let NUM_KEYS: u32>(
    query: Field,
    depth: Field,
    root: Field,
    cred_pk: PublicKey,
    current_time_stamp: u64,
    inputs: OprfQueryInputs<MAX_DEPTH, NUM_KEYS>,
    beta_bits: [u1; 251],
) -> PublicKey {
    // 1. Verify sk/pk by verifying a signature to a known message
    let chosen_pk = inputs.user_pk[inputs.pk_index as u32];

    let is_valid = verify_eddsa_poseidon2(
        chosen_pk.x,
        chosen_pk.y,
        inputs.query_s,
        inputs.query_r,
        query,
    );
    assert(is_valid, "Invalid signature");

    // Compute and verify merkle proof
    let merkle_leaf = merkle_leaf(inputs.user_pk);
    let computed_root = compute_merkle_root_poseidon2(
        merkle_leaf,
        depth,
        inputs.merkle_proof.mt_index,
        inputs.merkle_proof.siblings,
    );
    assert(computed_root == root, "Merkle proof verification failed");

    // Verify credential signature
    check_credential_signature(
        inputs.cred_s,
        inputs.cred_r,
        [cred_pk.x, cred_pk.y],
        inputs.cred_type_id,
        inputs.merkle_proof.mt_index,
        inputs.cred_genesis_issued_at,
        inputs.cred_expires_at,
        [inputs.cred_hashes.claims_hash, inputs.cred_hashes.associated_data_hash],
        current_time_stamp,
    );

    // Encode query to curve point and perform scalar multiplication
    let (px, py) = encode(query);
    let p = BabyJubJubPoint::new(px, py);
    let q = p.scalar_mul_bits(beta_bits);

    PublicKey { x: q.x, y: q.y }
}

pub fn verify_unblinding(
    oprf_response: PublicKey,
    oprf_response_blinded: PublicKey,
    beta_bits: [u1; 251],
) {
    // Check that oprf_response is on the curve and perform unblinding
    let response_point = BabyJubJubPoint::new(oprf_response.x, oprf_response.y);
    assert(response_point.is_on_curve(), "OPRF response must be on curve");

    // Verify: oprf_response * beta === oprf_response_blinded
    let reblinded = response_point.scalar_mul_bits(beta_bits);

    assert(
        (reblinded.x == oprf_response_blinded.x) & (reblinded.y == oprf_response_blinded.y),
        "Unblinding verification failed",
    );
}
