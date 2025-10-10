use super::{
    constants::{CREDENTIAL_DS, MERKLE_LEAF_DS, NUM_KEYS},
    types::{OprfQueryInputs, PublicKey},
};
use babyjubjub::{BabyJubJubPoint, hash_to_curve::encode_to_curve_baby_jubjub};
use eddsa_poseidon2::verify_eddsa_poseidon2;
use poseidon2::bn254::perm;

// Utility functions for OPRF query verification

fn merkle_leaf(pk: [PublicKey; NUM_KEYS]) -> Field {
    let mut inputs: [Field; 16] = [0; 16];
    inputs[0] = MERKLE_LEAF_DS;

    for i in 0..NUM_KEYS {
        inputs[i * 2 + 1] = pk[i].x;
        inputs[i * 2 + 2] = pk[i].y;
    }

    let hash_state = perm::x5_16(inputs);
    hash_state[1]
}

fn check_credential_signature(
    s: Field,
    r: [Field; 2],
    pk: [Field; 2],
    credential_type_id: Field,
    user_id: Field,
    genesis_issued_at: Field,
    expires_at: Field,
    hashes: [Field; 2],
    current_time_stamp: Field,
) {
    // Check expiration first
    assert((current_time_stamp as u64) < (expires_at as u64), "Credential expired");

    // Calculate message hash
    let hash_inputs = [
        CREDENTIAL_DS,
        credential_type_id,
        user_id,
        genesis_issued_at,
        expires_at,
        hashes[0],
        hashes[1],
        0,
    ];
    let hash_state = perm::x5_8(hash_inputs);
    let message = hash_state[1];

    // Verify EdDSA signature and assert directly
    assert(verify_eddsa_poseidon2(pk[0], pk[1], s, r, message), "Credential signature invalid");
}

fn compute_merkle_root_poseidon2<let N: u32>(
    leaf: Field,
    depth: Field,
    index: Field,
    hashpath: [Field; N],
) -> Field {
    let mut current = leaf;
    let mut idx = index as u32;
    let depth_u32 = depth as u32;

    for i in 0..N {
        if i < depth_u32 {
            let sibling = hashpath[i];
            let is_right = idx & 1;

            // Use branchless selection
            let is_right_field = is_right as Field;
            let diff = current - sibling;
            let left = sibling + (diff * (1 - is_right_field));
            let right = sibling + (diff * is_right_field);

            let hash_state = perm::x5_2([left, right]);
            current = hash_state[0] + left;

            idx >>= 1;
        }
    }

    current
}

pub fn oprf_query(inputs: OprfQueryInputs, query: Field, beta_bits: [u1; 251]) -> PublicKey {
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
        inputs.merkle_proof.depth,
        inputs.merkle_proof.mt_index,
        inputs.merkle_proof.siblings,
    );
    assert(computed_root == inputs.merkle_proof.root, "Merkle proof verification failed");

    // Verify credential signature
    check_credential_signature(
        inputs.cred_s,
        inputs.cred_r,
        [inputs.cred_pk.x, inputs.cred_pk.y],
        inputs.cred_type_id,
        inputs.merkle_proof.mt_index,
        inputs.cred_genesis_issued_at,
        inputs.cred_expires_at,
        [inputs.cred_hashes.claims_hash, inputs.cred_hashes.associated_data_hash],
        inputs.current_time_stamp,
    );

    // Encode query to curve point and perform scalar multiplication
    let (px, py) = encode_to_curve_baby_jubjub(query);
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
