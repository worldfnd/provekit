use super::{
    hash_to_curve::hash_to_curve::encode_to_curve_baby_jubjub,
    orpfQuery::{check_credential_signature, compute_merkle_root_poseidon2, merkle_leaf},
    types::{OprfQueryInputs, PublicKey},
};
use babyjubjub::BabyJubJubPoint;
use eddsa_poseidon2::verify_eddsa_poseidon2;

pub fn oprf_query(inputs: OprfQueryInputs, query: Field) -> PublicKey {
    let (_validated_beta, beta_bits) =
        BabyJubJubPoint::validate_scalar_field_with_bits(inputs.beta);

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

    // Verify credential signature (do this before expensive curve operations)
    let cred_valid = check_credential_signature(
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
    assert(cred_valid, "Credential signature invalid");

    // Encode query to curve point and perform scalar multiplication: q = beta * P
    let (x, y) = encode_to_curve_baby_jubjub(query);
    let p = BabyJubJubPoint::new(x, y);
    let q = p.scalar_mul_bits(beta_bits);

    PublicKey { x: q.x, y: q.y }
}

pub fn verify_unblinding(oprf_response: PublicKey, oprf_response_blinded: PublicKey, beta: Field) {
    // NOIR OPTIMIZATION: Validate and get bits to avoid redundant decomposition
    let (_validated_beta, beta_bits) = BabyJubJubPoint::validate_scalar_field_with_bits(beta);

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
