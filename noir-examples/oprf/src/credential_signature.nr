use super::constants::{CREDENTIAL_DS, DS_C_CS};
use eddsa_poseidon2::verify_eddsa_poseidon2;
use poseidon2::bn254::perm;

pub fn check_credential_signature(
    s: Field,
    r: [Field; 2],
    pk: [Field; 2],
    issuer_schema_id: Field,
    user_id: Field,
    user_id_r: Field,
    genesis_issued_at: u64,
    expires_at: u64,
    hashes: [Field; 2],
    current_time_stamp: u64,
    genesis_issued_at_min: u64,
    credential_id: Field,
) {
    // Check expiration first
    assert(current_time_stamp < expires_at, "Credential expired");
    // Check genesis issued at is valid
    assert(genesis_issued_at >= genesis_issued_at_min, "Credential issued_at too old");

    let blinded_user_id = perm::x5_3([DS_C_CS, user_id, user_id_r])[1];

    // Calculate message hash
    let hash_inputs = [
        CREDENTIAL_DS,
        issuer_schema_id,
        blinded_user_id,
        genesis_issued_at as Field,
        expires_at as Field,
        hashes[0],
        hashes[1],
        credential_id,
    ];
    let hash_state = perm::x5_8(hash_inputs);
    let message = hash_state[1];

    // Verify EdDSA signature and assert directly
    assert(verify_eddsa_poseidon2(pk[0], pk[1], s, r, message), "Credential signature invalid");
}
