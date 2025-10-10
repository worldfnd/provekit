use super::{constants::NUM_KEYS, types::PublicKey};
use eddsa_poseidon2::verify_eddsa_poseidon2;
use poseidon2::bn254::perm;

global MERKLE_LEAF_DS: Field = 105702839725298824521994315;
global CREDENTIAL_DS: Field = 33037561950257263916064606852876458089761913554974635334680016433; // b"POSEIDON2+EDDSA-BJJ+DLBE-v1"

pub fn merkle_leaf(pk: [PublicKey; NUM_KEYS]) -> Field {
    let mut inputs: [Field; 16] = [0; 16];
    inputs[0] = MERKLE_LEAF_DS;

    for i in 0..NUM_KEYS {
        inputs[i * 2 + 1] = pk[i].x;
        inputs[i * 2 + 2] = pk[i].y;
    }
    // inputs[15] is already 0 from initialization

    let hash_state = perm::x5_16(inputs);
    hash_state[1]
}

pub fn check_credential_signature(
    s: Field,
    r: [Field; 2],
    pk: [Field; 2],
    credential_type_id: Field,
    user_id: Field,
    genesis_issued_at: Field,
    expires_at: Field,
    hashes: [Field; 2],
    current_time_stamp: Field,
) -> bool {
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

    // Verify EdDSA signature
    let sig_valid = verify_eddsa_poseidon2(pk[0], pk[1], s, r, message);

    // Check credential hasn't expired
    assert((current_time_stamp as u64) < (expires_at as u64), "Credential expired");

    sig_valid
}

pub fn compute_merkle_root_poseidon2<let N: u32>(
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

            // Compute left and right using conditional selection
            let left = if is_right == 0 { current } else { sibling };
            let right = if is_right == 0 { sibling } else { current };

            let hash_state = perm::x5_2([left, right]);
            current = hash_state[0] + left;

            idx >>= 1;
        }
    }

    current
}
