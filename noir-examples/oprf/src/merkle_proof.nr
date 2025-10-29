use super::{constants::MERKLE_LEAF_DS, types::PublicKey};
use poseidon2::bn254::perm;

pub fn merkle_leaf<let NUM_KEYS: u32>(pk: [PublicKey; NUM_KEYS]) -> Field {
    let mut inputs: [Field; 16] = [0; 16];
    inputs[0] = MERKLE_LEAF_DS;

    for i in 0..NUM_KEYS {
        inputs[i * 2 + 1] = pk[i].x;
        inputs[i * 2 + 2] = pk[i].y;
    }

    let hash_state = perm::x5_16(inputs);
    hash_state[1]
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
    assert(idx < (1 << depth_u32), "Index out of range for given depth");

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
