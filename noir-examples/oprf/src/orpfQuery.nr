// use dep::poseidon2;
use std::embedded_curve_ops::{
    multi_scalar_mul, 
    fixed_base_scalar_mul,
    EmbeddedCurvePoint,
    EmbeddedCurveScalar
};
use std::hash::Hasher;
use poseidon::poseidon2::Poseidon2;
use poseidon::poseidon2::Poseidon2Hasher;
// use std::hash::poseidon2::Poseidon2;
use ec::consts::te::baby_jubjub;
use ec::tecurve::affine::Point as TEPoint;
use hash_to_curve::hash_to_curve;

global MERKLE_LEAF_DS: Field = 105702839725298824521994315;
global CREDENTIAL_DS: Field = 33037561950257263916064606852876458089761913554974635334680016433; // b"POSEIDON2+EDDSA-BJJ+DLBE-v1"
global QUERY_DS: Field = 1773399373884719043551600379785849; // b"World ID Query"


fn merkle_leaf(pk: [[Field; 2]; 7]) -> Field {
    let mut inputs: [Field; 16] = [0; 16];
    inputs[0] = MERKLE_LEAF_DS;
    
    for i in 0..7 {
        inputs[i * 2 + 1] = pk[i][0];
        inputs[i * 2 + 2] = pk[i][1];
    }
    inputs[15] = 0;

    // std::hash::poseidon2_permutation(inputs, 16)
        Poseidon2::hash(inputs, 16)
}

fn choose_public_key(pk: [[Field; 2]; 7], index: Field) -> [Field; 2] {
    let mut result = [0, 0];
    
    for i in 0..7 {
        let is_match = if (i as Field) == index { 1 } else { 0 };
        result[0] += is_match * pk[i][0];
        result[1] += is_match * pk[i][1];
    }
    
    result
}

pub fn verify_eddsa_poseidon2(
    pub_key: [Field; 2],
    signature_s: Field,
    signature_r: [Field; 2],
    message: Field,
) -> bool {
    eddsa_verify::<Poseidon2Hasher>(
        pub_key[0], pub_key[1],
        signature_s,
        signature_r[0], signature_r[1],
        message
    )
}

fn eddsa_verify<H>(
    pub_key_x: Field,
    pub_key_y: Field,
    signature_s: Field,
    signature_r8_x: Field,
    signature_r8_y: Field,
    message: Field,
) -> bool
where
    H: Hasher + Default,
{
    let bjj = baby_jubjub();
    
    let pub_key = TEPoint::new(pub_key_x, pub_key_y);
    assert(bjj.curve.contains(pub_key));
    
    let signature_r8 = TEPoint::new(signature_r8_x, signature_r8_y);
    assert(bjj.curve.contains(signature_r8));
    
    assert(signature_s.lt(bjj.suborder));
    
    let mut hasher = H::default();
    hasher.write(signature_r8_x);
    hasher.write(signature_r8_y);
    hasher.write(pub_key_x);
    hasher.write(pub_key_y);
    hasher.write(message);
    let hash: Field = hasher.finish();
    
    let pub_key_mul_2 = bjj.curve.add(pub_key, pub_key);
    let pub_key_mul_4 = bjj.curve.add(pub_key_mul_2, pub_key_mul_2);
    let pub_key_mul_8 = bjj.curve.add(pub_key_mul_4, pub_key_mul_4);
    
    assert(!pub_key_mul_8.is_zero());
    
    let right = bjj.curve.add(signature_r8, bjj.curve.mul(hash, pub_key_mul_8));
    let left = bjj.curve.mul(signature_s, bjj.base8);
    
    left.eq(right)
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
        0
    ];
    let message = Poseidon2::hash(hash_inputs, 8);
    
    // Verify EdDSA signature
    let sig_valid = verify_eddsa_poseidon2(pk, s, r, message);
    
    // Check credential hasn't expired
    assert((current_time_stamp as u64) < (expires_at as u64), "Credential expired");
    
    sig_valid
}
fn compute_merkle_root_poseidon2<let N: u32>(
    leaf: Field,
    index: Field,
    hashpath: [Field; N]
) -> Field {
    let mut current = leaf;
    let mut idx = index as u32;
    
    for i in 0..N {
        let sibling = hashpath[i];
        
        let (left, right) = if idx & 1 == 0 {
            (current, sibling)
        } else {
            (sibling, current)
        };
        
        // Hash with Poseidon2
        current = Poseidon2::hash([left, right], 2);
        idx = idx >> 1;
    }
    
    current
}
pub fn oprf_query_inner<let MAX_DEPTH: u32>(
    pk: [[Field; 2]; 7],
    pk_index: Field,
    s: Field,
    r: [Field; 2],
    cred_type_id: Field,
    cred_pk: [Field; 2],
    cred_hashes: [Field; 2],
    cred_genesis_issued_at: Field,
    cred_expires_at: Field,
    cred_s: Field,
    cred_r: [Field; 2],
    current_time_stamp: Field,
    merkle_root: Field,
    depth: u32,
    mt_index: Field,
    siblings: [Field; MAX_DEPTH],
    beta: Field,
    query: Field,
) -> [Field; 2] {
    let bjj = baby_jubjub();
    
    // Ensure beta < Subgroup Order
    assert(beta.lt(bjj.suborder), "Beta out of range");
    
  
    let chosen_pk = choose_public_key(pk, pk_index);
    let query_sig_valid = verify_eddsa_poseidon2(chosen_pk, s, r, query);
    assert(query_sig_valid, "Query signature invalid");
    
    let leaf = merkle_leaf(pk);
    let computed_root = compute_merkle_root_poseidon2(leaf, mt_index, siblings);
    assert(computed_root == merkle_root, "Merkle proof invalid");
    
 
    let p = hash_to_curve(query);
    
   
    let q = bjj.curve.mul(beta, p);
    

    let cred_valid = check_credential_signature(
        cred_s,
        cred_r,
        cred_pk,
        cred_type_id,
        mt_index,
        cred_genesis_issued_at,
        cred_expires_at,
        cred_hashes,
        current_time_stamp
    );
    assert(cred_valid, "Credential signature invalid");
    
    [q.x, q.y]
}
// global QUERY_DS: Field = 1773399373884719043551600379785849; // b"World ID Query"


fn main(
    // Private inputs
    pk: [[Field; 2]; 7],
    pk_index: Field,
    s: Field,
    r: [Field; 2],
    cred_type_id: Field,
    cred_hashes: [Field; 2],
    cred_genesis_issued_at: Field,
    cred_expires_at: Field,
    cred_s: Field,
    cred_r: [Field; 2],
    mt_index: Field,
    siblings: [Field; 30], 
    beta: Field,
    
    // Public inputs
    cred_pk: [Field; 2],
    current_time_stamp: Field,
    merkle_root: Field,
    depth: u32,
    rp_id: Field,
    action: Field,
    nonce: Field,
) -> pub [Field; 2] {  

 
    let query_inputs = [QUERY_DS, mt_index, rp_id, action];
    let query = Poseidon2::hash(query_inputs, 4);
    
    // Call inner logic
    let q = oprf_query_inner(
        pk,
        pk_index,
        s,
        r,
        cred_type_id,
        cred_pk,
        cred_hashes,
        cred_genesis_issued_at,
        cred_expires_at,
        cred_s,
        cred_r,
        current_time_stamp,
        merkle_root,
        depth,
        mt_index,
        siblings,
        beta,
        query
    );
    
  
    let _ = nonce * nonce;
    
    q
}
