use super::constants::{MAX_DEPTH, NUM_KEYS};

pub struct PublicKey {
    pub x: Field,
    pub y: Field,
}

pub struct CredentialHashes {
    pub claims_hash: Field,
    pub associated_data_hash: Field,
}

pub struct MerkleProof {
    pub root: Field,
    pub depth: Field,
    pub mt_index: Field,
    pub siblings: [Field; MAX_DEPTH],
}

pub struct OprfQueryInputs {
    // Signature verification of the OPRF nonce
    pub user_pk: [PublicKey; NUM_KEYS],
    pub pk_index: Field,
    pub query_s: Field, // Added missing query signature scalar
    pub query_r: [Field; 2], // Added missing query signature point

    // Credential Signature
    pub cred_type_id: Field,
    pub cred_pk: PublicKey,
    pub cred_hashes: CredentialHashes,
    pub cred_genesis_issued_at: Field,
    pub cred_expires_at: Field,
    pub cred_s: Field, // Added missing credential signature scalar
    pub cred_r: [Field; 2], // Added missing credential signature point
    pub current_time_stamp: Field, // Public

    pub merkle_proof: MerkleProof,

    // OPRF query
    pub beta: Field,
    pub rp_id: Field, // Public
    pub action: Field, // Public
    pub nonce: Field, // Public
}

pub struct OprfNullifierInputs {
    // All OPRF query inputs
    pub query_inputs: OprfQueryInputs,

    // Discrete logarithm equality proof
    pub dlog_e: Field,
    pub dlog_s: Field,
    pub oprf_pk: PublicKey, // Public
    pub oprf_response_blinded: PublicKey,

    // Unblinded response
    pub oprf_response: PublicKey,

    // Signal hash and commitment
    pub signal_hash: Field, // Public
    pub id_commitment_r: Field,
}

pub struct OprfQueryOutputs {
    // Public
    pub q: PublicKey,
}

pub struct OprfNullifierOutputs {
    // Public
    pub id_commitment: Field,
    // Public
    pub nullifier: Field,
}
