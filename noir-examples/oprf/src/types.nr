use babyjubjub::BabyJubJubPoint;

pub struct PublicKey {
    pub x: Field,
    pub y: Field,
}

pub struct CredentialHashes {
    pub claims_hash: Field,
    pub associated_data_hash: Field,
}

pub struct MerkleProof<let MAX_DEPTH: u32> {
    pub mt_index: Field,
    pub siblings: [Field; MAX_DEPTH],
}

pub struct OprfQueryInputs<let MAX_DEPTH: u32, let NUM_KEYS: u32> {
    pub user_pk: [PublicKey; NUM_KEYS],
    pub pk_index: Field,
    pub query_s: Field,
    pub query_r: [Field; 2],

    pub merkle_proof: MerkleProof<MAX_DEPTH>,

    pub beta: Field,
}

pub struct OprfNullifierInputs<let MAX_DEPTH: u32, let NUM_KEYS: u32> {
    // All OPRF query inputs
    pub query_inputs: OprfQueryInputs<MAX_DEPTH, NUM_KEYS>,

    // Credential Signature
    pub issuer_schema_id: Field,
    pub cred_hashes: CredentialHashes,
    pub cred_genesis_issued_at: u64,
    pub cred_expires_at: u64,
    pub cred_s: Field,
    pub cred_r: [Field; 2],
    pub cred_id: Field,
    pub cred_user_id_r: Field,

    // Discrete logarithm equality proof
    pub dlog_e: Field,
    pub dlog_s: Field,
    // pub oprf_pk: PublicKey, // Public
    pub oprf_response_blinded: BabyJubJubPoint,

    // Unblinded response
    pub oprf_response: BabyJubJubPoint,

    pub id_commitment_r: Field,
}

pub struct OprfNullifierOutputs {
    pub id_commitment: Field,
    pub nullifier: Field,
}
