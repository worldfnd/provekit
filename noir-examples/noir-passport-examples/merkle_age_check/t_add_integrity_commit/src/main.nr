use common::{
    get_country_from_dg1,
    hash_salt_country_signed_attr_dg1_e_content_private_nullifier,
};
use data_check_integrity::{
    check_dg1_hash_within_sod, check_signed_attributes_sha256,
};
use poseidon::poseidon2::Poseidon2;
use utils::{
    pack_be_bytes_into_fields,
    types::{DG1Data, EContentData, SignedAttrsData},
};

/*
############################################################
# T_add Sub-circuit 4: Data Integrity + Poseidon Leaf Commit
############################################################
# Verifies the integrity of passport data (DG1 hash chain)
# and computes the Merkle tree leaf for the sequencer.
#
# This circuit replaces data_check_integrity_sa + compare_age
# from the fragmented approach. Instead of outputting a
# commitment for the next circuit in a chain, it outputs
# a Merkle leaf = Poseidon2(hDG1, private_nullifier) that
# the sequencer inserts into a Poseidon Merkle tree.
############################################################

# Inputs
############################################################
comm_in             Commitment from sub-circuit 3 (t_add_id_data)
salt_in             Salt to verify comm_in
dg1                 Machine Readable Zone data [u8; 95]
dg1_padded_length   Padded length for SHA-256
dg1_hash_offset     Offset of DG1 hash within eContent
signed_attributes   What the DSC signed [u8; 200]
signed_attributes_size  Actual size of signed_attributes
e_content           Hash values of data groups [u8; 200]
e_content_len       Actual length of eContent
private_nullifier   Pre-computed: Poseidon2(DG1, eContent, SOD sig)
r_dg1               Random blinding factor for Poseidon commitment

# Output
############################################################
leaf                Merkle leaf = Poseidon2(hDG1, private_nullifier)
                    where hDG1 = Poseidon2(r_dg1, packed_dg1)

# Checks
############################################################
- Verifies commitment chain from sub-circuit 3
- Checks DG1 SHA-256 hash is present in eContent
- Checks eContent SHA-256 hash is present in SignedAttributes
- Computes hDG1 = Poseidon2(r_dg1 || packed_dg1)
- Computes leaf = Poseidon2(hDG1, private_nullifier)
*/
fn main(
    comm_in: pub Field,
    salt_in: Field,
    dg1: DG1Data,
    dg1_padded_length: u64,
    dg1_hash_offset: u32,
    signed_attributes: SignedAttrsData,
    signed_attributes_size: u32,
    e_content: EContentData,
    e_content_len: u32,
    private_nullifier: Field,
    r_dg1: Field,
) -> pub Field {
    // Step 1: Verify commitment from sub-circuit 3 (t_add_id_data)
    // This ensures dg1, signed_attributes, e_content, and private_nullifier
    // are the same values that were committed in the previous circuit
    let country = get_country_from_dg1(dg1);
    assert(
        comm_in
            == hash_salt_country_signed_attr_dg1_e_content_private_nullifier(
                salt_in,
                country,
                signed_attributes,
                signed_attributes_size as Field,
                dg1,
                e_content,
                private_nullifier,
            ),
        "Commitment from sub-circuit 3 doesn't match",
    );

    // Step 2: Verify DG1 hash is present in eContent
    // SHA-256(DG1) must appear at dg1_hash_offset within eContent
    check_dg1_hash_within_sod(dg1, dg1_padded_length, e_content, e_content_len, dg1_hash_offset);

    // Step 3: Verify eContent hash is present in SignedAttributes
    // SHA-256(eContent) must appear in the signed attributes
    check_signed_attributes_sha256(signed_attributes, e_content, e_content_len);

    // Step 4: Compute Poseidon commitment to DG1 (hDG1)
    // This produces the same result as SaltedValue<[u8; 95]>.get_hash() with salt = r_dg1
    // hDG1 = Poseidon2(r_dg1, packed_dg1[0], packed_dg1[1], packed_dg1[2], packed_dg1[3])
    let packed_dg1: [Field; 4] = pack_be_bytes_into_fields::<95, 4, 31>(dg1);
    let h_dg1 = Poseidon2::hash([r_dg1].concat(packed_dg1), 5);

    // Step 5: Compute Merkle leaf
    // The leaf binds both the DG1 commitment and the private nullifier
    // This ensures the nullifier used in T_attest was committed during registration
    let leaf = Poseidon2::hash([h_dg1, private_nullifier], 2);

    leaf
}
