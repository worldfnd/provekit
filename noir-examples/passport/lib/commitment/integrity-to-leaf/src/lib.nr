// PROVEKIT MODIFICATION: New library replacing integrity-to-disclosure.
// Produces a Merkle leaf for on-chain registration instead of a disclosure commitment.
// This is the core architectural difference from zkPassport:
// - zkPassport: integrity -> disclosure commitment chain (pure commitment approach)
// - Provekit: integrity -> Merkle leaf (Registration/Attestation approach)
//
// leaf = Poseidon2(Poseidon2(r_dg1 || packed_dg1), calculate_sod_hash(e_content))
use common::{
    calculate_merkle_leaf, get_country_from_dg1,
    hash_salt_country_signed_attr_dg1_e_content_private_nullifier,
};
use utils::types::{DG1Data, EContentData, SaltedValue, SignedAttrsData};

/*
############################################################
# Circuit C (Provekit variant)
############################################################
# Verifies the integrity of the ePassport data and produces
# a Merkle leaf for on-chain registration.
############################################################

# Inputs/Outputs
############################################################
comm_in                 `assert comm_in == H(salt, country, signed_attr, dg1, e_content, private_nullifier)`
salt_in
salted_dg1
signed_attributes
e_content
salted_private_nullifier
r_dg1                   Random blinding factor for Merkle leaf privacy
leaf (public output)    `Poseidon2(Poseidon2(r_dg1 || packed_dg1), sod_hash)`
private_nullifier       Passed through for use in attestation circuit

# Checks
############################################################
- Verifies commitment chain from circuit B (id-data)
- DG1 hash and signed attributes hash checks are done in the circuit main.nr
- Produces Merkle leaf for on-chain insertion

# Differences from zkPassport's integrity-to-disclosure
############################################################
- REMOVED: DG2 hash extraction (salted_dg2_hash, salted_dg2_hash_type)
- REMOVED: Expiry date salting (expiry_date_salt)
- REMOVED: hash_salt_dg1_dg2_hash_private_nullifier output
- ADDED: r_dg1 blinding factor
- ADDED: Merkle leaf output via calculate_merkle_leaf
- Output is (leaf, private_nullifier) instead of comm_out
*/

pub fn commit_to_leaf(
    comm_in: Field,
    salt_in: Field,
    salted_dg1: SaltedValue<DG1Data>,
    signed_attributes: SignedAttrsData,
    signed_attributes_size: Field,
    e_content: EContentData,
    salted_private_nullifier: SaltedValue<Field>,
    r_dg1: Field,
) -> (Field, Field) {
    let country = get_country_from_dg1(salted_dg1.value);
    assert(
        comm_in
            == hash_salt_country_signed_attr_dg1_e_content_private_nullifier(
                salt_in,
                country,
                signed_attributes,
                signed_attributes_size,
                salted_dg1.value,
                e_content,
                salted_private_nullifier.value,
            ),
        "Commitment from 2nd subproof doesn't match in 3rd subproof",
    );

    let leaf = calculate_merkle_leaf(r_dg1, salted_dg1.value, e_content);

    (leaf, salted_private_nullifier.value)
}
