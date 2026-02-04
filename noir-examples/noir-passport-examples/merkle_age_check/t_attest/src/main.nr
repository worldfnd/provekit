use common::compute_merkle_root;
use compare_age_lib::{calculate_param_commitment, compare_age};
use data_check_expiry::check_expiry;
use poseidon::poseidon2::Poseidon2;
use scoped_nullifier::compute_nullifier_and_type;
use utils::{
    pack_be_bytes_into_fields,
    types::DG1Data,
};

// Merkle tree depth: 2^24 = 16,777,216 leaves
global TREE_DEPTH: u32 = 24;

/*
############################################################
# Proves passport holder satisfies an age requirement by
# demonstrating knowledge of a DG1 preimage whose Poseidon
# commitment exists in the sequencer's Merkle tree.
############################################################

# Public Inputs
############################################################
root                Current Merkle tree root (from sequencer)
current_date        Unix timestamp of current date
service_scope       H(domain_name) - service identifier
service_subscope    H(purpose) - service-specific subscope

# Private Inputs
############################################################
dg1                 Machine Readable Zone data [u8; 95]
r_dg1               Blinding factor used during T_add registration
sod_hash            Poseidon2(packed_e_content) from T_add registration
leaf_index          Position of user's leaf in the Merkle tree
merkle_path         Sibling hashes from leaf to root [Field; 24]
min_age_required    Minimum age to prove (e.g., 18)
max_age_required    Maximum age to prove (0 = no upper bound)
nullifier_secret    Optional secret to further salt the nullifier

# Public Outputs
############################################################
param_commitment    Binds proof to specific age parameters
nullifier_type      Type indicator (salted/non-salted, real/mock)
scoped_nullifier    Service-scoped nullifier for Sybil resistance

# Checks
############################################################
- hDG1 = Poseidon2(r_dg1 || packed_dg1)
- leaf = Poseidon2(hDG1, sod_hash) is in the tree at root
- Passport is not expired
- Age is within [min_age, max_age] bounds
- private_nullifier = Poseidon2(packed_dg1, sod_hash) (derived)
- Scoped nullifier correctly derived from private_nullifier
*/
fn main(
    // Public inputs
    root: pub Field,
    current_date: pub u64,
    service_scope: pub Field,
    service_subscope: pub Field,
    // Private inputs
    dg1: DG1Data,
    r_dg1: Field,
    sod_hash: Field,
    leaf_index: Field,
    merkle_path: [Field; TREE_DEPTH],
    min_age_required: u8,
    max_age_required: u8,
    nullifier_secret: Field,
) -> pub (Field, Field, Field) {
    let packed_dg1: [Field; 4] = pack_be_bytes_into_fields::<95, 4, 31>(dg1);
    let h_dg1: Field = Poseidon2::hash([r_dg1].concat(packed_dg1), 5);

    let leaf = Poseidon2::hash([h_dg1, sod_hash], 2);

    let computed_root = compute_merkle_root(leaf, leaf_index, merkle_path);
    assert(computed_root == root, "Merkle path verification failed");
    check_expiry(dg1, current_date);

    compare_age(
        dg1,
        min_age_required,
        max_age_required,
        current_date,
    );
    let private_nullifier = Poseidon2::hash(packed_dg1.concat([sod_hash]), 5);

    let (scoped_nullifier, nullifier_type) = compute_nullifier_and_type(
        private_nullifier,
        dg1,
        service_scope,
        service_subscope,
        nullifier_secret,
    );

    let param_commitment = calculate_param_commitment(
        current_date,
        min_age_required,
        max_age_required,
    );

    (param_commitment, nullifier_type, scoped_nullifier)
}
