use common::compute_merkle_root;
use compare_age_lib::{calculate_param_commitment, compare_age};
use data_check_expiry::check_expiry;
use poseidon::poseidon2::Poseidon2;
use utils::{
    get_issuing_country_from_mrz,
    pack_be_bytes_into_fields,
    constants::{
        NON_SALTED_MOCK_NULLIFIER, NON_SALTED_NULLIFIER,
        SALTED_MOCK_NULLIFIER, SALTED_NULLIFIER,
    },
    types::DG1Data,
};

// Merkle tree depth: 2^24 = 16,777,216 leaves
global TREE_DEPTH: u32 = 24;

// ZKR (Zero Knowledge Republic) test country code bytes
global ZKR_COUNTRY_CODE_BYTES: [u8; 3] = [90, 75, 82];

/*
############################################################
# T_attest: Attestation Proof (Repeated, Cheap)
############################################################
# Proves passport holder satisfies an age requirement by
# demonstrating knowledge of a DG1 preimage whose Poseidon
# commitment exists in the sequencer's Merkle tree.
#
# This circuit uses ONLY Poseidon hashing and field arithmetic.
# No SHA-256. No RSA. This is what makes it fast on mobile.
#
# The expensive operations (SHA-256, RSA signature verification)
# were already proven once during T_add registration.
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
private_nullifier   Derived from passport data during T_add
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
- leaf = Poseidon2(hDG1, private_nullifier) is in the tree at root
- Passport is not expired
- Age is within [min_age, max_age] bounds
- Scoped nullifier correctly derived
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
    private_nullifier: Field,
    leaf_index: Field,
    merkle_path: [Field; TREE_DEPTH],
    min_age_required: u8,
    max_age_required: u8,
    nullifier_secret: Field,
) -> pub (Field, Field, Field) {
    // Step 1: Recompute hDG1 from DG1 and blinding factor
    // This produces the same result as SaltedValue<[u8; 95]>.get_hash() with salt = r_dg1
    // hDG1 = Poseidon2(r_dg1, packed_dg1[0..3])
    let packed_dg1: [Field; 4] = pack_be_bytes_into_fields::<95, 4, 31>(dg1);
    let h_dg1 = Poseidon2::hash([r_dg1].concat(packed_dg1), 5);

    // Step 2: Reconstruct Merkle leaf
    // The leaf was computed during T_add as Poseidon2(hDG1, private_nullifier)
    let leaf = Poseidon2::hash([h_dg1, private_nullifier], 2);

    // Step 3: Verify Merkle membership
    // Walk the Poseidon Merkle path from leaf to root and assert it matches
    let computed_root = compute_merkle_root(leaf, leaf_index, merkle_path);
    assert(computed_root == root, "Merkle path verification failed");

    // Step 4: Check passport expiry
    check_expiry(dg1, current_date);

    // Step 5: Compare age against requirements
    compare_age(
        dg1,
        min_age_required,
        max_age_required,
        current_date,
    );

    // Step 6: Compute scoped nullifier
    // The nullifier is different for each (service_scope, service_subscope) pair,
    // preventing cross-service linkability while enabling Sybil resistance within a service
    let scoped_nullifier = if private_nullifier == 0 {
        // If private nullifier is 0, return 0 (proof unusable for nullifier)
        0
    } else if nullifier_secret != 0 {
        Poseidon2::hash(
            [private_nullifier, service_scope, service_subscope, nullifier_secret],
            4,
        )
    } else {
        Poseidon2::hash(
            [private_nullifier, service_scope, service_subscope],
            3,
        )
    };

    // Step 7: Determine nullifier type
    let issuing_country = get_issuing_country_from_mrz(dg1);
    let mut nullifier_type = if nullifier_secret != 0 {
        SALTED_NULLIFIER
    } else {
        NON_SALTED_NULLIFIER
    };
    // ZKR is a test country - mark nullifier as mock to prevent production use
    if issuing_country == ZKR_COUNTRY_CODE_BYTES {
        if nullifier_secret != 0 {
            nullifier_type = SALTED_MOCK_NULLIFIER;
        } else {
            nullifier_type = NON_SALTED_MOCK_NULLIFIER;
        }
    }

    // Step 8: Compute parameter commitment
    // Binds the proof to specific age parameters so the verifier knows what was proven
    let param_commitment = calculate_param_commitment(
        current_date,
        min_age_required,
        max_age_required,
    );

    (param_commitment, nullifier_type, scoped_nullifier)
}
