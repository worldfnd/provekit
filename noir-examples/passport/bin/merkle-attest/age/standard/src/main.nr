// PROVEKIT MODIFICATION: New circuit - Merkle tree attestation for age.
// This circuit does NOT exist in zkPassport. It replaces zkPassport's compare/age
// circuit which uses a commitment chain approach.
//
// Architecture:
// - Registration Phase (circuits 1-3) produces a Merkle leaf stored on-chain
// - This Attestation circuit proves Merkle membership + age range + expiry
// - Can be run repeatedly without re-running circuits 1-3
//
// Reuses from zkPassport (unmodified, audited):
// - compare_age::compare_age - age range verification
// - data_check_expiry::check_expiry - passport expiry check
// - common::compute_merkle_root - Merkle tree membership proof
// - common::calculate_scoped_nullifier - scoped nullifier computation
// - common::calculate_merkle_leaf - leaf reconstruction (PROVEKIT addition)
// - compare_age::calculate_param_commitment - parameter commitment
//
// Private nullifier uses zkPassport's calculate_private_nullifier(dg1, e_content, sod_signature)
// computed in circuit 2 and passed through as private input.
use common::{calculate_merkle_leaf, calculate_scoped_nullifier, compute_merkle_root};
use compare_age::{calculate_param_commitment, compare_age};
use data_check_expiry::check_expiry;
use utils::{
    constants::{
        NON_SALTED_MOCK_NULLIFIER, NON_SALTED_NULLIFIER, SALTED_MOCK_NULLIFIER, SALTED_NULLIFIER,
    },
    get_issuing_country_from_mrz,
    types::{DG1Data, EContentData, SaltedValue},
};

global TREE_DEPTH: u32 = 24;

// The ZKR (or Zero Knowledge Republic) is a mock country used for testing purposes
global ZKR_COUNTRY_CODE_BYTES: [u8; 3] = [90, 75, 82];

fn main(
    // Public inputs
    root: pub Field,
    current_date: pub u64,
    min_age_required: pub u8,
    max_age_required: pub u8,
    service_scope: pub Field,
    service_subscope: pub Field,
    // Private inputs
    dg1: DG1Data,
    e_content: EContentData,
    r_dg1: Field,
    private_nullifier: Field,
    nullifier_secret: Field,
    leaf_index: Field,
    merkle_path: [Field; TREE_DEPTH],
) -> pub (Field, Field, Field) {
    // (param_commitment, nullifier_type, scoped_nullifier)

    // 1. Reconstruct Merkle leaf (must match circuit 3 output)
    let leaf = calculate_merkle_leaf(r_dg1, dg1, e_content);

    // 2. Verify Merkle membership
    let computed_root = compute_merkle_root(leaf, leaf_index, merkle_path);
    assert(computed_root == root, "Merkle membership proof failed");

    // 3. Check the ID is not expired
    check_expiry(dg1, current_date);

    // 4. Age check
    compare_age(dg1, min_age_required, max_age_required, current_date);

    // 5. Scoped nullifier (reuses zkPassport's calculate_scoped_nullifier)
    let salted_pn = SaltedValue { salt: 0, value: private_nullifier, hash: private_nullifier };
    let mut scoped_nullifier =
        calculate_scoped_nullifier(salted_pn, service_scope, service_subscope, nullifier_secret);

    // 6. Determine nullifier type (same logic as zkPassport's scoped-nullifier lib)
    let mut nullifier_type = if nullifier_secret != 0 {
        SALTED_NULLIFIER
    } else {
        NON_SALTED_NULLIFIER
    };
    let issuing_country = get_issuing_country_from_mrz(dg1);
    if issuing_country == ZKR_COUNTRY_CODE_BYTES {
        if nullifier_secret != 0 {
            nullifier_type = SALTED_MOCK_NULLIFIER;
        } else {
            nullifier_type = NON_SALTED_MOCK_NULLIFIER;
        }
    }

    // 7. Param commitment (no timestamp - matches zkPassport approach)
    let param_commitment = calculate_param_commitment(min_age_required, max_age_required);

    (param_commitment, nullifier_type, scoped_nullifier)
}
