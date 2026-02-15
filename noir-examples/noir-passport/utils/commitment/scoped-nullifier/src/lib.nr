use poseidon::poseidon2::Poseidon2;
use utils::{
    constants::{
        NON_SALTED_MOCK_NULLIFIER, NON_SALTED_NULLIFIER, SALTED_MOCK_NULLIFIER, SALTED_NULLIFIER,
    },
    get_issuing_country_from_mrz,
    types::DG1Data,
};

// The ZKR (or Zero Knowledge Republic) is a mock country used for testing purposes
global ZKR_COUNTRY_CODE_BYTES: [u8; 3] = [90, 75, 82];

/*
############################################################
# compute_nullifier_and_type
############################################################
# Compute scoped nullifier and type for attestation circuits
# Works with raw values (no SaltedValue wrapper, no commitment verification)
############################################################

# Inputs/Outputs
############################################################
private_nullifier   Raw private_nullifier (not salted)
dg1                 Raw DG1 data
service_scope       H(<domain_name>)
service_subscope    H(<purpose>)
nullifier_secret    Optional secret for additional salting
Returns: (scoped_nullifier, nullifier_type)

# Purpose
############################################################
This function is specifically designed for attestation circuits like t_attest
that don't use commitment chains and work with raw values instead of
SaltedValue wrappers.
*/
pub fn compute_nullifier_and_type(
    private_nullifier: Field,
    dg1: DG1Data,
    service_scope: Field,
    service_subscope: Field,
    nullifier_secret: Field,
) -> (Field, Field) {
    // Compute scoped_nullifier
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

    // Determine nullifier_type based on secret and country
    let mut nullifier_type = if nullifier_secret != 0 {
        SALTED_NULLIFIER
    } else {
        NON_SALTED_NULLIFIER
    };

    let issuing_country = get_issuing_country_from_mrz(dg1);
    // ZKR is a test country - mark nullifier as mock to prevent production use
    if issuing_country == ZKR_COUNTRY_CODE_BYTES {
        nullifier_type = if nullifier_secret != 0 {
            SALTED_MOCK_NULLIFIER
        } else {
            NON_SALTED_MOCK_NULLIFIER
        };
    }

    (scoped_nullifier, nullifier_type)
}
